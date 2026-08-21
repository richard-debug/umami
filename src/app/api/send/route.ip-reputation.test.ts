import { beforeEach, describe, expect, test, vi } from 'vitest';
import { checkAuth } from '@/lib/auth';
import { getBlocklist } from '@/lib/blocklist';
import clickhouse from '@/lib/clickhouse';
import { CACHE_TOKEN_TYPE } from '@/lib/constants';
import { getSalt, hash, secret, uuid } from '@/lib/crypto';
import { createToken } from '@/lib/jwt';
import { parseRequest } from '@/lib/request';
import { createSession, saveIpReputationHits } from '@/queries/sql';
import { POST } from './route';

const afterTasks = vi.hoisted(() => [] as Promise<unknown>[]);

vi.mock('next/server', () => ({
  after: vi.fn((callback: () => unknown) => {
    afterTasks.push(Promise.resolve().then(callback));
  }),
}));

vi.mock('@/lib/clickhouse', () => ({ default: { enabled: false } }));
vi.mock('@/lib/load', () => ({
  fetchWebsite: vi.fn(async () => ({ id: '11111111-1111-1111-1111-111111111111' })),
}));
vi.mock('@/lib/auth', () => ({ checkAuth: vi.fn(async () => null) }));
vi.mock('@/lib/blocklist', () => ({ getBlocklist: vi.fn() }));
vi.mock('@/lib/request', () => ({ parseRequest: vi.fn() }));
vi.mock('@/queries/sql', () => ({
  createSession: vi.fn(),
  saveEvent: vi.fn(),
  saveIpReputationHits: vi.fn(),
  saveSessionData: vi.fn(),
  saveSessionLink: vi.fn(),
  updateSession: vi.fn(),
}));

const USER_AGENT = vi.hoisted(
  () =>
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
);

vi.mock('@/lib/detect', () => ({
  // Mirrors upstream: a payload ip wins over the headers for hashing/geolocation.
  getClientInfo: vi.fn(async (_request: Request, payload: any) => ({
    userAgent: USER_AGENT,
    browser: 'chrome',
    os: 'Mac OS',
    device: 'laptop',
    ip: payload?.ip ?? '203.0.113.45',
    country: 'JP',
    region: 'JP-12',
    city: 'Funabashi',
  })),
  hasBlockedIp: vi.fn(() => false),
}));

const WEBSITE_ID = '11111111-1111-1111-1111-111111111111';
const REAL_IP = '203.0.113.45';
const SPOOFED_IP = '198.51.100.7';

const parseRequestMock = vi.mocked(parseRequest);
const createSessionMock = vi.mocked(createSession);
const checkAuthMock = vi.mocked(checkAuth);
const getBlocklistMock = vi.mocked(getBlocklist);
const saveIpReputationHitsMock = vi.mocked(saveIpReputationHits);

async function flushAfterTasks() {
  await Promise.all(afterTasks.splice(0));
}

function send({ payload = {}, headers = {} }: { payload?: any; headers?: Record<string, string> }) {
  const body = { type: 'event', payload: { website: WEBSITE_ID, url: '/', ...payload } };

  parseRequestMock.mockResolvedValue({ body, auth: null, error: undefined } as any);

  return POST(
    new Request('http://localhost/api/send', {
      method: 'POST',
      headers: { 'cf-connecting-ip': REAL_IP, ...headers },
      body: JSON.stringify(body),
    }),
  );
}

function cacheToken(overrides: Record<string, any> = {}) {
  const timestamp = Math.floor(Date.now() / 1000);
  const sessionSalt = getSalt(process.env.SALT_ROTATION || 'month', new Date(timestamp * 1000));

  return createToken(
    {
      websiteId: WEBSITE_ID,
      sessionId: uuid(WEBSITE_ID, REAL_IP, USER_AGENT, sessionSalt),
      visitId: '44444444-4444-4444-4444-444444444444',
      iat: timestamp,
      type: CACHE_TOKEN_TYPE,
      ...overrides,
    },
    secret(),
  );
}

const storedIp = () => createSessionMock.mock.calls[0][0].ip;

beforeEach(() => {
  clickhouse.enabled = false;
  process.env.APP_SECRET = 'test-secret';
  // Named header = the operator has declared their proxy; see isProxiedRequest().
  process.env.CLIENT_IP_HEADER = 'cf-connecting-ip';
  delete process.env.DISABLE_CLIENT_IP;
  delete process.env.DEBUG_SESSION_IP;
  delete process.env.TRUSTED_PROXY_SECRET;
  parseRequestMock.mockReset();
  createSessionMock.mockReset();
  saveIpReputationHitsMock.mockReset();
  getBlocklistMock.mockReset();
  getBlocklistMock.mockResolvedValue({
    check: () => [],
    evaluate: () => ({
      status: 'not-listed',
      confidence: 'none',
      sources: [],
      exportable: false,
    }),
    sources: ['test-source'],
  });
  checkAuthMock.mockReset();
  checkAuthMock.mockResolvedValue(null);
  afterTasks.splice(0);
});

describe('persisted session IP fork behavior', () => {
  test('uses the IP resolved from trusted proxy headers', async () => {
    await send({});

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    expect(storedIp()).toBe(REAL_IP);
  });

  test('ignores a payload IP from an unauthenticated caller', async () => {
    await send({ payload: { ip: SPOOFED_IP } });

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    expect(storedIp()).toBeUndefined();
  });

  test('accepts a payload IP from an authenticated caller', async () => {
    checkAuthMock.mockResolvedValue({ user: { id: 'server' } } as any);

    await send({ payload: { ip: SPOOFED_IP } });

    expect(storedIp()).toBe(SPOOFED_IP);
  });

  test('does not run an auth check on ordinary browser traffic', async () => {
    await send({});

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    expect(checkAuthMock).not.toHaveBeenCalled();
  });

  test('stores nothing when DISABLE_CLIENT_IP is set', async () => {
    process.env.DISABLE_CLIENT_IP = '1';

    await send({});

    expect(storedIp()).toBeUndefined();
  });
});

describe('proxy trust', () => {
  test('stores nothing when no proxy header has been declared', async () => {
    // Otherwise getIpAddress() would walk a dozen headers any client can set.
    delete process.env.CLIENT_IP_HEADER;

    await send({});

    expect(storedIp()).toBeUndefined();
  });

  test('requires the shared secret once one is configured', async () => {
    process.env.TRUSTED_PROXY_SECRET = 'x-origin-token: s3cret';

    await send({});

    expect(storedIp()).toBeUndefined();
  });

  test('stores the IP when the secret matches', async () => {
    process.env.TRUSTED_PROXY_SECRET = 'x-origin-token: s3cret';

    await send({ headers: { 'x-origin-token': 's3cret' } });

    expect(storedIp()).toBe(REAL_IP);
  });

  test('rejects a wrong or truncated secret', async () => {
    process.env.TRUSTED_PROXY_SECRET = 'x-origin-token: s3cret';

    await send({ headers: { 'x-origin-token': 'wrong!' } });
    expect(storedIp()).toBeUndefined();

    createSessionMock.mockReset();

    await send({ headers: { 'x-origin-token': 's3cre' } });
    expect(storedIp()).toBeUndefined();
  });

  test('a forged forwarding header alone is not enough', async () => {
    process.env.TRUSTED_PROXY_SECRET = 'x-origin-token: s3cret';

    // Direct-to-origin request impersonating Cloudflare.
    await send({ headers: { 'cf-connecting-ip': '198.51.100.7' } });

    expect(storedIp()).toBeUndefined();
  });

  test('ignores a malformed secret setting rather than trusting everything', async () => {
    process.env.TRUSTED_PROXY_SECRET = 'no-colon-here';

    await send({});

    expect(storedIp()).toBeUndefined();
  });
});

describe('session IP diagnostics', () => {
  test('logs persistence decisions without logging the IP or proxy secret', async () => {
    process.env.DEBUG_SESSION_IP = '1';
    process.env.TRUSTED_PROXY_SECRET = 'x-origin-token: s3cret';
    const log = vi.spyOn(console, 'info').mockImplementation(() => undefined);

    try {
      await send({ headers: { 'x-origin-token': 's3cret' } });

      expect(log).toHaveBeenCalledTimes(1);

      const output = log.mock.calls[0].join(' ');

      expect(output).toContain('[DEBUG-session-ip-a83f]');
      expect(output).toContain('"configuredIpHeaderPresent":true');
      expect(output).toContain('"proxyAccepted":true');
      expect(output).toContain('"sessionIpResolved":true');
      expect(output).toContain('"willWriteSession":true');
      expect(output).not.toContain(REAL_IP);
      expect(output).not.toContain('s3cret');
    } finally {
      log.mockRestore();
    }
  });
});

describe('cached sessions', () => {
  test('refreshes the IP when it no longer matches the cache token', async () => {
    await send({ headers: { 'x-umami-cache': cacheToken({ ipHash: hash('192.0.2.99') }) } });

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    expect(storedIp()).toBe(REAL_IP);
  });

  test('skips the write when the IP is unchanged', async () => {
    const response = await send({
      headers: { 'x-umami-cache': cacheToken({ ipHash: hash(REAL_IP) }) },
    });

    // Assert the request actually completed, so this cannot pass by bailing out early.
    await expect(response.json()).resolves.toHaveProperty('sessionId');
    expect(createSessionMock).not.toHaveBeenCalled();
  });

  test('backfills the IP for tokens issued before this feature', async () => {
    await send({ headers: { 'x-umami-cache': cacheToken() } });

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    expect(storedIp()).toBe(REAL_IP);
  });

  test('issues a token carrying the IP hash, never the address', async () => {
    const response = await send({});
    const { cache } = await response.json();

    const decoded = JSON.parse(Buffer.from(cache.split('.')[1], 'base64url').toString());

    expect(decoded.ipHash).toBe(hash(REAL_IP));
    expect(JSON.stringify(decoded)).not.toContain(REAL_IP);
  });
});

describe('IP reputation history', () => {
  test('records positive matches after the response path completes', async () => {
    getBlocklistMock.mockResolvedValue({
      check: () => ['spamhaus-drop-v4'],
      evaluate: () => ({
        status: 'listed',
        confidence: 'high',
        sources: ['spamhaus-drop-v4'],
        exportable: true,
      }),
      sources: ['spamhaus-drop-v4'],
    });

    const response = await send({});

    expect(response.status).toBe(200);
    expect(saveIpReputationHitsMock).not.toHaveBeenCalled();

    await flushAfterTasks();

    expect(saveIpReputationHitsMock).toHaveBeenCalledWith({
      websiteId: WEBSITE_ID,
      ip: REAL_IP,
      sources: ['spamhaus-drop-v4'],
      observedAt: expect.any(Date),
    });
  });

  test('does not persist clean addresses', async () => {
    await send({});
    await flushAfterTasks();

    expect(saveIpReputationHitsMock).not.toHaveBeenCalled();
  });

  test('checks a cached visitor at most once per day when the IP is unchanged', async () => {
    await send({
      headers: {
        'x-umami-cache': cacheToken({
          ipHash: hash(REAL_IP),
          reputationAt: Math.floor(Date.now() / 1000),
        }),
      },
    });
    await flushAfterTasks();

    expect(getBlocklistMock).not.toHaveBeenCalled();
  });

  test('rechecks immediately when a cached visitor changes IP', async () => {
    await send({
      headers: {
        'x-umami-cache': cacheToken({
          ipHash: hash('192.0.2.99'),
          reputationAt: Math.floor(Date.now() / 1000),
        }),
      },
    });
    await flushAfterTasks();

    expect(getBlocklistMock).toHaveBeenCalledTimes(1);
  });

  test('records history when ClickHouse stores analytics events', async () => {
    clickhouse.enabled = true;
    getBlocklistMock.mockResolvedValue({
      check: () => ['feodo'],
      evaluate: () => ({
        status: 'listed',
        confidence: 'high',
        sources: ['feodo'],
        exportable: true,
      }),
      sources: ['feodo'],
    });

    await send({});
    await flushAfterTasks();

    expect(saveIpReputationHitsMock).toHaveBeenCalledWith(
      expect.objectContaining({ websiteId: WEBSITE_ID, ip: REAL_IP, sources: ['feodo'] }),
    );
  });
});
