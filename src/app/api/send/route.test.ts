import { beforeEach, describe, expect, test, vi } from 'vitest';
import { checkAuth } from '@/lib/auth';
import { CACHE_TOKEN_TYPE } from '@/lib/constants';
import { hash, secret } from '@/lib/crypto';
import { createToken } from '@/lib/jwt';
import { parseRequest } from '@/lib/request';
import { createSession } from '@/queries/sql';
import { POST } from './route';

vi.mock('@/lib/clickhouse', () => ({ default: { enabled: false } }));
vi.mock('@/lib/load', () => ({
  fetchWebsite: vi.fn(async () => ({ id: '11111111-1111-1111-1111-111111111111' })),
}));
vi.mock('@/lib/auth', () => ({ checkAuth: vi.fn(async () => null) }));
vi.mock('@/lib/request', () => ({ parseRequest: vi.fn() }));
vi.mock('@/queries/sql', () => ({
  createSession: vi.fn(),
  saveEvent: vi.fn(),
  saveSessionData: vi.fn(),
}));
vi.mock('@/lib/detect', () => ({
  // Mirrors upstream: a payload ip wins over the headers for hashing/geolocation.
  getClientInfo: vi.fn(async (_request: Request, payload: any) => ({
    userAgent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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
  return createToken(
    {
      websiteId: WEBSITE_ID,
      sessionId: '33333333-3333-3333-3333-333333333333',
      visitId: '44444444-4444-4444-4444-444444444444',
      iat: Math.floor(Date.now() / 1000),
      type: CACHE_TOKEN_TYPE,
      ...overrides,
    },
    secret(),
  );
}

const storedIp = () => createSessionMock.mock.calls[0][0].ip;

beforeEach(() => {
  process.env.APP_SECRET = 'test-secret';
  delete process.env.DISABLE_CLIENT_IP;
  parseRequestMock.mockReset();
  createSessionMock.mockReset();
  checkAuthMock.mockReset();
  checkAuthMock.mockResolvedValue(null);
});

describe('persisted session IP', () => {
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
