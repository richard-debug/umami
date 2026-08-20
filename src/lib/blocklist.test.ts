import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { getBlocklist, parseBlocklist } from './blocklist';

// Shaped like the real feeds: bare addresses and CIDRs, IPv4 and IPv6, comments, blanks.
const FEED = `
# comment line
1.12.221.155
1.10.16.0/20
1.19.0.0/16

203.0.113.7
2605:6400:30:fd0b:1::
2a05:b0c7:6000::/36
not-an-ip
999.999.999.999
`;

function restoreCache() {
  delete globalThis['ip-blocklist'];
}

describe('parseBlocklist', () => {
  const list = parseBlocklist('test', FEED);

  test('separates bare addresses from ranges', () => {
    expect(list.exact.size).toBe(3);
    expect(list.ranges.ipv4).toHaveLength(2);
    expect(list.ranges.ipv6).toHaveLength(1);
  });

  test('drops comments, blanks and malformed entries', () => {
    expect(list.exact.has('not-an-ip')).toBe(false);
    expect(list.exact.has('999.999.999.999')).toBe(false);
  });

  test('parses Spamhaus DROP JSON lines', () => {
    const list = parseBlocklist(
      'spamhaus-drop-v4',
      [
        '{"cidr":"192.0.2.0/24","sblid":["SBL1"]}',
        '{"cidr":"198.51.100.7/32","sblid":["SBL2"]}',
        '{"type":"metadata","timestamp":1787184000}',
      ].join('\n'),
    );

    expect(list.ranges.ipv4).toHaveLength(2);
    expect(list.exact.size).toBe(0);
  });
});

describe('matching', () => {
  beforeEach(() => {
    restoreCache();
    process.env.IP_BLOCKLIST_URLS = 'https://lists.example.com/a.txt';
    delete process.env.DISABLE_IP_BLOCKLIST;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(FEED, { status: 200 })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    restoreCache();
    delete process.env.IP_BLOCKLIST_URLS;
  });

  test('matches an exact IPv4 entry', async () => {
    const blocklist = await getBlocklist();

    expect(blocklist.check('1.12.221.155')).toEqual(['lists.example.com']);
  });

  test('matches inside an IPv4 CIDR range', async () => {
    const blocklist = await getBlocklist();

    expect(blocklist.check('1.10.31.255')).toEqual(['lists.example.com']);
    expect(blocklist.check('1.19.240.1')).toEqual(['lists.example.com']);
  });

  test('does not match just outside a range', async () => {
    const blocklist = await getBlocklist();

    expect(blocklist.check('1.10.32.0')).toEqual([]);
    expect(blocklist.check('8.8.8.8')).toEqual([]);
  });

  test('matches IPv6 exactly and by range', async () => {
    const blocklist = await getBlocklist();

    // Same address, different textual form.
    expect(blocklist.check('2605:6400:30:fd0b:1:0:0:0')).toEqual(['lists.example.com']);
    expect(blocklist.check('2a05:b0c7:6fff::1')).toEqual(['lists.example.com']);
    expect(blocklist.check('2a05:b0c8::1')).toEqual([]);
  });

  test('never throws on absent or malformed input', async () => {
    const blocklist = await getBlocklist();

    expect(blocklist.check(undefined)).toEqual([]);
    expect(blocklist.check(null)).toEqual([]);
    expect(blocklist.check('')).toEqual([]);
    expect(blocklist.check('nonsense')).toEqual([]);
  });

  test('fetches once and serves later calls from cache', async () => {
    await getBlocklist();
    await getBlocklist();
    await getBlocklist();

    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test('reports every configured list that matches', async () => {
    process.env.IP_BLOCKLIST_URLS =
      'https://lists.example.com/a.txt,https://other.example.org/b.txt';

    const blocklist = await getBlocklist();

    expect(blocklist.sources).toEqual(['lists.example.com', 'other.example.org']);
    expect(blocklist.check('1.12.221.155')).toEqual(['lists.example.com', 'other.example.org']);
  });

  test('does not treat overlapping default aggregates as independent corroboration', async () => {
    process.env.IP_BLOCKLIST_URLS =
      'ustc=https://lists.example.com/a.txt,ipsum=https://other.example.org/b.txt';

    const blocklist = await getBlocklist();

    expect(blocklist.evaluate('1.12.221.155')).toEqual({
      status: 'listed',
      confidence: 'medium',
      sources: ['ustc', 'ipsum'],
      exportable: false,
    });
  });

  test('evaluates two independent configured sources as exportable high confidence', async () => {
    process.env.IP_BLOCKLIST_URLS =
      'source-a=https://lists.example.com/a.txt,source-b=https://other.example.org/b.txt';

    const blocklist = await getBlocklist();

    expect(blocklist.evaluate('1.12.221.155')).toMatchObject({
      status: 'listed',
      confidence: 'high',
      sources: ['source-a', 'source-b'],
      exportable: true,
    });
  });

  test('evaluates a single aggregate-source match as medium confidence', async () => {
    const blocklist = await getBlocklist();

    expect(blocklist.evaluate('1.12.221.155')).toEqual({
      status: 'listed',
      confidence: 'medium',
      sources: ['lists.example.com'],
      exportable: false,
    });
  });

  test('treats a specialist source as high confidence on its own', async () => {
    process.env.IP_BLOCKLIST_URLS = 'feodo=https://lists.example.com/a.txt';

    const blocklist = await getBlocklist();

    expect(blocklist.evaluate('1.12.221.155')).toMatchObject({
      status: 'listed',
      confidence: 'high',
      sources: ['feodo'],
      exportable: true,
    });
  });

  test('distinguishes no match and no IP from an unavailable feed', async () => {
    const blocklist = await getBlocklist();

    expect(blocklist.evaluate('8.8.8.8')).toMatchObject({
      status: 'not-listed',
      confidence: 'none',
    });
    expect(blocklist.evaluate()).toMatchObject({ status: 'unknown', confidence: 'none' });
  });

  test('labels feeds by name when given as name=url', async () => {
    // Two feeds on one host would otherwise collide under a hostname-derived name.
    process.env.IP_BLOCKLIST_URLS =
      'firehol=https://raw.example.com/a.netset,ipsum=https://raw.example.com/b.txt';

    const blocklist = await getBlocklist();

    expect(blocklist.sources).toEqual(['firehol', 'ipsum']);
    expect(blocklist.check('1.12.221.155')).toEqual(['firehol', 'ipsum']);
  });

  test('never flags a non-public address', async () => {
    // FireHOL level1 and similar firewall feeds list these deliberately.
    process.env.IP_BLOCKLIST_URLS = 'bogons=https://lists.example.com/bogons.txt';
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response('10.0.0.0/8\n127.0.0.0/8\n100.64.0.0/10\n192.168.0.0/16\nfd00::/8', {
            status: 200,
          }),
      ),
    );

    const blocklist = await getBlocklist();

    expect(blocklist.check('10.1.2.3')).toEqual([]);
    expect(blocklist.check('127.0.0.1')).toEqual([]);
    expect(blocklist.check('100.64.0.1')).toEqual([]);
    expect(blocklist.check('192.168.1.1')).toEqual([]);
    expect(blocklist.check('fd00::1')).toEqual([]);
  });
});

describe('failure and opt-out', () => {
  beforeEach(restoreCache);
  afterEach(() => {
    vi.unstubAllGlobals();
    restoreCache();
    delete process.env.IP_BLOCKLIST_URLS;
    delete process.env.DISABLE_IP_BLOCKLIST;
  });

  test('reports nothing when a feed is unreachable', async () => {
    process.env.IP_BLOCKLIST_URLS = 'https://lists.example.com/a.txt';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }),
    );

    const blocklist = await getBlocklist();

    expect(blocklist.check('1.12.221.155')).toEqual([]);
    expect(blocklist.evaluate('1.12.221.155')).toMatchObject({
      status: 'unavailable',
      confidence: 'none',
    });
  });

  test('keeps serving the previous copy when a refresh fails', async () => {
    process.env.IP_BLOCKLIST_URLS = 'https://lists.example.com/a.txt';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(FEED, { status: 200 })),
    );

    await getBlocklist();

    // Force the cache stale, then fail the refresh.
    globalThis['ip-blocklist'].checkedAt = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }),
    );

    const blocklist = await getBlocklist();

    expect(blocklist.check('1.12.221.155')).toEqual(['lists.example.com']);
    expect(globalThis['ip-blocklist'].loaded).toBe(false);

    // Incomplete attempts retry after the short interval even though the old data remains
    // usable. Six minutes is longer than the five-minute retry window.
    globalThis['ip-blocklist'].checkedAt -= 6 * 60 * 1000;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('8.8.8.8', { status: 200 })),
    );

    const refreshed = await getBlocklist();

    expect(refreshed.check('8.8.8.8')).toEqual(['lists.example.com']);
    expect(globalThis['ip-blocklist'].loaded).toBe(true);
  });

  test('atomically refreshes successful sources while retaining failed source snapshots', async () => {
    process.env.IP_BLOCKLIST_URLS =
      'first=https://lists.example.com/a.txt,second=https://other.example.org/b.txt';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(FEED, { status: 200 })),
    );

    await getBlocklist();

    globalThis['ip-blocklist'].checkedAt = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('other.example.org')) {
          throw new Error('source unavailable');
        }

        return new Response('8.8.8.8', { status: 200 });
      }),
    );

    const blocklist = await getBlocklist();

    expect(blocklist.sources).toEqual(['first', 'second']);
    expect(blocklist.check('1.12.221.155')).toEqual(['second']);
    expect(blocklist.check('8.8.8.8')).toEqual(['first']);
    expect(blocklist.evaluate('1.12.221.155')).toMatchObject({
      status: 'unavailable',
      sources: ['second'],
      exportable: false,
    });
    expect(blocklist.evaluate('9.9.9.9').status).toBe('unavailable');
  });

  test('retains the previous snapshot when a 200 response is not a feed', async () => {
    process.env.IP_BLOCKLIST_URLS = 'first=https://lists.example.com/a.txt';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(FEED, { status: 200 })),
    );

    await getBlocklist();
    globalThis['ip-blocklist'].checkedAt = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('<html>rate limited</html>', { status: 200 })),
    );

    const blocklist = await getBlocklist();

    expect(blocklist.check('1.12.221.155')).toEqual(['first']);
    expect(blocklist.evaluate('1.12.221.155')).toMatchObject({
      status: 'unavailable',
      sources: ['first'],
      exportable: false,
    });
  });

  test('does no network call at all when disabled', async () => {
    process.env.DISABLE_IP_BLOCKLIST = '1';
    vi.stubGlobal('fetch', vi.fn());

    const blocklist = await getBlocklist();

    expect(blocklist.check('1.12.221.155')).toEqual([]);
    expect(blocklist.sources).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});
