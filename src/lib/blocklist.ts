import ipaddr from 'ipaddr.js';

const CACHE_KEY = 'ip-blocklist';
/**
 * Three complementary feeds, so a flag can be corroborated rather than resting on one
 * source — the UI names whichever matched.
 *
 *  - FireHOL level1: conservative aggregate (includes Spamhaus DROP), near-zero false
 *    positives, mostly ranges.
 *  - ipsum level 3: addresses appearing on at least three independent blocklists.
 *  - USTC: aggregates Spamhaus, Talos and Feodo Tracker.
 */
const DEFAULT_URLS = [
  'firehol=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
  'ipsum=https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
  'ustc=https://blackip.ustc.edu.cn/list.php?txt',
].join(',');
const REFRESH_INTERVAL = 6 * 60 * 60 * 1000;
const RETRY_INTERVAL = 5 * 60 * 1000;
const FETCH_TIMEOUT = 20000;

type Range = [ipaddr.IPv4 | ipaddr.IPv6, number];

interface Source {
  name: string;
  exact: Set<string>;
  ranges: { ipv4: Range[]; ipv6: Range[] };
}

interface BlocklistCache {
  sources: Source[];
  /** Timestamp of the last completed attempt, successful or not. */
  checkedAt: number;
  /** Whether that attempt produced usable data — a failure keeps the previous copy. */
  loaded: boolean;
  inflight?: Promise<Source[]>;
}

export interface Blocklist {
  /** Names of the configured lists that contain this address. */
  check: (ip?: string | null) => string[];
  /** Configured list names, whether or not they matched. */
  sources: string[];
}

const EMPTY: Blocklist = { check: () => [], sources: [] };

function getUrls() {
  if (process.env.DISABLE_IP_BLOCKLIST) {
    return [];
  }

  return (process.env.IP_BLOCKLIST_URLS ?? DEFAULT_URLS)
    .split(',')
    .map(entry => entry.trim())
    .filter(Boolean)
    .map(parseEntry);
}

/**
 * Each configured entry is either a bare URL or `name=url`. The explicit form matters
 * because two feeds can share a host — FireHOL and ipsum are both on raw.githubusercontent
 * — and the name is what the UI shows against a flagged address.
 */
function parseEntry(entry: string) {
  const separator = entry.indexOf('=');

  if (separator > 0) {
    const name = entry.slice(0, separator);

    // Only treat it as a label if it could not be part of a URL or query string.
    if (/^[\w.-]+$/.test(name)) {
      return { name, url: entry.slice(separator + 1) };
    }
  }

  try {
    return { name: new URL(entry).hostname, url: entry };
  } catch {
    return { name: entry, url: entry };
  }
}

/**
 * Feeds are plain text, one entry per line, mixing bare addresses with CIDR ranges and
 * IPv4 with IPv6. Bare addresses go into a set for O(1) hits; only ranges are scanned.
 */
export function parseBlocklist(name: string, text: string): Source {
  const source: Source = {
    name,
    exact: new Set(),
    ranges: { ipv4: [], ipv6: [] },
  };

  for (const line of text.split('\n')) {
    const entry = line.trim();

    if (!entry || entry.startsWith('#') || entry.startsWith(';')) {
      continue;
    }

    try {
      if (entry.includes('/')) {
        const range = ipaddr.parseCIDR(entry);

        source.ranges[range[0].kind()].push(range);
      } else {
        source.exact.add(ipaddr.parse(entry).toString());
      }
    } catch {
      // Skip anything that is not a valid address or range.
    }
  }

  return source;
}

async function fetchSource({ name, url }: { name: string; url: string }): Promise<Source | null> {
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    if (!response.ok) {
      return null;
    }

    return parseBlocklist(name, await response.text());
  } catch {
    return null;
  }
}

function matches(source: Source, address: ipaddr.IPv4 | ipaddr.IPv6, normalized: string) {
  if (source.exact.has(normalized)) {
    return true;
  }

  // A range only ever matches an address of its own kind, and match() throws across kinds.
  return source.ranges[address.kind()].some(range => address.match(range));
}

function build(sources: Source[]): Blocklist {
  return {
    sources: sources.map(s => s.name),
    check: ip => {
      if (!ip || !sources.length) {
        return [];
      }

      let address: ipaddr.IPv4 | ipaddr.IPv6;

      try {
        address = ipaddr.parse(ip);
      } catch {
        return [];
      }

      // Feeds built for firewall ingress filtering (FireHOL level1, for one) list bogons
      // such as 10/8, 127/8 and 100.64/10 alongside genuinely hostile addresses. Blocking
      // those at a firewall is correct; labelling a visitor with one as hostile is not, so
      // anything that is not publicly routable is never flagged.
      if (address.range() !== 'unicast') {
        return [];
      }

      const normalized = address.toString();

      return sources.filter(source => matches(source, address, normalized)).map(s => s.name);
    },
  };
}

/**
 * Loads the configured feeds, cached in module-global state and refreshed on a timer.
 *
 * Lookups are local: a visitor's address is never sent to the list provider. A failed
 * refresh keeps serving the previous copy rather than reporting every address as clean,
 * and is retried on a short interval instead of on every request.
 */
export async function getBlocklist(): Promise<Blocklist> {
  const urls = getUrls();

  if (!urls.length) {
    return EMPTY;
  }

  if (!globalThis[CACHE_KEY]) {
    globalThis[CACHE_KEY] = { sources: [], checkedAt: 0, loaded: false };
  }

  const cache: BlocklistCache = globalThis[CACHE_KEY];

  const age = Date.now() - cache.checkedAt;
  const isStale = age > (cache.loaded ? REFRESH_INTERVAL : RETRY_INTERVAL);

  if (cache.checkedAt && !isStale) {
    return build(cache.sources);
  }

  cache.inflight ??= (async () => {
    const results = (await Promise.all(urls.map(fetchSource))).filter(Boolean) as Source[];

    cache.checkedAt = Date.now();

    if (results.length) {
      cache.sources = results;
      cache.loaded = true;
    }

    cache.inflight = undefined;

    return cache.sources;
  })();

  return build(await cache.inflight);
}
