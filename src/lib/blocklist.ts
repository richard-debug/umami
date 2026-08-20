import ipaddr from 'ipaddr.js';
import { getIpReputationConfidence } from './ip-reputation';

const CACHE_KEY = 'ip-blocklist';
/**
 * Complementary feeds let a flag be corroborated rather than resting on one source — the
 * UI names whichever matched.
 *
 *  - FireHOL level1: conservative aggregate (includes Spamhaus DROP), near-zero false
 *    positives, mostly ranges.
 *  - ipsum level 3: addresses appearing on at least three independent blocklists.
 *  - USTC: aggregates Spamhaus, Talos and Feodo Tracker.
 *  - Spamhaus DROP: high-confidence malicious network ranges, provided as JSON lines.
 *  - Feodo Tracker: active botnet command-and-control addresses.
 */
const DEFAULT_URLS = [
  'firehol=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
  'ipsum=https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
  'ustc=https://blackip.ustc.edu.cn/list.php?txt',
  'spamhaus-drop-v4=https://www.spamhaus.org/drop/drop_v4.json',
  'spamhaus-drop-v6=https://www.spamhaus.org/drop/drop_v6.json',
  'feodo=https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
].join(',');
const REFRESH_INTERVAL = 6 * 60 * 60 * 1000;
const RETRY_INTERVAL = 5 * 60 * 1000;
const FETCH_TIMEOUT = 20000;

type Range = [ipaddr.IPv4 | ipaddr.IPv6, number];

interface Source {
  name: string;
  exact: Set<string>;
  ranges: { ipv4: Range[]; ipv6: Range[] };
  /** False when this copy survived a failed refresh and is only stale evidence. */
  fresh: boolean;
}

interface BlocklistCache {
  sources: Source[];
  /** Timestamp of the last completed attempt, successful or not. */
  checkedAt: number;
  /** Whether the last attempt refreshed every configured source successfully. */
  loaded: boolean;
  inflight?: Promise<Source[]>;
}

export interface Blocklist {
  /** Names of the configured lists that contain this address. */
  check: (ip?: string | null) => string[];
  /** User-facing state and export confidence for this address. */
  evaluate: (ip?: string | null) => IpReputation;
  /** Configured list names, whether or not they matched. */
  sources: string[];
}

export interface IpReputation {
  status: 'listed' | 'not-listed' | 'unavailable' | 'unknown';
  confidence: 'high' | 'medium' | 'none';
  sources: string[];
  exportable: boolean;
}

const emptyReputation = (status: IpReputation['status']): IpReputation => ({
  status,
  confidence: 'none',
  sources: [],
  exportable: false,
});

const EMPTY: Blocklist = {
  check: () => [],
  evaluate: ip => emptyReputation(ip ? 'unavailable' : 'unknown'),
  sources: [],
};

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
 * Feeds are plain text or JSON lines, one entry per line, mixing bare addresses with CIDR
 * ranges and IPv4 with IPv6. Bare addresses go into a set for O(1) hits; only ranges are
 * scanned.
 */
export function parseBlocklist(name: string, text: string): Source {
  const source: Source = {
    name,
    exact: new Set(),
    ranges: { ipv4: [], ipv6: [] },
    fresh: true,
  };

  for (const line of text.split('\n')) {
    let entry = line.trim();

    if (!entry || entry.startsWith('#') || entry.startsWith(';')) {
      continue;
    }

    try {
      if (entry.startsWith('{')) {
        const data = JSON.parse(entry);

        if (typeof data?.cidr !== 'string') {
          continue;
        }

        entry = data.cidr;
      }

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

    const text = await response.text();

    if (/^\s*(?:<!doctype\s+html|<html)/i.test(text)) {
      return null;
    }

    const source = parseBlocklist(name, text);
    const entryCount = source.exact.size + source.ranges.ipv4.length + source.ranges.ipv6.length;

    // Feodo documents that an empty feed can be legitimate. For the other defaults, a
    // non-empty 200 response with no parseable entries is normally an upstream error page
    // or format change, so retain the previous snapshot instead of replacing it with empty.
    if (!entryCount && !name.startsWith('feodo')) {
      return null;
    }

    return source;
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
  const findMatches = (ip?: string | null) => {
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

    return sources.filter(source => matches(source, address, normalized));
  };
  const check = (ip?: string | null) => findMatches(ip).map(source => source.name);

  return {
    sources: sources.map(s => s.name),
    check,
    evaluate: ip => {
      if (!ip) {
        return emptyReputation('unknown');
      }

      if (!sources.length) {
        return emptyReputation('unavailable');
      }

      const matched = findMatches(ip);
      const matchedSources = matched.map(source => source.name);

      if (!matchedSources.length) {
        return emptyReputation(
          sources.every(source => source.fresh) ? 'not-listed' : 'unavailable',
        );
      }

      const currentSources = matched.filter(source => source.fresh).map(source => source.name);

      if (!currentSources.length) {
        return {
          ...emptyReputation('unavailable'),
          sources: matchedSources,
        };
      }

      const { confidence, exportable } = getIpReputationConfidence(currentSources);

      return {
        status: 'listed',
        confidence,
        sources: currentSources,
        exportable,
      };
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
    const previousSources = new Map(cache.sources.map(source => [source.name, source]));
    const results = await Promise.all(urls.map(fetchSource));
    const nextSources = urls
      .map(({ name }, index) => {
        const source = results[index];
        const previous = previousSources.get(name);

        return source ?? (previous ? { ...previous, fresh: false } : null);
      })
      .filter(Boolean) as Source[];

    cache.checkedAt = Date.now();

    if (nextSources.length) {
      // Build the complete next snapshot first, then swap the reference once. Readers never
      // observe a partially refreshed set, and a failed source retains its previous copy.
      cache.sources = nextSources;
      // A usable mixed snapshot can still be served, but an incomplete refresh retries on
      // the shorter interval until every configured source has a current copy.
      cache.loaded = results.every(Boolean);
    }

    cache.inflight = undefined;

    return cache.sources;
  })();

  return build(await cache.inflight);
}
