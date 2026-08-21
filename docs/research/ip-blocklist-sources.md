# IP blocklist sources and WAF export constraints

Research date: 2026-08-20

## Scope

This note evaluates sources for checking IPs that actually visit an Umami-tracked site.
It does not propose importing an entire third-party feed into a WAF. The safer export is
the intersection of recent local observations and current threat-feed membership.

## Recommended sources

| Source | Signal and format | Operational fit | Caveats |
| --- | --- | --- | --- |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | High-confidence malicious IPv4/IPv6 network ranges in JSON | Strong automatic-block candidate; first-party documentation says legitimate network space is not listed and false positives are extremely low | Needs a JSON adapter; Spamhaus asks products using the data to preserve attribution and copyright text |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | Active botnet command-and-control IPs; downloadable blocklists | Strong, narrow signal for C2 infrastructure | Narrow malware scope; an empty feed can be valid, according to the [official FAQ](https://feodotracker.abuse.ch/faq/) |
| [ThreatFox](https://threatfox.abuse.ch/api/) | Structured IOC API/exports with type, confidence, and timestamps | Useful enrichment when restricted to IP/IP:port IOCs with a high confidence threshold | Requires an Auth-Key; community API use is subject to fair-use/commercial terms; IOCs older than six months are expired to reduce cloud-IP false positives |
| [blocklist.de](https://www.blocklist.de/en/export.html) | One IP per line, split by attack category; generated every 30 minutes from attacks reported in the previous 48 hours | Useful corroboration, especially the web-oriented `apache`, `bots`, and conservative `strongips` feeds | Broad `all.txt` is noisier and is explicitly offered “as is”; short-lived observations and shared hosts make permanent blocking risky |
| [USTC BlackIP](https://blackip.ustc.edu.cn/intro.php) | Plain-text aggregate feed; the [linked list](https://blackip.ustc.edu.cn/list.php?txt) is already a default source in this fork | Useful regional/aggregate corroboration and directly compatible with the current parser | Treat as corroboration rather than a sole automatic-block authority; public provenance, cadence, and redistribution terms are less explicit than the specialist feeds above |

## Existing aggregate sources

- [FireHOL level 1](https://github.com/firehol/blocklist-ipsets) is a conservative aggregate
  already enabled by this fork. It is convenient but inherits the semantics and licensing
  of multiple upstream sources.
- [ipsum](https://github.com/stamparm/ipsum) aggregates IPs and exposes confidence levels
  based on the number of contributing lists. The fork uses level 3, which requires at
  least three reports. It is useful for corroboration, not provenance.

## Recommended decision policy

Do not export the union of all feeds. Export only IPs that:

1. were actually observed on the selected website during the selected period;
2. are still present in the current feed snapshot at export time; and
3. meet one of these confidence rules:
   - a high-confidence source such as Spamhaus DROP or Feodo Tracker; or
   - at least two independent configured sources.

The three default aggregate sources (FireHOL, ipsum, and USTC) have overlapping upstream
inputs, so their co-occurrence is not treated as independent corroboration. Custom sources
can satisfy the two-source rule; direct Spamhaus DROP and Feodo matches qualify alone.

This remains the recommended automatic-blocking policy. The application exports exactly
the rows selected by its date, search, source, and confidence controls, so choosing All or
Medium is an explicit operator decision and requires manual review before WAF import.

Keep the source names, first/last seen timestamps, and local hit count in the audit export.
Dynamic residential, VPN, carrier-grade NAT, and cloud IPs can change owners, so generated
WAF entries should have an expiry/review date rather than becoming permanent by default.

## Persistence needed for weekly, monthly, and yearly export

The current application computes blocklist membership when a sessions API is read and does
not persist a hit. Day-granular period reporting therefore needs a daily rollup keyed by:

```text
website_id + ip + source + observed_date
```

Each row should hold `first_seen_at`, `last_seen_at`, and `hit_count`. The implemented
bucket boundary is a UTC calendar day, so a selected period is evaluated at UTC-day
granularity rather than pretending to preserve arbitrary local-time boundaries. A single
lifetime row with only first/last seen would incorrectly include quiet periods between two
observations.

Recommended exports:

- Audit CSV: `ip,sources,first_seen,last_seen,hit_count,confidence,review_after`.
- Generic WAF text: one unique IP or CIDR per line.
- Cloudflare WAF CSV: headerless `IP,DESCRIPTION`, one item per line. Descriptions contain
  `review_after` and avoid additional CSV-like delimiters so the dashboard importer keeps
  the IP and description in the intended columns; custom source labels are normalized and
  the description is capped at Cloudflare's 500-character limit.

## Cloudflare WAF constraints

[Cloudflare custom IP lists](https://developers.cloudflare.com/waf/tools/lists/custom-lists/)
accept individual IPv4/IPv6 addresses and CIDRs. Their CSV form is one item per line with
an optional description. [Current list quotas](https://developers.cloudflare.com/waf/tools/lists/)
are 10,000 total custom-list items for Free, Pro, and Business accounts and 500,000 for
Enterprise accounts.

Dashboard CSV uploads add or update items but do not remove stale ones. Replacing the whole
generated list safely requires the [Lists API bulk update workflow](https://developers.cloudflare.com/waf/tools/lists/lists-api/endpoints/),
which is asynchronous. For a first version, manual export and review is safer than storing
Cloudflare API credentials in Umami.

## Implementation recommendation

Deliver this in separate slices:

1. Add a dedicated session-table status column using the existing current-match API field.
2. Add the daily hit-rollup table and record only positive matches.
3. Add authenticated period queries and audit/generic/Cloudflare exports.
4. Consider direct Cloudflare list synchronization later, with explicit replacement,
   expiry, item-limit handling, and separately scoped API credentials.
