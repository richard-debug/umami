# Fork: show visitor IP address

Upstream Umami deliberately never persists IP addresses — it hashes
`websiteId + ip + userAgent + salt` into a session ID and throws the IP away. This fork
stores the IP on the session row, renders it in the visitor (session) detail panel next
to Country / Region / City, and shows it as a column in the sessions list — where it is
also searchable.

## What changed

| File | Change |
| --- | --- |
| `prisma/schema.prisma` | `Session.ip String? @db.VarChar(45)` |
| `prisma/migrations/fork_add_session_ip/migration.sql` | `ALTER TABLE "session" ADD COLUMN "ip" VARCHAR(45)` |
| `src/lib/constants.ts` | `FIELD_LENGTH.ip = 45` |
| `src/app/api/send/route.ts` | resolves the IP to persist; refreshes it for cached sessions |
| `src/queries/sql/sessions/createSession.ts` | writes `ip`; upserts it when it changes |
| `src/queries/sql/sessions/getWebsiteSession.ts` | selects `ip` (Postgres path) |
| `src/queries/sql/sessions/getWebsiteSessions.ts` | selects `ip`, adds it to the search predicate |
| `src/queries/sql/reports/getRevenueSessions.ts` | same — it feeds the same table component |
| `src/components/messages.ts`, `public/intl/messages/en-US.json` | `label.ip-address` |
| `.../sessions/SessionInfo.tsx` | renders the IP field in the detail panel |
| `.../sessions/SessionsTable.tsx` | IP column in the sessions list |
| `src/app/api/send/route.test.ts` | covers the trust rules and the cached-session refresh |
| `prisma/migrations/fork_add_ip_reputation_hits/migration.sql` | daily positive-match history for period reports |
| `src/lib/blocklist.ts` | local multi-source IP reputation snapshots |
| `.../sessions/IpReputationPanel.tsx` | authenticated history, filters, and WAF exports |

`VARCHAR(45)` is the maximum length of an IPv4-mapped IPv6 literal, so every address
form Umami can produce fits.

### Which IP gets stored

`/api/send` is unauthenticated and its Zod schema accepts a `payload.ip`, which upstream
prefers over the request headers. That is fine for a value that only feeds a hash, but not
for one this fork displays and makes searchable — any browser could POST an arbitrary
address. `getSessionIp()` therefore applies a narrower rule than upstream's
`getClientInfo()`:

| Request | Stored |
| --- | --- |
| Normal tracker traffic, through the declared proxy | `getIpAddress(request.headers)` |
| `payload.ip` from an authenticated caller | `payload.ip` |
| `payload.ip` from an unauthenticated caller | nothing |
| Anything not demonstrably proxied (see below) | nothing |

`checkAuth()` only runs when a `payload.ip` is actually present, so browser traffic never
pays for the extra lookup.

### Proving the request came through your proxy

Forwarding headers are self-asserted. `cf-connecting-ip` is authoritative only on a request
that actually transited Cloudflare — anyone who discovers the origin address can connect to
it directly and send any value they like, which would otherwise land straight in the stored
IP and its blocklist status. Setting `CLIENT_IP_HEADER` narrows *which* header is read; it
does not establish that Cloudflare set it.

There are three levels here, and it is worth knowing which one you are on:

1. **Nothing declared.** No IP is persisted at all. `getIpAddress()` would otherwise fall
   back through a dozen candidate headers, any of which a client can set, which is not a
   defensible source for stored data.
2. **`CLIENT_IP_HEADER` set.** The named header is used. This rests entirely on the origin
   being unreachable except through the proxy. On Dokploy that means firewalling the host so
   only [Cloudflare's ranges](https://www.cloudflare.com/ips/) can reach 80/443, or turning
   on Authenticated Origin Pulls. Without one of those, a direct request to the origin still
   wins.
3. **`TRUSTED_PROXY_SECRET` set**, as `Header-Name: value`. The header must be present and
   match, compared in constant time, before any header-derived address is stored. Add it in
   Cloudflare with Rules → Transform Rules → Modify Request Header → *Set static*, using a
   long random value. This holds even if the origin is directly reachable, so it is the one
   to use if you cannot firewall the host.

A malformed `TRUSTED_PROXY_SECRET` — no colon, or an empty value — is treated as a failure
to verify, not as an absent setting, so a typo cannot silently reopen the gap.

None of this changes the `ip` upstream folds into the session hash and the geolocation
lookup; those keep upstream's behaviour, so a forged header can still shift a visitor's
reported country. Only the stored, displayed address is held to this standard.

The stored IP can therefore differ from the one upstream folds into the session hash and
the geolocation lookup. Those remain upstream's behaviour and are still influenced by a
spoofed `payload.ip` — a visitor can still lie about their country. Only the displayed IP
column is hardened here. A visitor can also suppress their own IP by sending a
`payload.ip`; that is a deliberate trade against storing a value we cannot vouch for.

### Upsert behaviour

The insert was `on conflict (session_id) do nothing`. It is now:

```sql
on conflict (session_id) do update
  set ip = excluded.ip
  where excluded.ip is not null
    and session.ip is distinct from excluded.ip
```

For normal (anonymous) traffic this is a no-op: the session ID is *derived from* the IP,
so a different IP already produces a different session row. It matters for sessions keyed
by `distinctId` via the identify API, where one session persists across IP changes — those
show the most recently seen IP instead of being frozen at the first one. The `where`
clause means no row is written when the IP is unchanged, and a null IP never wipes a
stored one.

Reaching that upsert needs one more change. `createSession()` is skipped entirely when the
request carries a valid `x-umami-cache` token, so on its own the clause above would only
ever fire on a client's first request. The cache token now carries an `ipHash`, and the
guard became:

```ts
if (!clickhouse.enabled && (!cache?.sessionId || cache.ipHash !== ipHash)) {
```

The comparison is against a signed token the server issued, so an unchanged IP costs
nothing — no query, no write. A changed IP costs exactly one upsert. Tokens issued before
this change have no `ipHash`, so they trigger a single backfilling write and are then
reissued with one.

The token holds `hash(ip)` rather than the address itself: it is a plain signed JWT, so
its payload is readable by anything that sees it.

## Blocklist status

Sessions whose IP appears on a configured blocklist are flagged in both the detail panel
and the sessions list. Hovering the flag names the lists that matched. For authenticated
users, the Sessions page also has an **IP reputation** tab for daily history,
source/confidence filters, and audit, generic WAF, or Cloudflare CSV downloads.

`src/lib/blocklist.ts` downloads whole feeds and matches locally, rather than querying a
reputation API per address. That means **no visitor IP is ever sent to a third party**, no
API key is needed, and there is no per-visitor network call — which matters given the rest
of this fork is about handling IPs carefully.

The parser accepts plain-text IP/CIDR lines and Spamhaus JSON lines, with IPv4 and IPv6.
Comments and malformed lines are skipped. Six feeds are configured by default:

| Feed | Role | Confidence policy |
| --- | --- | --- |
| `firehol` | Conservative aggregate including Spamhaus DROP | Signal only; overlaps other defaults |
| `ipsum` | IPs reported by at least three contributing lists | Signal only; overlaps other defaults |
| `ustc` | Aggregate including Spamhaus, Talos, and Feodo | Signal only; overlaps other defaults |
| `spamhaus-drop-v4` | Direct Spamhaus malicious IPv4 ranges | High confidence by itself |
| `spamhaus-drop-v6` | Direct Spamhaus malicious IPv6 ranges | High confidence by itself |
| `feodo` | Direct active botnet C2 addresses | High confidence by itself |

Entries are `name=url` or a bare URL (the name then falls back to the hostname). The
explicit form matters because feeds can share a host — FireHOL and ipsum are both on
`raw.githubusercontent.com`. A configured custom source is medium confidence by itself;
two distinct non-aggregate custom sources are high confidence. FireHOL, ipsum, and USTC
never corroborate one another because their upstream inputs overlap.

Refresh is lazy-periodic, not a cron job: each application process checks the cache when it
uses it, and starts a refresh after six hours. Ingestion triggers it inside Next.js
`after()`, so feed downloads and history writes happen after the analytics response. The
first authenticated sessions read in a new process can wait for its initial snapshot.

Publication is atomic within each process. All feeds are fetched in parallel and the next
snapshot is built before one reference swap, so readers see either the prior snapshot or
the complete next snapshot, never a partially mutated table. This is not a strict
all-sources transaction: when one source fails, its previous copy is retained and marked
stale while successful sources advance. Stale evidence can still explain a warning but
cannot produce a high-confidence WAF export. Incomplete refreshes retry after five minutes;
a fully fresh snapshot is used for six hours. HTML/error pages and unexpectedly empty feeds
do not replace prior data. In a multi-instance deployment each process has its own snapshot
and refresh timing.

Positive matches are rolled up in Postgres by website, IP, source, and UTC day. A signed
cache-token timestamp limits the normal check to once per visitor per 24 hours, with an
immediate recheck if the IP changes. Audit exports preserve historical evidence. Firewall
exports are stricter: they include only historical high-confidence IPs that are still
high-confidence in the current fresh snapshot. Audit and Cloudflare CSV output includes a
`review_after` date seven days after the last observation so entries are not silently
treated as permanent. Direct Cloudflare API synchronization and credential storage remain
out of scope; the generated file is for review and manual import.

Addresses that are not publicly routable are never flagged, whatever the feeds say. Lists
built for firewall ingress filtering — FireHOL level1 among them — deliberately include
`10/8`, `127/8`, `192.168/16` and the `100.64/10` CGNAT range. Blocking those at a firewall
is correct; labelling a visitor carrying one as hostile is not.

**Read the flag as a signal, not a verdict.** These lists target mail abuse, botnet C2 and
scanning infrastructure — not general web browsing. A visitor on CGNAT, a VPN exit or a
recycled cloud IP can be flagged without having done anything. Treat it as a prompt to
look closer.

## Configuration

| Variable | Effect |
| --- | --- |
| `CLIENT_IP_HEADER` | Pin IP resolution to one header. **Required for any IP to be stored. Set it to `cf-connecting-ip` behind Cloudflare** — see below. |
| `TRUSTED_PROXY_SECRET` | `Header-Name: value` that your proxy injects. When set, header-derived IPs are stored only if it matches. |
| `DISABLE_CLIENT_IP` | Set to `1` to stop persisting IPs. Everything else keeps working; the field renders as `—`. |
| `IGNORE_IP` | Unchanged upstream behaviour — comma-separated IPs/CIDRs to drop entirely. |
| `IP_BLOCKLIST_URLS` | Comma-separated `name=url` (or bare URL) feeds. Defaults to FireHOL, ipsum, USTC, Spamhaus DROP v4/v6, and Feodo. |
| `DISABLE_IP_BLOCKLIST` | Set to `1` to skip blocklist loading entirely — no fetch, nothing flagged. |

## Behind Cloudflare

Set `CLIENT_IP_HEADER=cf-connecting-ip`.

Without it, `getIpAddress()` walks `IP_ADDRESS_HEADERS` in order and checks
`true-client-ip` **before** `cf-connecting-ip`. `True-Client-IP` is only injected by
Cloudflare on Enterprise plans; on Free/Pro/Business, Cloudflare passes through whatever
the visitor sent. A visitor sending `True-Client-IP: 1.2.3.4` would therefore have that
value recorded as their IP *and* folded into their session hash. `CF-Connecting-IP` is
always overwritten by Cloudflare on every plan, so pinning to it is both correct and
unspoofable.

If your proxy chain does not sit behind Cloudflare, use `x-forwarded-for` instead — but
only when you trust every hop that can append to it.

## Scope / limitations

- **The session IP column is Postgres only.** The ClickHouse path of `getWebsiteSession` is
  untouched because it stores session attributes denormalised on `website_event`. IP
  reputation history still works with ClickHouse analytics: positive matches are written
  to Umami's Postgres metadata database, but ClickHouse session rows do not gain an IP
  column from this fork.
- **Existing sessions show `—`.** The column is backfilled with `NULL`; only sessions
  created after the migration have an IP.
- **Search is a substring match** (`ilike '%…%'`), so `203.0.113` matches every session
  in that /24, but there is no CIDR or range matching.
- Storing IPs makes the database hold personal data under GDPR/CCPA. That is a change in
  the legal character of the deployment, not just a feature — set retention and access
  accordingly, and update your privacy notice.

## Deploying on Dokploy

The Dokploy template pins `ghcr.io/umami-software/umami:3.0.3`, a prebuilt upstream
image, so it has to be replaced with an image built from this fork.

**Option A — let Dokploy build it (simplest).** Create a *Compose* service pointing at
this repository and use a compose file with `build:` instead of `image:`:

```yaml
services:
  umami:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://umami:umami@db:5432/umami
      DATABASE_TYPE: postgresql
      APP_SECRET: <keep the value your existing deployment already uses>
      CLIENT_IP_HEADER: cf-connecting-ip
      # Recommended unless the origin is firewalled to Cloudflare's ranges. Must match a
      # Cloudflare Transform Rule that sets the same header.
      TRUSTED_PROXY_SECRET: 'x-origin-token: <long random value>'
    depends_on:
      db:
        condition: service_healthy
    restart: always
    healthcheck:
      test: ['CMD-SHELL', 'curl http://localhost:3000/api/heartbeat']
      interval: 5s
      timeout: 5s
      retries: 5
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: umami
      POSTGRES_USER: umami
      POSTGRES_PASSWORD: umami
    volumes:
      - db-data:/var/lib/postgresql/data
    restart: always
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}']
      interval: 5s
      timeout: 5s
      retries: 5
volumes:
  db-data:
```

The build pulls the GeoLite2 City database from a public mirror; no MaxMind licence key
is required.

**Option B — build in CI.** `.github/workflows/fork-image.yml` builds this fork and pushes
it to GHCR; the Dokploy template then needs only its `image:` line changed.

Upstream's `cd.yml` is not reusable here: it runs on a self-hosted Blacksmith runner, and
its non-tag path would produce `…/umami:feat/session-ip`, which is not a valid image tag.
The fork workflow is a separate file so rebases never conflict with it, and it is guarded
with `if: github.repository != 'umami-software/umami'`.

It runs on push to `feat/session-ip` and on manual dispatch, and pushes three tags:

| Tag | Use |
| --- | --- |
| `ghcr.io/<owner>/umami:sha-<short>` | what to pin in Dokploy — immutable |
| `ghcr.io/<owner>/umami:feat-session-ip` | current head of the branch |
| `ghcr.io/<owner>/umami:latest` | convenience; moves on every build |

Three things need doing once, by hand:

1. **Enable Actions on the fork.** GitHub disables workflows on forks by default — open the
   Actions tab and confirm before the first run.
2. **Decide the package visibility.** GHCR packages start private. Either make it public
   (package settings → change visibility) or add a registry credential in Dokploy using a
   PAT with `read:packages`. A private package with no credential fails the pull.
3. **Pick the architecture.** The workflow defaults to `linux/amd64`, which is what almost
   every VPS running Dokploy uses. If your host is arm64, dispatch it manually and choose
   the platform — arm64 is emulated through QEMU and the build takes substantially longer.

Either way:

- Keep the **same `APP_SECRET`** and the **same database volume** as the current
  deployment, otherwise existing sessions and logins are invalidated.
- The container runs `prisma migrate deploy` on start (`npm run start-docker` →
  `check-db`), so `fork_add_session_ip` applies automatically on first boot. No manual SQL.
- Keep the Cloudflare proxy (orange cloud) on, and keep Dokploy's Traefik router in front
  — `CF-Connecting-IP` passes through untouched.

## Taking a new upstream release

`.github/workflows/sync-upstream.yml` does this for you. Weekly (and on demand) it resolves
upstream's latest release, replays this fork's patch onto it, runs `tsc` and the full test
suite, and **opens a pull request** — as a draft if the checks failed. If the rebase
conflicts it pushes nothing and opens an issue listing the conflicting paths.

It opens a PR rather than force-pushing `feat/session-ip` on purpose: an automated rebase
rewrites history, and doing that unannounced to the branch the deployed image is built from
is not a decision a schedule should make. Merging the PR pushes `feat/session-ip`, which
builds a new image. Nothing redeploys on its own — you still repoint Dokploy at the new
`sha-` tag.

### Repository prerequisites

`schedule` and `workflow_dispatch` only ever fire from a repository's **default branch**.
That is why this fork's default is `feat/session-ip` and not `master` — on `master` the sync
workflow would silently never run, and would not even appear in the Actions UI.

- **"Allow GitHub Actions to create and approve pull requests"** (Settings → Actions →
  General) must stay on, or the final step cannot open the PR. Already enabled here.
- **Scheduled workflows are auto-disabled after 60 days of repository inactivity**, and are
  disabled by default in forks. Check the Actions tab if a week passes with no run.
- **Issues are disabled on this fork**, as they are on all forks by default. The conflict
  path therefore writes its report to the run summary and fails the run — a red run is the
  notification. Turning issues on additionally gets you a tracked issue with the same
  content; the workflow detects this and adapts.

### Doing it by hand

One-time setup:

```bash
git remote add upstream https://github.com/umami-software/umami.git
```

Each time you want a newer upstream:

```bash
git fetch upstream --tags
git checkout feat/session-ip
git rebase v3.3.0          # or upstream/master to track the tip
```

Releases are safer than `master`: tags are what upstream builds their own images from.

Resolve any conflicts, then **run the checks before pushing** — they are the whole point of
the tests in this fork:

```bash
pnpm install               # lockfile may have moved
pnpm exec prisma generate  # schema may have moved
pnpm exec tsc --noEmit
pnpm test
```

`src/app/api/send/route.test.ts` and `src/lib/blocklist.test.ts` cover the parts most likely
to break silently in a rebase — the IP trust rules, the cached-session refresh, and feed
matching. If they pass, the patch survived.

Then:

```bash
git push --force-with-lease fork feat/session-ip
```

which triggers `fork-image.yml` and publishes a new multi-arch image. Redeploy in Dokploy
against the new `sha-` tag.

### What to look at during a rebase

| Area | Why |
| --- | --- |
| `src/app/api/send/route.ts` | Highest-churn file upstream, and holds most of this patch. Check `getSessionIp()` and the `cache.ipHash` guard survived intact. |
| `createSession.ts` | Upstream edits the insert column list a few times a year. `ip` must stay in the column list, the values list, and the `on conflict` clause. |
| `getWebsiteSession(s).ts`, `getRevenueSessions.ts` | If upstream adds or removes a session column, `ip` must stay in both the select and the `group by`. |
| `prisma/schema.prisma` | Keep the `ip` field on `Session`. If upstream ever adds their own IP column, drop ours and migrate rather than carrying both. |
| `messages.ts`, `en-US.json`, `constants.ts` | One-line list insertions; conflicts here resolve to "keep both". |
| `.github/workflows/fork-image.yml` | Fork-only file — should never conflict. If it does, upstream added a file of the same name. |

The migration directory is deliberately named `fork_add_session_ip` rather than taking the
next number. Upstream adds roughly two dozen migrations a year, so any number we picked
would eventually collide; a letter prefix sorts after every numeric one and can never
clash. **Do not rename it once it has been applied** — Prisma keys `_prisma_migrations` on
the directory name, so a rename makes it look unapplied and the re-run of
`ADD COLUMN "ip"` fails the deploy.

New upstream migrations apply on the next container start, in the same
`prisma migrate deploy` run. Take a database snapshot in Dokploy before deploying a major
upstream jump — the fork's own migration is trivially reversible (`ALTER TABLE "session"
DROP COLUMN "ip"`), but upstream's may not be.
