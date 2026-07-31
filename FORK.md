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
| `prisma/migrations/21_add_session_ip/migration.sql` | `ALTER TABLE "session" ADD COLUMN "ip" VARCHAR(45)` |
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
| No `payload.ip` (normal tracker traffic) | `getIpAddress(request.headers)` |
| `payload.ip` from an authenticated caller | `payload.ip` |
| `payload.ip` from an unauthenticated caller | nothing |

`checkAuth()` only runs when a `payload.ip` is actually present, so browser traffic never
pays for the extra lookup.

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

## Configuration

| Variable | Effect |
| --- | --- |
| `CLIENT_IP_HEADER` | Pin IP resolution to one header. **Set this to `cf-connecting-ip` behind Cloudflare** — see below. |
| `DISABLE_CLIENT_IP` | Set to `1` to stop persisting IPs. Everything else keeps working; the field renders as `—`. |
| `IGNORE_IP` | Unchanged upstream behaviour — comma-separated IPs/CIDRs to drop entirely. |

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

- **Postgres only.** The ClickHouse path of `getWebsiteSession` is untouched, because
  ClickHouse stores session attributes denormalised on `website_event`; adding `ip` there
  means a column on the events table plus the `website_event_stats_hourly` materialised
  view. With `CLICKHOUSE_URL` unset (the default, and what the Dokploy template deploys)
  this code path never runs.
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

**Option B — build in CI.** Push a GHCR image from a GitHub Actions workflow on this
fork and change only the `image:` line of the existing template.

Either way:

- Keep the **same `APP_SECRET`** and the **same database volume** as the current
  deployment, otherwise existing sessions and logins are invalidated.
- The container runs `prisma migrate deploy` on start (`npm run start-docker` →
  `check-db`), so `21_add_session_ip` applies automatically on first boot. No manual SQL.
- Keep the Cloudflare proxy (orange cloud) on, and keep Dokploy's Traefik router in front
  — `CF-Connecting-IP` passes through untouched.

### Rebasing on upstream

```bash
git remote add upstream https://github.com/umami-software/umami.git
git fetch upstream
git rebase upstream/master
```

Expect conflicts only in `createSession.ts` and `getWebsiteSession.ts` if upstream
changes the session columns.
