import { FIELD_LENGTH } from '@/lib/constants';
import { truncateString } from '@/lib/format';
import prisma from '@/lib/prisma';

const FUNCTION_NAME = 'saveIpReputationHits';

export interface SaveIpReputationHitsParams {
  websiteId: string;
  ip: string;
  sources: string[];
  observedAt: Date;
}

export async function saveIpReputationHits({
  websiteId,
  ip,
  sources,
  observedAt,
}: SaveIpReputationHitsParams) {
  const normalizedSources = [
    ...new Set(sources.map(source => truncateString(source, 64)).filter(Boolean)),
  ];

  if (!normalizedSources.length) {
    return;
  }

  return prisma.rawQuery(
    `
    insert into ip_reputation_hit (
      website_id,
      ip,
      source,
      observed_date,
      first_seen_at,
      last_seen_at,
      hit_count
    )
    select
      {{websiteId}},
      {{ip}},
      source,
      ({{observedAt}})::date,
      {{observedAt}},
      {{observedAt}},
      1
    from unnest({{sources}}::text[]) as source
    on conflict (website_id, ip, source, observed_date) do update
      set first_seen_at = least(ip_reputation_hit.first_seen_at, excluded.first_seen_at),
          last_seen_at = greatest(ip_reputation_hit.last_seen_at, excluded.last_seen_at),
          hit_count = ip_reputation_hit.hit_count + 1
    `,
    {
      websiteId,
      ip: truncateString(ip, FIELD_LENGTH.ip),
      sources: normalizedSources,
      observedAt,
    },
    FUNCTION_NAME,
  );
}
