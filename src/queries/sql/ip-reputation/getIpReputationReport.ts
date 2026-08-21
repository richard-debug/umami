import { DEFAULT_PAGE_SIZE } from '@/lib/constants';
import {
  CORROBORATION_EXCLUDED_SOURCE_PREFIXES,
  HIGH_CONFIDENCE_SOURCE_PREFIXES,
  MIN_CORROBORATING_SOURCES,
} from '@/lib/ip-reputation';
import type { IpReputationExportRow } from '@/lib/ip-reputation-export';
import prisma from '@/lib/prisma';
import type { QueryFilters } from '@/lib/types';

const FUNCTION_NAME = 'getIpReputationReport';
const HIGH_CONFIDENCE_SOURCE_SQL = HIGH_CONFIDENCE_SOURCE_PREFIXES.map(
  (_, index) => `source like {{highConfidenceSource${index}}}::text`,
).join(' or ');
const CORROBORATING_SOURCE_SQL = CORROBORATION_EXCLUDED_SOURCE_PREFIXES.map(
  (_, index) => `source not like {{excludedSource${index}}}::text`,
).join(' and ');

export interface IpReputationFilters extends QueryFilters {
  source?: string;
  confidence?: 'high' | 'medium';
}

interface RawIpReputationRow {
  ip: string;
  sources: string[];
  firstSeenAt: Date;
  lastSeenAt: Date;
  hitCount: bigint | number;
  exportable: boolean;
}

const REPORT_CTE = `
  with grouped as (
    select
      ip,
      array_agg(distinct source order by source) as sources,
      min(first_seen_at) as "firstSeenAt",
      max(last_seen_at) as "lastSeenAt",
      sum(hit_count) as "hitCount",
      count(distinct source) filter (where ${CORROBORATING_SOURCE_SQL}) >= ${MIN_CORROBORATING_SOURCES}
        or bool_or(${HIGH_CONFIDENCE_SOURCE_SQL}) as exportable
    from ip_reputation_hit
    where website_id = {{websiteId::uuid}}
      and observed_date >= ({{startDate}} at time zone 'UTC')::date
      and observed_date <= ({{endDate}} at time zone 'UTC')::date
    group by ip
  ), filtered as (
    select *
    from grouped
    where ({{search}}::text is null or ip ilike {{searchPattern}}::text)
      and ({{source}}::text is null or {{source}}::text = any(sources))
      and (
        {{confidence}}::text is null
        or ({{confidence}}::text = 'high' and exportable)
        or ({{confidence}}::text = 'medium' and not exportable)
      )
  )
`;

function getParams(websiteId: string, filters: IpReputationFilters) {
  const { startDate, endDate, search, source, confidence } = filters;

  return {
    websiteId,
    startDate,
    endDate,
    search: search || null,
    searchPattern: search ? `%${search}%` : null,
    source: source || null,
    confidence: confidence || null,
    ...Object.fromEntries(
      HIGH_CONFIDENCE_SOURCE_PREFIXES.map((sourceName, index) => [
        `highConfidenceSource${index}`,
        `${sourceName}%`,
      ]),
    ),
    ...Object.fromEntries(
      CORROBORATION_EXCLUDED_SOURCE_PREFIXES.map((sourceName, index) => [
        `excludedSource${index}`,
        `${sourceName}%`,
      ]),
    ),
  };
}

function normalizeRows(rows: RawIpReputationRow[]): IpReputationExportRow[] {
  return rows.map(row => ({
    ...row,
    hitCount: Number(row.hitCount),
    confidence: row.exportable ? 'high' : 'medium',
  }));
}

export async function getIpReputationReport(websiteId: string, filters: IpReputationFilters) {
  const { page = 1, pageSize } = filters;
  const size = Math.min(Number(pageSize) || DEFAULT_PAGE_SIZE, 1000);
  const offset = size * (Number(page) - 1);
  const params = getParams(websiteId, filters);

  const [rows, summaryRows] = await Promise.all([
    prisma.rawQuery(
      `${REPORT_CTE}
      select ip, sources, "firstSeenAt", "lastSeenAt", "hitCount", exportable
      from filtered
      order by "lastSeenAt" desc
      limit ${size} offset ${offset}
      `,
      params,
      FUNCTION_NAME,
    ) as Promise<RawIpReputationRow[]>,
    prisma.rawQuery(
      `${REPORT_CTE}
      select
        count(*) as "uniqueIps",
        count(*) filter (where exportable) as "highConfidence",
        coalesce(sum("hitCount"), 0) as observations,
        coalesce(
          (select array_agg(distinct item order by item)
           from filtered, unnest(sources) as item),
          '{}'::text[]
        ) as sources
      from filtered
      `,
      params,
      `${FUNCTION_NAME}Summary`,
    ) as Promise<
      {
        uniqueIps: bigint | number;
        highConfidence: bigint | number;
        observations: bigint | number;
        sources: string[];
      }[]
    >,
  ]);

  const summary = summaryRows[0] ?? {
    uniqueIps: 0,
    highConfidence: 0,
    observations: 0,
    sources: [],
  };

  return {
    data: normalizeRows(rows),
    count: Number(summary.uniqueIps),
    page: Number(page),
    pageSize: size,
    summary: {
      uniqueIps: Number(summary.uniqueIps),
      highConfidence: Number(summary.highConfidence),
      observations: Number(summary.observations),
      sources: summary.sources,
    },
  };
}

export async function getIpReputationExportRows(websiteId: string, filters: IpReputationFilters) {
  const rows = (await prisma.rawQuery(
    `${REPORT_CTE}
    select ip, sources, "firstSeenAt", "lastSeenAt", "hitCount", exportable
    from filtered
    order by "lastSeenAt" desc
    `,
    getParams(websiteId, filters),
    'getIpReputationExportRows',
  )) as RawIpReputationRow[];

  return normalizeRows(rows);
}
