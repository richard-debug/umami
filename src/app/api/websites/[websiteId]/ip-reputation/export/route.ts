import { z } from 'zod';
import {
  formatIpReputationExport,
  type IpReputationExportFormat,
} from '@/lib/ip-reputation-export';
import { getQueryFilters, parseRequest } from '@/lib/request';
import { unauthorized } from '@/lib/response';
import { searchParams, withDateRange } from '@/lib/schema';
import { canViewAuthenticatedWebsite } from '@/permissions';
import { getIpReputationExportRows } from '@/queries/sql';

const contentTypes: Record<IpReputationExportFormat, string> = {
  audit: 'text/csv; charset=utf-8',
  generic: 'text/plain; charset=utf-8',
  cloudflare: 'text/csv; charset=utf-8',
};

export async function GET(
  request: Request,
  { params }: { params: Promise<{ websiteId: string }> },
) {
  const schema = withDateRange({
    ...searchParams,
    source: z.string().optional(),
    confidence: z.enum(['high', 'medium']).optional(),
    format: z.enum(['audit', 'generic', 'cloudflare']),
  });
  const { auth, query, error } = await parseRequest(request, schema);

  if (error) {
    return error();
  }

  const { websiteId } = await params;

  if (!(await canViewAuthenticatedWebsite(auth, websiteId))) {
    return unauthorized();
  }

  const filters = await getQueryFilters(query, websiteId);
  const rows = await getIpReputationExportRows(websiteId, {
    ...filters,
    source: query.source,
    confidence: query.confidence,
  });
  const format = query.format as IpReputationExportFormat;
  const extension = format === 'generic' ? 'txt' : 'csv';

  return new Response(formatIpReputationExport(rows, format), {
    headers: {
      'Content-Disposition': `attachment; filename="ip-reputation-${format}.${extension}"`,
      'Content-Type': contentTypes[format],
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
