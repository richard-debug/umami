export type IpReputationExportFormat = 'audit' | 'generic' | 'cloudflare';

const CLOUDFLARE_DESCRIPTION_MAX_LENGTH = 500;

export interface IpReputationExportRow {
  ip: string;
  sources: string[];
  firstSeenAt: Date | string;
  lastSeenAt: Date | string;
  hitCount: number;
  confidence: 'high' | 'medium';
  exportable: boolean;
}

function protectFormula(value: string) {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}

function csvCell(value: string, forceQuote = false) {
  const safe = protectFormula(value);
  const escaped = safe.replaceAll('"', '""');

  return forceQuote || /[",\r\n]/.test(escaped) ? `"${escaped}"` : escaped;
}

function toIso(value: Date | string) {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

function getReviewDate(value: Date | string) {
  const date = new Date(toIso(value));

  date.setUTCDate(date.getUTCDate() + 7);

  return date.toISOString().slice(0, 10);
}

function getCloudflareDescription(row: IpReputationExportRow) {
  const prefix = 'Umami sources=';
  const suffix = ` hits=${row.hitCount} last=${toIso(row.lastSeenAt)} review_after=${getReviewDate(row.lastSeenAt)}`;
  const sources = row.sources.map(source => source.replaceAll(/[^a-zA-Z0-9._-]+/g, '_')).join('+');
  const sourceLength = Math.max(
    0,
    CLOUDFLARE_DESCRIPTION_MAX_LENGTH - prefix.length - suffix.length,
  );

  return `${prefix}${sources.slice(0, sourceLength)}${suffix}`;
}

export function formatIpReputationExport(
  rows: IpReputationExportRow[],
  format: IpReputationExportFormat,
) {
  const uniqueRows = [...new Map(rows.map(row => [row.ip, row])).values()];

  if (format === 'generic') {
    return uniqueRows.map(row => row.ip).join('\n') + (uniqueRows.length ? '\n' : '');
  }

  if (format === 'cloudflare') {
    return uniqueRows
      .map(row => {
        const description = getCloudflareDescription(row);

        return `${csvCell(row.ip)},${csvCell(description)}`;
      })
      .join('\r\n')
      .concat(uniqueRows.length ? '\r\n' : '');
  }

  const header = 'ip,sources,first_seen,last_seen,hit_count,confidence,review_after';
  const body = uniqueRows.map(row =>
    [
      row.ip,
      row.sources.join('|'),
      toIso(row.firstSeenAt),
      toIso(row.lastSeenAt),
      String(row.hitCount),
      row.confidence,
      getReviewDate(row.lastSeenAt),
    ]
      .map(value => csvCell(value))
      .join(','),
  );

  return [header, ...body].join('\r\n');
}
