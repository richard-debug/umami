export type IpReputationExportFormat = 'audit' | 'generic' | 'cloudflare';

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
        const description = `Umami: ${row.sources.join('|')}; hits=${row.hitCount}; last=${toIso(row.lastSeenAt)}`;

        return `${csvCell(row.ip)},${csvCell(description, true)}`;
      })
      .join('\r\n')
      .concat(uniqueRows.length ? '\r\n' : '');
  }

  const header = 'ip,sources,first_seen,last_seen,hit_count,confidence';
  const body = uniqueRows.map(row =>
    [
      row.ip,
      row.sources.join('|'),
      toIso(row.firstSeenAt),
      toIso(row.lastSeenAt),
      String(row.hitCount),
      row.confidence,
    ]
      .map(value => csvCell(value))
      .join(','),
  );

  return [header, ...body].join('\r\n');
}
