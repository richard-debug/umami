import { describe, expect, test } from 'vitest';
import { formatIpReputationExport } from './ip-reputation-export';

const rows = [
  {
    ip: '203.0.113.4',
    sources: ['spamhaus-drop-v4', 'feodo'],
    firstSeenAt: new Date('2026-08-01T01:02:03.000Z'),
    lastSeenAt: new Date('2026-08-20T04:05:06.000Z'),
    hitCount: 12,
    confidence: 'high' as const,
    exportable: true,
  },
];

describe('formatIpReputationExport', () => {
  test('creates a reviewable audit CSV', () => {
    expect(formatIpReputationExport(rows, 'audit')).toBe(
      [
        'ip,sources,first_seen,last_seen,hit_count,confidence,review_after',
        '203.0.113.4,spamhaus-drop-v4|feodo,2026-08-01T01:02:03.000Z,2026-08-20T04:05:06.000Z,12,high,2026-08-27',
      ].join('\r\n'),
    );
  });

  test('creates a generic one-address-per-line list', () => {
    expect(formatIpReputationExport(rows, 'generic')).toBe('203.0.113.4\n');
  });

  test('creates Cloudflare WAF rows with one unquoted comma delimiter', () => {
    expect(formatIpReputationExport(rows, 'cloudflare')).toBe(
      '203.0.113.4,Umami sources=spamhaus-drop-v4+feodo hits=12 last=2026-08-20T04:05:06.000Z review_after=2026-08-27\r\n',
    );
  });

  test('keeps custom source names from introducing Cloudflare CSV delimiters', () => {
    const unsafe = [{ ...rows[0], sources: ['bad,source', 'evil";\r\n\t|value'] }];
    const output = formatIpReputationExport(unsafe, 'cloudflare');
    const line = output.slice(0, -2);

    expect(output.match(/\r\n/g)).toHaveLength(1);
    expect(line.match(/,/g)).toHaveLength(1);
    expect(line).not.toMatch(/[";\r\n\t|]/);
  });

  test('escapes formula-like feed labels in audit CSV output', () => {
    const unsafe = [{ ...rows[0], sources: ['=external-value'] }];

    expect(formatIpReputationExport(unsafe, 'audit')).toContain("'=external-value");
  });
});
