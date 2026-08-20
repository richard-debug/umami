import { beforeEach, expect, test, vi } from 'vitest';
import prisma from '@/lib/prisma';
import { getIpReputationReport } from './getIpReputationReport';

vi.mock('@/lib/prisma', () => ({ default: { rawQuery: vi.fn() } }));

const rawQuery = vi.mocked(prisma.rawQuery);

beforeEach(() => rawQuery.mockReset());

test('returns paged rows and JSON-safe summary numbers', async () => {
  rawQuery
    .mockResolvedValueOnce([
      {
        ip: '203.0.113.4',
        sources: ['feodo'],
        firstSeenAt: new Date('2026-08-01T00:00:00Z'),
        lastSeenAt: new Date('2026-08-20T00:00:00Z'),
        hitCount: 7n,
        exportable: true,
      },
    ])
    .mockResolvedValueOnce([
      { uniqueIps: 2n, highConfidence: 1n, observations: 9n, sources: ['feodo', 'ipsum'] },
    ]);

  const report = await getIpReputationReport('11111111-1111-1111-1111-111111111111', {
    startDate: new Date('2026-08-01T00:00:00Z'),
    endDate: new Date('2026-08-31T23:59:59Z'),
    page: 1,
    pageSize: 50,
    confidence: 'high',
  });

  expect(report.data[0]).toMatchObject({ hitCount: 7, confidence: 'high' });
  expect(report).toMatchObject({
    count: 2,
    summary: {
      uniqueIps: 2,
      highConfidence: 1,
      observations: 9,
      sources: ['feodo', 'ipsum'],
    },
  });
  expect(rawQuery.mock.calls[0][1]).toMatchObject({ confidence: 'high' });
});
