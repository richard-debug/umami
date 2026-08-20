import { beforeEach, expect, test, vi } from 'vitest';
import prisma from '@/lib/prisma';
import { saveIpReputationHits } from './saveIpReputationHits';

vi.mock('@/lib/prisma', () => ({ default: { rawQuery: vi.fn() } }));

const rawQuery = vi.mocked(prisma.rawQuery);

beforeEach(() => rawQuery.mockReset());

test('upserts one deduplicated daily row per matching source', async () => {
  const observedAt = new Date('2026-08-20T12:34:56Z');

  await saveIpReputationHits({
    websiteId: '11111111-1111-1111-1111-111111111111',
    ip: '203.0.113.4',
    sources: ['feodo', 'feodo', 'spamhaus-drop-v4'],
    observedAt,
  });

  expect(rawQuery).toHaveBeenCalledWith(
    expect.stringMatching(/on conflict \(website_id, ip, source, observed_date\) do update/),
    expect.objectContaining({
      ip: '203.0.113.4',
      sources: ['feodo', 'spamhaus-drop-v4'],
      observedAt,
    }),
    'saveIpReputationHits',
  );
});

test('does not write an empty match set', async () => {
  await saveIpReputationHits({
    websiteId: '11111111-1111-1111-1111-111111111111',
    ip: '203.0.113.4',
    sources: [],
    observedAt: new Date(),
  });

  expect(rawQuery).not.toHaveBeenCalled();
});
