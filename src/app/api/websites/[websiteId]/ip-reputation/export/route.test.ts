import { beforeEach, describe, expect, test, vi } from 'vitest';
import { getBlocklist } from '@/lib/blocklist';
import { getQueryFilters, parseRequest } from '@/lib/request';
import { canViewAuthenticatedWebsite } from '@/permissions';
import { getIpReputationExportRows } from '@/queries/sql';
import { GET } from './route';

vi.mock('@/lib/blocklist', () => ({ getBlocklist: vi.fn() }));
vi.mock('@/lib/request', () => ({
  getQueryFilters: vi.fn(),
  parseRequest: vi.fn(),
}));
vi.mock('@/permissions', () => ({ canViewAuthenticatedWebsite: vi.fn() }));
vi.mock('@/queries/sql', () => ({ getIpReputationExportRows: vi.fn() }));

const WEBSITE_ID = '11111111-1111-1111-1111-111111111111';
const row = (ip: string) => ({
  ip,
  sources: ['spamhaus-drop-v4'],
  firstSeenAt: new Date('2026-08-01T00:00:00Z'),
  lastSeenAt: new Date('2026-08-20T00:00:00Z'),
  hitCount: 4,
  confidence: 'high' as const,
  exportable: true,
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(parseRequest).mockResolvedValue({
    auth: { user: { id: 'user' } },
    query: { format: 'generic' },
    error: undefined,
  });
  vi.mocked(canViewAuthenticatedWebsite).mockResolvedValue(true);
  vi.mocked(getQueryFilters).mockResolvedValue({
    startDate: new Date('2026-08-01T00:00:00Z'),
    endDate: new Date('2026-08-31T23:59:59Z'),
  });
  vi.mocked(getIpReputationExportRows).mockResolvedValue([row('203.0.113.4'), row('203.0.113.5')]);
  vi.mocked(getBlocklist).mockResolvedValue({
    sources: ['spamhaus-drop-v4'],
    check: ip => (ip === '203.0.113.4' ? ['spamhaus-drop-v4'] : ['aggregate']),
    evaluate: ip => ({
      status: 'listed',
      confidence: ip === '203.0.113.4' ? 'high' : 'medium',
      sources: ip === '203.0.113.4' ? ['spamhaus-drop-v4'] : ['aggregate'],
      exportable: ip === '203.0.113.4',
    }),
  });
});

describe('GET /api/websites/:websiteId/ip-reputation/export', () => {
  test('exports only addresses that remain high confidence in the current snapshot', async () => {
    const response = await GET(
      new Request('http://localhost/api/websites/x/ip-reputation/export', { method: 'GET' }),
      { params: Promise.resolve({ websiteId: WEBSITE_ID }) },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('content-disposition')).toContain('ip-reputation-generic');
    await expect(response.text()).resolves.toBe('203.0.113.4\n');
  });
});
