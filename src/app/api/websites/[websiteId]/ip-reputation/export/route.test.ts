import { beforeEach, describe, expect, test, vi } from 'vitest';
import { getQueryFilters, parseRequest } from '@/lib/request';
import { canViewAuthenticatedWebsite } from '@/permissions';
import { getIpReputationExportRows } from '@/queries/sql';
import { GET } from './route';

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
});

describe('GET /api/websites/:websiteId/ip-reputation/export', () => {
  test('generic export contains every row returned by the selected filters', async () => {
    vi.mocked(getIpReputationExportRows).mockResolvedValue([
      row('203.0.113.4'),
      {
        ...row('203.0.113.5'),
        sources: ['ustc'],
        confidence: 'medium',
        exportable: false,
      },
    ]);

    const response = await GET(
      new Request('http://localhost/api/websites/x/ip-reputation/export', { method: 'GET' }),
      { params: Promise.resolve({ websiteId: WEBSITE_ID }) },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('content-disposition')).toContain('ip-reputation-generic');
    await expect(response.text()).resolves.toBe('203.0.113.4\n203.0.113.5\n');
  });

  test('Cloudflare export uses the selected source and confidence filters', async () => {
    vi.mocked(parseRequest).mockResolvedValue({
      auth: { user: { id: 'user' } },
      query: {
        format: 'cloudflare',
        search: '203.0.113',
        source: 'ustc',
        confidence: 'medium',
      },
      error: undefined,
    });
    vi.mocked(getQueryFilters).mockResolvedValue({
      startDate: new Date('2026-08-01T00:00:00Z'),
      endDate: new Date('2026-08-31T23:59:59Z'),
      search: '203.0.113',
    });
    vi.mocked(getIpReputationExportRows).mockResolvedValue([
      {
        ...row('203.0.113.5'),
        sources: ['ustc'],
        confidence: 'medium',
        exportable: false,
      },
    ]);

    const response = await GET(
      new Request('http://localhost/api/websites/x/ip-reputation/export', { method: 'GET' }),
      { params: Promise.resolve({ websiteId: WEBSITE_ID }) },
    );

    expect(getIpReputationExportRows).toHaveBeenCalledWith(
      WEBSITE_ID,
      expect.objectContaining({
        search: '203.0.113',
        source: 'ustc',
        confidence: 'medium',
      }),
    );
    await expect(response.text()).resolves.toBe(
      '203.0.113.5,Umami sources=ustc hits=4 last=2026-08-20T00:00:00.000Z review_after=2026-08-27\r\n',
    );
  });
});
