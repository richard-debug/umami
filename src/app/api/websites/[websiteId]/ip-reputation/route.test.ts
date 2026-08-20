import { beforeEach, describe, expect, test, vi } from 'vitest';
import { getQueryFilters, parseRequest } from '@/lib/request';
import { canViewAuthenticatedWebsite } from '@/permissions';
import { getIpReputationReport } from '@/queries/sql';
import { GET } from './route';

vi.mock('@/lib/request', () => ({
  getQueryFilters: vi.fn(),
  parseRequest: vi.fn(),
}));
vi.mock('@/permissions', () => ({ canViewAuthenticatedWebsite: vi.fn() }));
vi.mock('@/queries/sql', () => ({ getIpReputationReport: vi.fn() }));

const WEBSITE_ID = '11111111-1111-1111-1111-111111111111';

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(parseRequest).mockResolvedValue({
    auth: { user: { id: 'user' } },
    query: { source: 'feodo', confidence: 'high' },
    error: undefined,
  });
  vi.mocked(canViewAuthenticatedWebsite).mockResolvedValue(true);
  vi.mocked(getQueryFilters).mockResolvedValue({
    startDate: new Date('2026-08-01T00:00:00Z'),
    endDate: new Date('2026-08-31T23:59:59Z'),
    page: 1,
    pageSize: 50,
  });
  vi.mocked(getIpReputationReport).mockResolvedValue({
    data: [],
    count: 0,
    page: 1,
    pageSize: 50,
    summary: { uniqueIps: 0, highConfidence: 0, observations: 0, sources: [] },
  });
});

describe('GET /api/websites/:websiteId/ip-reputation', () => {
  test('returns the authenticated period report with reputation filters', async () => {
    const response = await GET(
      new Request('http://localhost/api/websites/x/ip-reputation', { method: 'GET' }),
      { params: Promise.resolve({ websiteId: WEBSITE_ID }) },
    );

    expect(response.status).toBe(200);
    expect(getIpReputationReport).toHaveBeenCalledWith(
      WEBSITE_ID,
      expect.objectContaining({ source: 'feodo', confidence: 'high' }),
    );
    await expect(response.json()).resolves.toHaveProperty('summary.uniqueIps', 0);
  });

  test('does not expose stored addresses through public website shares', async () => {
    vi.mocked(canViewAuthenticatedWebsite).mockResolvedValue(false);

    const response = await GET(
      new Request('http://localhost/api/websites/x/ip-reputation', { method: 'GET' }),
      { params: Promise.resolve({ websiteId: WEBSITE_ID }) },
    );

    expect(response.status).toBe(401);
    expect(getIpReputationReport).not.toHaveBeenCalled();
  });
});
