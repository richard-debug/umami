import { expect, test, vi } from 'vitest';
import { useIpReputationQuery } from '@/components/hooks';
import { render, screen, waitFor } from '@/test/render';
import { IpReputationPanel } from './IpReputationPanel';

vi.mock('@/components/hooks', async importOriginal => ({
  ...(await importOriginal<typeof import('@/components/hooks')>()),
  useIpReputationQuery: vi.fn(),
}));

const queryMock = vi.mocked(useIpReputationQuery);

test('renders report data, filters, and the export menu', async () => {
  queryMock.mockReturnValue({
    data: {
      data: [
        {
          ip: '203.0.113.4',
          confidence: 'high',
          sources: ['feodo', 'spamhaus-drop-v4'],
          hitCount: 9,
          firstSeenAt: '2026-08-01T00:00:00Z',
          lastSeenAt: '2026-08-20T00:00:00Z',
        },
      ],
      count: 1,
      page: 1,
      pageSize: 50,
      summary: {
        uniqueIps: 1,
        highConfidence: 1,
        observations: 9,
        sources: ['feodo', 'spamhaus-drop-v4'],
      },
    },
    isLoading: false,
    isFetching: false,
    error: null,
  } as any);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('203.0.113.4\n')),
  );
  const NativeURL = URL;

  class TestURL extends NativeURL {
    static createObjectURL = vi.fn(() => 'blob:test');
    static revokeObjectURL = vi.fn();
  }

  vi.stubGlobal('URL', TestURL);
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

  const { user } = render(<IpReputationPanel websiteId="11111111-1111-1111-1111-111111111111" />);

  expect(screen.getByText('203.0.113.4')).toBeInTheDocument();
  expect(screen.getByText('feodo, spamhaus-drop-v4')).toBeInTheDocument();
  expect(screen.getAllByText('High confidence')).toHaveLength(3);
  expect(screen.getAllByText('All sources')).toHaveLength(2);
  expect(screen.getAllByText('All confidence')).toHaveLength(2);

  await user.click(screen.getByRole('button', { name: /All confidence/ }));
  await user.click(screen.getAllByRole('option', { name: 'High confidence' }).at(-1));

  await waitFor(() =>
    expect(queryMock).toHaveBeenLastCalledWith(
      '11111111-1111-1111-1111-111111111111',
      expect.objectContaining({ confidence: 'high' }),
    ),
  );

  await user.click(screen.getByRole('button', { name: 'Download' }));

  expect(screen.getByRole('menuitem', { name: 'Audit CSV' })).toBeInTheDocument();
  expect(screen.getByRole('menuitem', { name: 'Generic WAF list' })).toBeInTheDocument();
  expect(screen.getByRole('menuitem', { name: 'Cloudflare CSV' })).toBeInTheDocument();

  await user.click(screen.getByRole('menuitem', { name: 'Generic WAF list' }));

  expect(fetch).toHaveBeenCalledWith(
    expect.stringContaining('format=generic'),
    expect.objectContaining({ headers: expect.any(Object) }),
  );
});
