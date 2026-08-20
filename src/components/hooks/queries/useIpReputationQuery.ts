import { useApi } from '../useApi';
import { useDateParameters } from '../useDateParameters';
import { usePagedQuery } from '../usePagedQuery';

export function useIpReputationQuery(
  websiteId: string,
  params?: { source?: string; confidence?: 'high' | 'medium' },
) {
  const { get } = useApi();
  const { startAt, endAt, unit, timezone } = useDateParameters();

  return usePagedQuery({
    queryKey: ['ip-reputation', { websiteId, startAt, endAt, unit, timezone, ...params }],
    queryFn: pageParams =>
      get(`/websites/${websiteId}/ip-reputation`, {
        startAt,
        endAt,
        unit,
        timezone,
        ...pageParams,
        ...params,
      }),
  });
}
