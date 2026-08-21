import { StatusLight } from '@umami/react-zen';
import { useMessages } from '@/components/hooks';
import type { IpReputation } from '@/lib/blocklist';

export function IpReputationStatus({ reputation }: { reputation?: IpReputation }) {
  const { t, labels } = useMessages();

  if (!reputation || reputation.status === 'unknown') {
    return '—';
  }

  if (reputation.status === 'unavailable') {
    return (
      <StatusLight variant="warning">
        <span title={reputation.sources.join(', ') || undefined}>{t(labels.unavailable)}</span>
      </StatusLight>
    );
  }

  if (reputation.status === 'not-listed') {
    return <StatusLight variant="none">{t(labels.noMatch)}</StatusLight>;
  }

  return (
    <StatusLight variant="error">
      <span title={reputation.sources.join(', ')}>
        {t(labels.blocklisted)} · {reputation.sources.length}
      </span>
    </StatusLight>
  );
}
