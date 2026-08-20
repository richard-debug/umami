import { DataColumn, DataTable, type DataTableProps, StatusLight } from '@umami/react-zen';
import { DateDistance } from '@/components/common/DateDistance';
import { useMessages } from '@/components/hooks';
import { formatNumber } from '@/lib/format';

export function IpReputationTable(props: DataTableProps) {
  const { t, labels } = useMessages();
  return (
    <DataTable {...props}>
      <DataColumn id="ip" label={t(labels.ipAddress)} width="200px" />
      <DataColumn id="confidence" label={t(labels.confidence)} width="150px">
        {(row: any) => (
          <StatusLight variant={row.confidence === 'high' ? 'error' : 'warning'}>
            {row.confidence === 'high' ? t(labels.highConfidence) : t(labels.medium)}
          </StatusLight>
        )}
      </DataColumn>
      <DataColumn id="sources" label={t(labels.sources)} width="280px">
        {(row: any) => <span title={row.sources.join(', ')}>{row.sources.join(', ')}</span>}
      </DataColumn>
      <DataColumn id="hitCount" label={t(labels.hits)} width="100px">
        {(row: any) => formatNumber(row.hitCount)}
      </DataColumn>
      <DataColumn id="firstSeenAt" label={t(labels.firstSeen)} width="160px">
        {(row: any) => <DateDistance date={new Date(row.firstSeenAt)} />}
      </DataColumn>
      <DataColumn id="lastSeenAt" label={t(labels.lastSeen)} width="160px">
        {(row: any) => <DateDistance date={new Date(row.lastSeenAt)} />}
      </DataColumn>
    </DataTable>
  );
}
