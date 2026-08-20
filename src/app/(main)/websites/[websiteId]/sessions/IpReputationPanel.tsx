'use client';
import {
  Button,
  Column,
  Icon,
  ListItem,
  Menu,
  MenuItem,
  MenuTrigger,
  Popover,
  Row,
  Select,
  Text,
  useToast,
} from '@umami/react-zen';
import type { Key } from 'react';
import { useMemo, useState } from 'react';
import { DataGrid } from '@/components/common/DataGrid';
import {
  useDateParameters,
  useIpReputationQuery,
  useMessages,
  usePageParameters,
} from '@/components/hooks';
import { Download } from '@/components/icons';
import { getApiUrl } from '@/lib/api-url';
import { getClientAuthToken } from '@/lib/client';
import { formatNumber } from '@/lib/format';
import { buildPath } from '@/lib/url';
import { IpReputationTable } from './IpReputationTable';

type ConfidenceFilter = 'all' | 'high' | 'medium';

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <Column gap="1" minWidth="130px">
      <Text size="sm" color="muted">
        {label}
      </Text>
      <Text size="lg" weight="bold">
        {value}
      </Text>
    </Column>
  );
}

function ExportMenu({
  websiteId,
  source,
  confidence,
}: {
  websiteId: string;
  source?: string;
  confidence?: 'high' | 'medium';
}) {
  const { t, labels, messages } = useMessages();
  const { toast } = useToast();
  const date = useDateParameters();
  const { search } = usePageParameters();
  const [isDownloading, setDownloading] = useState(false);

  const handleAction = async (key: Key) => {
    const format = key.toString();
    const extension = format === 'generic' ? 'txt' : 'csv';

    setDownloading(true);

    try {
      const url = buildPath(getApiUrl(`/websites/${websiteId}/ip-reputation/export`), {
        ...date,
        search,
        source,
        confidence,
        format,
      });
      const response = await fetch(url, {
        headers: { authorization: `Bearer ${getClientAuthToken()}` },
      });

      if (!response.ok) {
        throw new Error(`Export failed: ${response.status}`);
      }

      const objectUrl = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a');

      anchor.href = objectUrl;
      anchor.download = `ip-reputation-${format}.${extension}`;
      anchor.click();
      URL.revokeObjectURL(objectUrl);
    } catch {
      toast(t(messages.error));
    } finally {
      setDownloading(false);
    }
  };

  return (
    <MenuTrigger>
      <Button variant="quiet" isDisabled={isDownloading}>
        <Icon>
          <Download />
        </Icon>
        <Text size="sm">{t(labels.download)}</Text>
      </Button>
      <Popover placement="bottom end">
        <Menu onAction={handleAction} aria-label={t(labels.download)}>
          <MenuItem id="audit">{t(labels.auditCsv)}</MenuItem>
          <MenuItem id="generic">{t(labels.genericWafList)}</MenuItem>
          <MenuItem id="cloudflare">{t(labels.cloudflareCsv)}</MenuItem>
        </Menu>
      </Popover>
    </MenuTrigger>
  );
}

export function IpReputationPanel({ websiteId }: { websiteId: string }) {
  const { t, labels } = useMessages();
  const [source, setSource] = useState('all');
  const [confidence, setConfidence] = useState<ConfidenceFilter>('all');
  const sourceParam = source === 'all' ? undefined : source;
  const confidenceParam = confidence === 'all' ? undefined : confidence;
  const query = useIpReputationQuery(websiteId, {
    source: sourceParam,
    confidence: confidenceParam,
  });
  const summary = (query.data as any)?.summary;
  const sourceOptions = useMemo(
    () => [...new Set([...(summary?.sources ?? []), ...(sourceParam ? [sourceParam] : [])])],
    [summary?.sources, sourceParam],
  );

  return (
    <Column gap="4">
      <Text color="muted">
        Addresses observed on this website that matched a threat feed during the selected period.
        WAF exports re-check the current snapshot and include high-confidence matches only.
      </Text>
      <Row gap="6" wrap="wrap" paddingY="2">
        <SummaryItem label={t(labels.ipAddress)} value={formatNumber(summary?.uniqueIps ?? 0)} />
        <SummaryItem
          label={t(labels.highConfidence)}
          value={formatNumber(summary?.highConfidence ?? 0)}
        />
        <SummaryItem
          label={t(labels.observations)}
          value={formatNumber(summary?.observations ?? 0)}
        />
      </Row>
      <DataGrid
        query={query as any}
        allowPaging
        allowSearch
        renderActions={() => (
          <Row gap alignItems="center" wrap="wrap">
            <Select value={source} onChange={setSource} style={{ minWidth: 150 }}>
              <ListItem id="all">{t(labels.allSources)}</ListItem>
              {sourceOptions.map(item => (
                <ListItem key={item} id={item}>
                  {item}
                </ListItem>
              ))}
            </Select>
            <Select
              value={confidence}
              onChange={value => setConfidence(value as ConfidenceFilter)}
              style={{ minWidth: 150 }}
            >
              <ListItem id="all">{t(labels.allConfidence)}</ListItem>
              <ListItem id="high">{t(labels.highConfidence)}</ListItem>
              <ListItem id="medium">{t(labels.medium)}</ListItem>
            </Select>
            <ExportMenu websiteId={websiteId} source={sourceParam} confidence={confidenceParam} />
          </Row>
        )}
      >
        {({ data }) => <IpReputationTable data={data} />}
      </DataGrid>
    </Column>
  );
}
