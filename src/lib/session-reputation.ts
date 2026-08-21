import type { Blocklist } from './blocklist';

export function addIpReputation<T extends { ip?: string | null }>(row: T, blocklist: Blocklist) {
  const reputation = blocklist.evaluate(row.ip);

  return { ...row, blocklist: reputation.sources, reputation };
}
