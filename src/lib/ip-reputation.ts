export const MIN_CORROBORATING_SOURCES = 2;
export const HIGH_CONFIDENCE_SOURCE_PREFIXES = ['spamhaus-drop', 'feodo'] as const;
// These defaults are aggregates with overlapping upstream inputs. Seeing the same address
// in two of them is not independent corroboration, so they never contribute to the
// two-source rule. Direct specialist feeds still qualify above on their own.
export const CORROBORATION_EXCLUDED_SOURCE_PREFIXES = ['firehol', 'ipsum', 'ustc'] as const;

export function getIpReputationConfidence(sources: string[]) {
  const corroboratingSources = sources.filter(
    name => !CORROBORATION_EXCLUDED_SOURCE_PREFIXES.some(source => name.startsWith(source)),
  );
  const highConfidence =
    new Set(corroboratingSources).size >= MIN_CORROBORATING_SOURCES ||
    sources.some(name => HIGH_CONFIDENCE_SOURCE_PREFIXES.some(source => name.startsWith(source)));

  return {
    confidence: highConfidence ? ('high' as const) : ('medium' as const),
    exportable: highConfidence,
  };
}
