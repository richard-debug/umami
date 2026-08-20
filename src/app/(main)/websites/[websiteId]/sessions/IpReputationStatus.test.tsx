import { expect, test } from 'vitest';
import { render, screen } from '@/test/render';
import { IpReputationStatus } from './IpReputationStatus';

test('shows the source count for a listed IP', () => {
  render(
    <IpReputationStatus
      reputation={{
        status: 'listed',
        confidence: 'high',
        sources: ['ustc', 'ipsum'],
        exportable: true,
      }}
    />,
  );

  expect(screen.getByText('Blocklisted · 2')).toHaveAttribute('title', 'ustc, ipsum');
});

test('uses neutral copy when no source matches', () => {
  render(
    <IpReputationStatus
      reputation={{ status: 'not-listed', confidence: 'none', sources: [], exportable: false }}
    />,
  );

  expect(screen.getByText('No match')).toBeInTheDocument();
});

test('distinguishes unavailable feeds from a missing IP', () => {
  const { rerender } = render(
    <IpReputationStatus
      reputation={{ status: 'unavailable', confidence: 'none', sources: [], exportable: false }}
    />,
  );

  expect(screen.getByText('Unavailable')).toBeInTheDocument();

  rerender(
    <IpReputationStatus
      reputation={{ status: 'unknown', confidence: 'none', sources: [], exportable: false }}
    />,
  );

  expect(screen.getByText('—')).toBeInTheDocument();
});
