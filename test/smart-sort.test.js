import { describe, expect, it } from 'vitest';
import { compareSmartKeys, getSmartSortScore, normalizeKey } from '../src/js/utils.js';

const NOW = Date.UTC(2026, 7, 17);

describe('smart token ordering', () => {
  it('keeps old records compatible with zero usage', () => {
    expect(normalizeKey({ name: 'Legacy', secret: 'JBSWY3DPEHPK3PXP' })).toMatchObject({ useCount: 0, lastUsed: 0 });
  });

  it('combines frequency with a smaller recency boost', () => {
    const frequent = { useCount: 8, lastUsed: NOW - 30 * 86_400_000 };
    const recent = { useCount: 1, lastUsed: NOW - 60_000 };
    expect(getSmartSortScore(frequent, NOW)).toBeGreaterThan(getSmartSortScore(recent, NOW));
  });

  it('orders favorites first, then commonly and recently used tokens', () => {
    const keys = [
      { name: 'Unused', favorite: false, useCount: 0, lastUsed: 0, order: 0 },
      { name: 'Frequent', favorite: false, useCount: 7, lastUsed: NOW - 86_400_000, order: 1 },
      { name: 'Favorite', favorite: true, useCount: 0, lastUsed: 0, order: 2 },
      { name: 'Recent', favorite: false, useCount: 2, lastUsed: NOW - 1_000, order: 3 },
    ];
    expect(keys.sort((left, right) => compareSmartKeys(left, right, NOW)).map((key) => key.name)).toEqual([
      'Favorite', 'Frequent', 'Recent', 'Unused',
    ]);
  });
});
