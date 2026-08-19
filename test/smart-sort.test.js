import { describe, expect, it } from 'vitest';
import { compareSmartKeys, compareSmartWorkflowNotes, compareStaleKeys, compareStaleWorkflowNotes, getSmartSortScore, normalizeKey, normalizeWorkflowNote } from '../src/js/utils.js';

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

  it('orders never-used and oldest-used tokens first regardless of favorites', () => {
    const keys = [
      { name: 'Recent favorite', favorite: true, lastUsed: NOW - 1_000 },
      { name: 'Old', favorite: false, lastUsed: NOW - 30 * 86_400_000 },
      { name: 'Never', favorite: false, lastUsed: 0 },
    ];
    expect(keys.sort(compareStaleKeys).map((key) => key.name)).toEqual(['Never', 'Old', 'Recent favorite']);
  });
});

describe('smart workflow ordering', () => {
  it('keeps legacy workflow records compatible with zero usage', () => {
    expect(normalizeWorkflowNote({ title: 'Legacy', content: 'Step' })).toMatchObject({ group: '', favorite: false, useCount: 0, lastUsed: 0 });
  });

  it('normalizes and limits workflow groups', () => {
    expect(normalizeWorkflowNote({ title: 'Grouped', group: `  ${'运'.repeat(110)}  ` }).group).toBe('运'.repeat(100));
  });

  it('orders favorites first, then commonly and recently used workflows', () => {
    const notes = [
      { title: 'Unused', favorite: false, useCount: 0, lastUsed: 0, updatedAt: 4 },
      { title: 'Frequent', favorite: false, useCount: 7, lastUsed: NOW - 86_400_000, updatedAt: 3 },
      { title: 'Favorite', favorite: true, useCount: 0, lastUsed: 0, updatedAt: 2 },
      { title: 'Recent', favorite: false, useCount: 2, lastUsed: NOW - 1_000, updatedAt: 1 },
    ];
    expect(notes.sort((left, right) => compareSmartWorkflowNotes(left, right, NOW)).map((note) => note.title)).toEqual([
      'Favorite', 'Frequent', 'Recent', 'Unused',
    ]);
  });

  it('finds never-used and oldest-used workflows first', () => {
    const notes = [
      { title: 'Recent', lastUsed: NOW - 1_000 },
      { title: 'Old', lastUsed: NOW - 30 * 86_400_000 },
      { title: 'Never', lastUsed: 0 },
    ];
    expect(notes.sort(compareStaleWorkflowNotes).map((note) => note.title)).toEqual(['Never', 'Old', 'Recent']);
  });
});
