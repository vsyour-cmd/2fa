import { describe, expect, it } from 'vitest';
import { syncWorkflowLinksForKey } from '../src/js/utils.js';

const key = { id: 'key-1', name: 'GitHub', issuer: 'GitHub', account: 'owner@example.com' };
const otherLink = { keyId: 'key-2', name: 'Cloudflare', issuer: 'Cloudflare', account: 'ops@example.com' };

function notes() {
  return [
    { id: 'note-1', title: '发布流程', linkedKeys: [otherLink], updatedAt: 1 },
    { id: 'note-2', title: '备份流程', linkedKeys: [{ keyId: 'key-1', name: '旧名称', issuer: '', account: '' }], updatedAt: 1 },
    { id: 'note-3', title: '无关流程', linkedKeys: [], updatedAt: 1 },
  ];
}

describe('linking workflow notes from a 2FA token', () => {
  it('adds and removes links while preserving other token links', () => {
    const original = notes();
    const result = syncWorkflowLinksForKey(original, key, new Set(['note-1', 'note-3']), 99);

    expect(result[0].linkedKeys).toEqual([otherLink, { keyId: 'key-1', name: 'GitHub', issuer: 'GitHub', account: 'owner@example.com' }]);
    expect(result[0].updatedAt).toBe(99);
    expect(result[1].linkedKeys).toEqual([]);
    expect(result[1].updatedAt).toBe(99);
    expect(result[2].linkedKeys).toHaveLength(1);
  });

  it('refreshes the stored token snapshot for an existing association', () => {
    const result = syncWorkflowLinksForKey(notes(), key, new Set(['note-2']), 99);

    expect(result[1].linkedKeys[0]).toEqual({ keyId: 'key-1', name: 'GitHub', issuer: 'GitHub', account: 'owner@example.com' });
    expect(result[1].updatedAt).toBe(99);
  });

  it('is idempotent and leaves unchanged notes by reference', () => {
    const original = syncWorkflowLinksForKey(notes(), key, new Set(['note-1']), 99);
    const result = syncWorkflowLinksForKey(original, key, new Set(['note-1']), 100);

    expect(result[0]).toBe(original[0]);
    expect(result[1]).toBe(original[1]);
    expect(result[2]).toBe(original[2]);
  });
});
