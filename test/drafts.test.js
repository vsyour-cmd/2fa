import { describe, expect, it } from 'vitest';
import { EncryptedDraftStore } from '../src/js/drafts.js';

class MemoryStorage {
  constructor() { this.values = new Map(); }
  getItem(key) { return this.values.get(key) ?? null; }
  setItem(key, value) { this.values.set(key, value); }
  removeItem(key) { this.values.delete(key); }
}

async function aesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

describe('encrypted form drafts', () => {
  it('stores sensitive drafts only as ciphertext and restores them with the vault key', async () => {
    const storage = new MemoryStorage();
    const store = new EncryptedDraftStore(storage);
    const key = await aesKey();
    const payload = { name: 'GitHub', secret: 'PLAINTEXTSECRET', content: '# private workflow' };

    await store.save('vault-hash', 'token', payload, key);

    const stored = storage.getItem(store.key('vault-hash', 'token'));
    expect(stored).not.toContain('PLAINTEXTSECRET');
    expect(stored).not.toContain('private workflow');
    expect((await store.load('vault-hash', 'token', key)).payload).toEqual(payload);
  });

  it('scopes drafts by vault and type, supports removal, and skips stale writes', async () => {
    const storage = new MemoryStorage();
    const store = new EncryptedDraftStore(storage);
    const key = await aesKey();

    expect(await store.save('vault-a', 'workflow', { title: 'stale' }, key, () => false)).toBeNull();
    expect(await store.load('vault-a', 'workflow', key)).toBeNull();
    await store.save('vault-a', 'workflow', { title: 'draft' }, key);
    expect(await store.load('vault-b', 'workflow', key)).toBeNull();
    expect(await store.load('vault-a', 'token', key)).toBeNull();
    store.remove('vault-a', 'workflow');
    expect(await store.load('vault-a', 'workflow', key)).toBeNull();
  });
});
