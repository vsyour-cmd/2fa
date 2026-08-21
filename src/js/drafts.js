import { decryptJson, encryptJson } from './crypto.js';

const DRAFT_PREFIX = '2fa_encrypted_form_draft_v1';

export class EncryptedDraftStore {
  constructor(storage = globalThis.localStorage) {
    this.storage = storage;
  }

  key(keyHash, type) {
    return `${DRAFT_PREFIX}:${String(keyHash)}:${String(type)}`;
  }

  async save(keyHash, type, payload, masterKey, shouldCommit = () => true) {
    const encryptedData = await encryptJson(payload, masterKey);
    if (!shouldCommit()) return null;
    const record = { version: 1, updatedAt: Date.now(), encryptedData };
    this.storage.setItem(this.key(keyHash, type), JSON.stringify(record));
    return record;
  }

  async load(keyHash, type, masterKey) {
    const raw = this.storage.getItem(this.key(keyHash, type));
    if (!raw) return null;
    try {
      const record = JSON.parse(raw);
      if (record?.version !== 1 || typeof record.encryptedData !== 'string') return null;
      const payload = await decryptJson(record.encryptedData, masterKey);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
      return { payload, updatedAt: Number(record.updatedAt || 0) };
    } catch {
      return null;
    }
  }

  remove(keyHash, type) {
    this.storage.removeItem(this.key(keyHash, type));
  }
}
