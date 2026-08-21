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

  async prepareMigration(sourceHash, targetHash, sourceKey, targetKey, types = ['token', 'workflow']) {
    const previousTargets = new Map();
    const copiedTypes = [];
    try {
      for (const type of types) {
        const sourceRaw = this.storage.getItem(this.key(sourceHash, type));
        if (!sourceRaw) continue;
        const restored = await this.load(sourceHash, type, sourceKey);
        if (!restored) throw new Error(`Unable to decrypt ${type} draft`);
        previousTargets.set(type, this.storage.getItem(this.key(targetHash, type)));
        await this.save(targetHash, type, restored.payload, targetKey);
        const verified = await this.load(targetHash, type, targetKey);
        if (!verified) throw new Error(`Unable to verify ${type} draft`);
        copiedTypes.push(type);
      }
    } catch (error) {
      for (const [type, previous] of previousTargets) {
        if (previous === null) this.remove(targetHash, type);
        else this.storage.setItem(this.key(targetHash, type), previous);
      }
      throw error;
    }
    return {
      copiedTypes: [...copiedTypes],
      commit: () => {
        for (const type of copiedTypes) this.remove(sourceHash, type);
      },
      rollback: () => {
        for (const type of copiedTypes) {
          const previous = previousTargets.get(type);
          if (previous === null) this.remove(targetHash, type);
          else this.storage.setItem(this.key(targetHash, type), previous);
        }
      },
    };
  }
}
