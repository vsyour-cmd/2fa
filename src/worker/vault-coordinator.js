import { DurableObject } from 'cloudflare:workers';

const VAULT_STORAGE_KEY = 'vault';

function validRecord(record) {
  return record
    && typeof record.encryptedData === 'string'
    && typeof record.salt === 'string'
    && Number.isFinite(Number(record.updatedAt));
}

export class VaultCoordinator extends DurableObject {
  async read(legacyRecord = null) {
    let current = await this.ctx.storage.get(VAULT_STORAGE_KEY);
    if (!current && validRecord(legacyRecord)) {
      current = legacyRecord;
      await this.ctx.storage.put(VAULT_STORAGE_KEY, current);
    }
    return current || null;
  }

  async save(nextRecord, expectedUpdatedAt, legacyRecord = null) {
    let current = await this.ctx.storage.get(VAULT_STORAGE_KEY);
    if (!current && validRecord(legacyRecord)) {
      current = legacyRecord;
      await this.ctx.storage.put(VAULT_STORAGE_KEY, current);
    }
    const currentUpdatedAt = Number(current?.updatedAt || 0);
    if (Number(expectedUpdatedAt) !== currentUpdatedAt) {
      return { saved: false, currentUpdatedAt };
    }
    const updatedAt = Math.max(Date.now(), currentUpdatedAt + 1);
    const stored = {
      encryptedData: nextRecord.encryptedData,
      salt: nextRecord.salt,
      version: Number(nextRecord.version || 1),
      updatedAt,
    };
    await this.ctx.storage.put(VAULT_STORAGE_KEY, stored);
    return { saved: true, currentUpdatedAt: updatedAt, record: stored };
  }

  async replace(record) {
    if (!validRecord(record)) throw new Error('Invalid vault record');
    await this.ctx.storage.put(VAULT_STORAGE_KEY, record);
    return record;
  }

  async remove(expectedUpdatedAt, legacyRecord = null) {
    let current = await this.ctx.storage.get(VAULT_STORAGE_KEY);
    if (!current && validRecord(legacyRecord)) {
      current = legacyRecord;
      await this.ctx.storage.put(VAULT_STORAGE_KEY, current);
    }
    const currentUpdatedAt = Number(current?.updatedAt || 0);
    if (Number(expectedUpdatedAt) !== currentUpdatedAt) {
      return { removed: false, currentUpdatedAt };
    }
    await this.ctx.storage.delete(VAULT_STORAGE_KEY);
    return { removed: true, currentUpdatedAt, record: current || null };
  }
}
