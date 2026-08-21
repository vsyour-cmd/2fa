import { DurableObject } from 'cloudflare:workers';

const VAULT_STORAGE_KEY = 'vault';
const HISTORY_INDEX_KEY = 'vault-history-index';
const HISTORY_KEY_PREFIX = 'vault-history:';
const HISTORY_LIMIT = 20;

function validRecord(record) {
  return record
    && typeof record.encryptedData === 'string'
    && typeof record.salt === 'string'
    && Number.isFinite(Number(record.updatedAt));
}

export class VaultCoordinator extends DurableObject {
  async #archiveCurrent(current) {
    if (!validRecord(current)) return;
    const existing = normalizeHistoryIndex(await this.ctx.storage.get(HISTORY_INDEX_KEY));
    const next = [
      { updatedAt: Number(current.updatedAt), version: Number(current.version || 1) },
      ...existing.filter((entry) => entry.updatedAt !== Number(current.updatedAt)),
    ];
    const kept = next.slice(0, HISTORY_LIMIT);
    await this.ctx.storage.put({
      [historyKey(current.updatedAt)]: current,
      [HISTORY_INDEX_KEY]: kept,
    });
    const removedKeys = next.slice(HISTORY_LIMIT).map((entry) => historyKey(entry.updatedAt));
    if (removedKeys.length) await this.ctx.storage.delete(removedKeys);
  }

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
    await this.#archiveCurrent(current);
    await this.ctx.storage.put(VAULT_STORAGE_KEY, stored);
    return { saved: true, currentUpdatedAt: updatedAt, record: stored };
  }

  async replace(record) {
    if (!validRecord(record)) throw new Error('Invalid vault record');
    await this.#archiveCurrent(await this.ctx.storage.get(VAULT_STORAGE_KEY));
    await this.ctx.storage.put(VAULT_STORAGE_KEY, record);
    return record;
  }

  async listHistory(limit = HISTORY_LIMIT) {
    const safeLimit = Math.max(1, Math.min(HISTORY_LIMIT, Number(limit) || HISTORY_LIMIT));
    return normalizeHistoryIndex(await this.ctx.storage.get(HISTORY_INDEX_KEY)).slice(0, safeLimit);
  }

  async restoreHistory(historyUpdatedAt, expectedUpdatedAt) {
    const current = await this.ctx.storage.get(VAULT_STORAGE_KEY);
    const currentUpdatedAt = Number(current?.updatedAt || 0);
    if (Number(expectedUpdatedAt) !== currentUpdatedAt) {
      return { restored: false, currentUpdatedAt, reason: 'conflict' };
    }
    const archived = await this.ctx.storage.get(historyKey(historyUpdatedAt));
    if (!validRecord(archived)) return { restored: false, currentUpdatedAt, reason: 'missing' };
    const updatedAt = Math.max(Date.now(), currentUpdatedAt + 1, Number(archived.updatedAt) + 1);
    const stored = { ...archived, updatedAt };
    await this.#archiveCurrent(current);
    await this.ctx.storage.put(VAULT_STORAGE_KEY, stored);
    return { restored: true, currentUpdatedAt: updatedAt, record: stored };
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
    await this.#archiveCurrent(current);
    await this.ctx.storage.delete(VAULT_STORAGE_KEY);
    return { removed: true, currentUpdatedAt, record: current || null };
  }
}

function historyKey(updatedAt) {
  return `${HISTORY_KEY_PREFIX}${Number(updatedAt)}`;
}

function normalizeHistoryIndex(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  return value
    .filter((entry) => Number.isSafeInteger(Number(entry?.updatedAt)) && Number(entry.updatedAt) > 0)
    .map((entry) => ({ updatedAt: Number(entry.updatedAt), version: Number(entry.version || 1) }))
    .filter((entry) => !seen.has(entry.updatedAt) && seen.add(entry.updatedAt))
    .sort((left, right) => right.updatedAt - left.updatedAt);
}
