import { normalizeAccountName } from './utils.js';

const SESSION_KEY = '2fa_sessions_v3';
const ACTIVE_ACCOUNT_KEY = '2fa_active_account_v3';
const KNOWN_ACCOUNTS_KEY = '2fa_known_accounts_v3';
const SETTINGS_KEY = '2fa_settings_v3';

export const DEFAULT_SETTINGS = Object.freeze({
  theme: 'system',
  sortMode: 'smart',
  autoLockMinutes: 15,
  lockOnHidden: false,
  clipboardAutoClear: true,
  trashRetentionDays: 30,
  settingsVersion: 2,
});

export class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function parseApiResponse(response) {
  let body = {};
  try {
    body = await response.json();
  } catch {
    body = {};
  }
  if (!response.ok) {
    const message = response.status === 429
      ? '请求过于频繁，请稍后再试'
      : (body.error || `API 错误 (${response.status})`);
    throw new ApiError(message, response.status);
  }
  return body;
}

export async function apiGet(keyHash) {
  const response = await fetch(`/api/data?key=${encodeURIComponent(keyHash)}`, {
    headers: { Accept: 'application/json' },
  });
  return parseApiResponse(response);
}

export async function apiSave(keyHash, encryptedData, salt, version = 3) {
  const response = await fetch('/api/data', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ key: keyHash, data: encryptedData, salt, version }),
  });
  return parseApiResponse(response);
}

export async function apiDelete(keyHash) {
  const response = await fetch(`/api/data?key=${encodeURIComponent(keyHash)}`, {
    method: 'DELETE',
    headers: { Accept: 'application/json' },
  });
  return parseApiResponse(response);
}

export class OfflineManager {
  constructor() {
    this.db = null;
    this.isOnline = navigator.onLine;
    this.dbName = '2fa-offline-db';
    this.storeName = 'encrypted-data';
    this.cacheExpiryDays = 7;
  }

  async init() {
    if (!('indexedDB' in window)) return;
    this.db = await new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = (event) => {
        const database = event.target.result;
        if (!database.objectStoreNames.contains(this.storeName)) {
          database.createObjectStore(this.storeName, { keyPath: 'keyHash' });
        }
      };
    });
  }

  async save(keyHash, encryptedData, salt, version, cloudUpdatedAt = null) {
    if (!this.db) {
      try { await this.init(); } catch { return; }
    }
    if (!this.db) return;
    const now = Date.now();
    const previous = await this.#request('readonly', (store) => store.get(keyHash));
    const isCloudSnapshot = cloudUpdatedAt !== null;
    const baseCloudUpdatedAt = isCloudSnapshot
      ? Number(cloudUpdatedAt)
      : Number(previous?.baseCloudUpdatedAt || (previous && !previous.locallyModified ? previous.updatedAt : 0) || 0);
    const value = {
      keyHash,
      encryptedData,
      salt,
      version,
      updatedAt: isCloudSnapshot ? Number(cloudUpdatedAt) : now,
      baseCloudUpdatedAt,
      cachedAt: now,
      locallyModified: !isCloudSnapshot,
    };
    await this.#request('readwrite', (store) => store.put(value));
  }

  async get(keyHash) {
    if (!this.db) {
      try { await this.init(); } catch { return null; }
    }
    if (!this.db) return null;
    const value = await this.#request('readonly', (store) => store.get(keyHash));
    if (!value) return null;
    const maxAge = this.cacheExpiryDays * 24 * 60 * 60 * 1000;
    if (Date.now() - value.cachedAt > maxAge) {
      await this.delete(keyHash);
      return null;
    }
    return value;
  }

  async delete(keyHash) {
    if (!this.db) return;
    await this.#request('readwrite', (store) => store.delete(keyHash));
  }

  detectConflict(localData, cloudUpdatedAt) {
    if (!localData?.locallyModified) return false;
    const baseCloudUpdatedAt = Number(localData.baseCloudUpdatedAt || 0);
    if (!baseCloudUpdatedAt) return true;
    return baseCloudUpdatedAt !== Number(cloudUpdatedAt || 0);
  }

  setupNetworkListeners(onOnline, onOffline) {
    window.addEventListener('online', () => {
      this.isOnline = true;
      onOnline?.();
    });
    window.addEventListener('offline', () => {
      this.isOnline = false;
      onOffline?.();
    });
  }

  #request(mode, createRequest) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], mode);
      const request = createRequest(transaction.objectStore(this.storeName));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
}

function parseJsonStorage(storage, key, fallback) {
  try {
    const value = storage.getItem(key);
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function sessionId(accountName) {
  return normalizeAccountName(accountName).normalize('NFKC').toLocaleLowerCase('en-US');
}

export function getSessions() {
  const sessions = parseJsonStorage(sessionStorage, SESSION_KEY, {});
  return sessions && typeof sessions === 'object' ? sessions : {};
}

export function saveSession(session) {
  const sessions = getSessions();
  sessions[sessionId(session.accountName)] = { ...session, accountName: normalizeAccountName(session.accountName) };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessions));
  setActiveAccount(session.accountName);
  rememberAccount(session.accountName);
}

export function getSession(accountName) {
  return getSessions()[sessionId(accountName)] || null;
}

export function removeSession(accountName) {
  const sessions = getSessions();
  delete sessions[sessionId(accountName)];
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessions));
}

export function clearAllSessions() {
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(ACTIVE_ACCOUNT_KEY);
}

export function setActiveAccount(accountName) {
  sessionStorage.setItem(ACTIVE_ACCOUNT_KEY, normalizeAccountName(accountName));
}

export function getActiveAccount() {
  return sessionStorage.getItem(ACTIVE_ACCOUNT_KEY) || '';
}

export function getKnownAccounts() {
  const accounts = parseJsonStorage(localStorage, KNOWN_ACCOUNTS_KEY, []);
  return Array.isArray(accounts) ? accounts.map(normalizeAccountName) : [];
}

export function rememberAccount(accountName) {
  const normalized = normalizeAccountName(accountName);
  const accounts = getKnownAccounts();
  if (!accounts.some((item) => item.toLocaleLowerCase() === normalized.toLocaleLowerCase())) {
    accounts.push(normalized);
    localStorage.setItem(KNOWN_ACCOUNTS_KEY, JSON.stringify(accounts));
  }
}

export function loadSettings() {
  const saved = parseJsonStorage(localStorage, SETTINGS_KEY, {});
  if (!saved || typeof saved !== 'object') return { ...DEFAULT_SETTINGS };
  const migrated = { ...saved };
  if (Number(migrated.settingsVersion || 0) < 2 && migrated.sortMode === 'custom') migrated.sortMode = 'smart';
  return { ...DEFAULT_SETTINGS, ...migrated, settingsVersion: 2 };
}

export function saveSettings(settings) {
  const safe = {
    theme: ['system', 'light', 'dark'].includes(settings.theme) ? settings.theme : DEFAULT_SETTINGS.theme,
    sortMode: ['smart', 'custom', 'name', 'recent'].includes(settings.sortMode) ? settings.sortMode : DEFAULT_SETTINGS.sortMode,
    autoLockMinutes: Math.max(0, Math.min(240, Number(settings.autoLockMinutes) || 0)),
    lockOnHidden: Boolean(settings.lockOnHidden),
    clipboardAutoClear: Boolean(settings.clipboardAutoClear),
    trashRetentionDays: Math.max(1, Math.min(365, Number(settings.trashRetentionDays) || 30)),
    settingsVersion: 2,
  };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(safe));
  return safe;
}

export function parseStoredCloudRecord(result) {
  if (!result?.exists) return { exists: false };
  let stored;
  try {
    stored = typeof result.data === 'string' ? JSON.parse(result.data) : result.data;
  } catch {
    throw new Error('服务器返回了无效数据');
  }
  if (!stored || typeof stored.encryptedData !== 'string' || typeof stored.salt !== 'string') {
    throw new Error('服务器数据不完整');
  }
  return {
    exists: true,
    encryptedData: stored.encryptedData,
    salt: stored.salt,
    version: Number(stored.version || 1),
    updatedAt: Number(stored.updatedAt || result.updatedAt || Date.now()),
  };
}
