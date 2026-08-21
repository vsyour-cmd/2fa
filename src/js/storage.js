import { normalizeAccountName } from './utils.js';

const SESSION_KEY = '2fa_sessions_v3';
const ACTIVE_ACCOUNT_KEY = '2fa_active_account_v3';
const KNOWN_ACCOUNTS_KEY = '2fa_known_accounts_v3';
const SETTINGS_KEY = '2fa_settings_v3';
const QUICK_UNLOCK_KEY = '2fa_quick_unlock_v1';
const SESSION_KEY_DB = '2fa-session-keys-v1';
const SESSION_KEY_STORE = 'session-keys';
const SESSION_KEY_TTL_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_SETTINGS = Object.freeze({
  theme: 'system',
  sortMode: 'smart',
  workflowSortMode: 'smart',
  columnsPerRow: 'auto',
  workflowColumnsPerRow: 'auto',
  autoLockMinutes: 15,
  lockOnHidden: false,
  clipboardAutoClear: true,
  vibrateOnCopy: true,
  trashRetentionDays: 30,
  settingsVersion: 3,
});

export class ApiError extends Error {
  constructor(message, status = 0, code = '') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function parseApiResponse(response) {
  let body;
  try {
    body = await response.json();
  } catch {
    if (response.ok) {
      throw new ApiError('云端返回了无效响应，可能需要重新登录 Cloudflare Access', 0, 'INVALID_RESPONSE');
    }
    body = {};
  }
  if (!response.ok) {
    const message = response.status === 429
      ? '请求过于频繁，请稍后再试'
      : (body.error || `API 错误 (${response.status})`);
    throw new ApiError(message, response.status, body.code || '');
  }
  return body;
}

export async function apiGet(keyHash, accountName = '') {
  const params = new URLSearchParams({ key: keyHash });
  const headers = { Accept: 'application/json' };
  if (accountName) headers['X-Vault-Account'] = encodeUtf8Base64Url(accountName);
  const response = await fetch(`/api/data?${params.toString()}`, {
    headers,
  });
  return parseApiResponse(response);
}

export async function apiGetAccessIdentity() {
  const response = await fetch('/api/access/me', {
    headers: { Accept: 'application/json' },
  });
  const result = await parseApiResponse(response);
  if (!result.authenticated || typeof result.email !== 'string' || !result.email.trim()) return null;
  return { email: result.email.trim() };
}

function encodeUtf8Base64Url(value) {
  const bytes = new TextEncoder().encode(String(value));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function apiSave(keyHash, encryptedData, salt, version = 3, accountName = '', expectedUpdatedAt) {
  const response = await fetch('/api/data', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ key: keyHash, data: encryptedData, salt, version, accountName, expectedUpdatedAt }),
  });
  const result = await parseApiResponse(response);
  const updatedAt = Number(result?.updatedAt);
  if (result?.success !== true || !Number.isFinite(updatedAt) || updatedAt <= 0) {
    throw new ApiError('云端没有确认保存成功，请重试', 0, 'INVALID_SAVE_ACK');
  }
  return result;
}

export async function apiDelete(keyHash, expectedUpdatedAt) {
  if (!Number.isSafeInteger(expectedUpdatedAt) || expectedUpdatedAt < 0) {
    throw new ApiError('删除前必须确认云端版本', 0, 'VERSION_REQUIRED');
  }
  const params = new URLSearchParams({ key: keyHash, expectedUpdatedAt: String(expectedUpdatedAt) });
  const response = await fetch(`/api/data?${params.toString()}`, {
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
      try { await this.init(); } catch { return false; }
    }
    if (!this.db) return false;
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
    return true;
  }

  async get(keyHash) {
    if (!this.db) {
      try { await this.init(); } catch { return null; }
    }
    if (!this.db) return null;
    const value = await this.#request('readonly', (store) => store.get(keyHash));
    if (!value) return null;
    const maxAge = this.cacheExpiryDays * 24 * 60 * 60 * 1000;
    // A locally modified record may be the only copy of the user's latest
    // vault. Cache expiry is only safe for snapshots already confirmed by the
    // cloud; pending local changes must survive until they are synced.
    if (!value.locallyModified && Date.now() - value.cachedAt > maxAge) {
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

function openSessionKeyDatabase() {
  if (!('indexedDB' in globalThis)) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(SESSION_KEY_DB, 1);
    request.onerror = () => reject(request.error || new Error('会话密钥数据库不可用'));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const database = event.target.result;
      if (!database.objectStoreNames.contains(SESSION_KEY_STORE)) {
        database.createObjectStore(SESSION_KEY_STORE, { keyPath: 'id' });
      }
    };
  });
}

async function sessionKeyRequest(mode, createRequest) {
  const database = await openSessionKeyDatabase();
  if (!database) throw new Error('当前浏览器不支持安全会话恢复');
  return new Promise((resolve, reject) => {
    let result;
    const transaction = database.transaction([SESSION_KEY_STORE], mode);
    transaction.oncomplete = () => {
      database.close?.();
      resolve(result);
    };
    transaction.onerror = () => {
      database.close?.();
      reject(transaction.error || new Error('会话密钥操作失败'));
    };
    transaction.onabort = transaction.onerror;
    const request = createRequest(transaction.objectStore(SESSION_KEY_STORE));
    request.onsuccess = () => { result = request.result; };
    request.onerror = () => {
      try { transaction.abort(); } catch { /* transaction may already be aborting */ }
    };
  });
}

function validStoredAesKey(key) {
  return Boolean(key
    && key.type === 'secret'
    && key.extractable === false
    && key.algorithm?.name === 'AES-GCM'
    && key.algorithm?.length === 256
    && Array.isArray(key.usages)
    && key.usages.includes('encrypt')
    && key.usages.includes('decrypt'));
}

async function deleteSessionKey(keyRef) {
  if (!keyRef) return;
  try {
    await sessionKeyRequest('readwrite', (store) => store.delete(keyRef));
  } catch (error) {
    console.warn('Unable to remove secure session key:', error);
  }
}

async function purgeExpiredSessionKeys() {
  const database = await openSessionKeyDatabase();
  if (!database) return;
  await new Promise((resolve, reject) => {
    const transaction = database.transaction([SESSION_KEY_STORE], 'readwrite');
    const store = transaction.objectStore(SESSION_KEY_STORE);
    const request = store.getAll();
    request.onsuccess = () => {
      for (const record of request.result || []) {
        if (Number(record?.expiresAt || 0) <= Date.now()) store.delete(record.id);
      }
    };
    request.onerror = () => {
      try { transaction.abort(); } catch { /* transaction may already be aborting */ }
    };
    transaction.oncomplete = () => {
      database.close?.();
      resolve();
    };
    transaction.onerror = () => {
      database.close?.();
      reject(transaction.error || request.error || new Error('过期会话密钥清理失败'));
    };
    transaction.onabort = transaction.onerror;
  });
}

export function getSessions() {
  const sessions = parseJsonStorage(sessionStorage, SESSION_KEY, {});
  if (!sessions || typeof sessions !== 'object') return {};
  let changed = false;
  for (const [id, session] of Object.entries(sessions)) {
    if (!session || typeof session !== 'object' || (session.keyRef && Number(session.expiresAt || 0) <= Date.now())) {
      delete sessions[id];
      changed = true;
    }
  }
  if (changed) sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessions));
  return sessions;
}

export async function saveSession(session, masterKey) {
  if (!validStoredAesKey(masterKey)) throw new Error('保险库密钥不符合安全会话要求');
  try { await purgeExpiredSessionKeys(); } catch (error) { console.warn('Unable to purge expired session keys:', error); }
  const sessions = getSessions();
  const id = sessionId(session.accountName);
  const previousKeyRef = sessions[id]?.keyRef;
  const keyRef = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_KEY_TTL_MS;
  await sessionKeyRequest('readwrite', (store) => store.put({
    id: keyRef,
    accountId: id,
    key: masterKey,
    expiresAt,
  }));
  try {
    const { keyStr: _legacyKey, ...safeSession } = session;
    sessions[id] = {
      ...safeSession,
      accountName: normalizeAccountName(session.accountName),
      keyRef,
      expiresAt,
    };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessions));
    setActiveAccount(session.accountName);
    rememberAccount(session.accountName);
  } catch (error) {
    await deleteSessionKey(keyRef);
    throw error;
  }
  if (previousKeyRef && previousKeyRef !== keyRef) await deleteSessionKey(previousKeyRef);
}

export function getSession(accountName) {
  return getSessions()[sessionId(accountName)] || null;
}

export async function loadSessionKey(session) {
  if (!session?.keyRef || Number(session.expiresAt || 0) <= Date.now()) return null;
  const record = await sessionKeyRequest('readonly', (store) => store.get(session.keyRef));
  if (!record
    || record.accountId !== sessionId(session.accountName)
    || Number(record.expiresAt || 0) <= Date.now()
    || !validStoredAesKey(record.key)) {
    await deleteSessionKey(session.keyRef);
    return null;
  }
  return record.key;
}

export async function removeSession(accountName) {
  const sessions = getSessions();
  const id = sessionId(accountName);
  const keyRef = sessions[id]?.keyRef;
  delete sessions[id];
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessions));
  await deleteSessionKey(keyRef);
}

export async function clearAllSessions() {
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(ACTIVE_ACCOUNT_KEY);
  try {
    await sessionKeyRequest('readwrite', (store) => store.clear());
  } catch (error) {
    console.warn('Unable to clear secure session keys:', error);
  }
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
  if (!['smart', 'name', 'recent', 'stale'].includes(migrated.workflowSortMode)) migrated.workflowSortMode = DEFAULT_SETTINGS.workflowSortMode;
  if (!['auto', '1', '2', '3', '4'].includes(String(migrated.columnsPerRow || 'auto'))) migrated.columnsPerRow = 'auto';
  if (!['auto', '1', '2', '3', '4'].includes(String(migrated.workflowColumnsPerRow || 'auto'))) migrated.workflowColumnsPerRow = 'auto';
  return {
    ...DEFAULT_SETTINGS,
    ...migrated,
    columnsPerRow: String(migrated.columnsPerRow || 'auto'),
    workflowColumnsPerRow: String(migrated.workflowColumnsPerRow || 'auto'),
    settingsVersion: 3,
  };
}

export function saveSettings(settings) {
  const safe = {
    theme: ['system', 'light', 'dark'].includes(settings.theme) ? settings.theme : DEFAULT_SETTINGS.theme,
    sortMode: ['smart', 'custom', 'name', 'recent', 'stale'].includes(settings.sortMode) ? settings.sortMode : DEFAULT_SETTINGS.sortMode,
    workflowSortMode: ['smart', 'name', 'recent', 'stale'].includes(settings.workflowSortMode) ? settings.workflowSortMode : DEFAULT_SETTINGS.workflowSortMode,
    columnsPerRow: ['auto', '1', '2', '3', '4'].includes(String(settings.columnsPerRow)) ? String(settings.columnsPerRow) : DEFAULT_SETTINGS.columnsPerRow,
    workflowColumnsPerRow: ['auto', '1', '2', '3', '4'].includes(String(settings.workflowColumnsPerRow)) ? String(settings.workflowColumnsPerRow) : DEFAULT_SETTINGS.workflowColumnsPerRow,
    autoLockMinutes: Math.max(0, Math.min(240, Number(settings.autoLockMinutes) || 0)),
    lockOnHidden: Boolean(settings.lockOnHidden),
    clipboardAutoClear: Boolean(settings.clipboardAutoClear),
    vibrateOnCopy: settings.vibrateOnCopy !== false,
    trashRetentionDays: Math.max(1, Math.min(365, Number(settings.trashRetentionDays) || 30)),
    settingsVersion: 3,
  };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(safe));
  return safe;
}

function quickUnlockId(accountName) {
  return normalizeAccountName(accountName).normalize('NFKC').toLocaleLowerCase('en-US');
}

export function getQuickUnlockConfig(accountName) {
  const configs = parseJsonStorage(localStorage, QUICK_UNLOCK_KEY, {});
  const config = configs && typeof configs === 'object' ? configs[quickUnlockId(accountName)] : null;
  if (!config || typeof config.salt !== 'string' || typeof config.hash !== 'string') return null;
  const iterations = Number(config.iterations);
  return { salt: config.salt, hash: config.hash, iterations: Number.isInteger(iterations) && iterations >= 100_000 && iterations <= 1_000_000 ? iterations : 200_000 };
}

export function saveQuickUnlockConfig(accountName, config) {
  const configs = parseJsonStorage(localStorage, QUICK_UNLOCK_KEY, {});
  const safeConfigs = configs && typeof configs === 'object' && !Array.isArray(configs) ? configs : {};
  safeConfigs[quickUnlockId(accountName)] = { salt: String(config.salt), hash: String(config.hash), iterations: Number(config.iterations || 200_000) };
  localStorage.setItem(QUICK_UNLOCK_KEY, JSON.stringify(safeConfigs));
}

export function removeQuickUnlockConfig(accountName) {
  const configs = parseJsonStorage(localStorage, QUICK_UNLOCK_KEY, {});
  if (!configs || typeof configs !== 'object' || Array.isArray(configs)) return;
  delete configs[quickUnlockId(accountName)];
  localStorage.setItem(QUICK_UNLOCK_KEY, JSON.stringify(configs));
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
