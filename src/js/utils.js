export const DEFAULT_ACCOUNT = '默认账户';

export function generateId() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function normalizeAccountName(value) {
  return String(value || '').trim() || DEFAULT_ACCOUNT;
}

export function normalizeAlgorithm(value) {
  const compact = String(value || 'SHA-1').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (compact === 'SHA256') return 'SHA-256';
  if (compact === 'SHA512') return 'SHA-512';
  return 'SHA-1';
}

export function normalizeSecret(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

export function normalizeKey(raw = {}, index = 0) {
  const period = Number.parseInt(raw.period, 10);
  const digits = Number.parseInt(raw.digits, 10);
  return {
    id: String(raw.id || raw.uuid || generateId()),
    name: String(raw.name || raw.issuer || '未命名').trim() || '未命名',
    issuer: String(raw.issuer || '').trim(),
    account: String(raw.account || raw.label || '').trim(),
    note: String(raw.note || '').trim().slice(0, 500),
    secret: normalizeSecret(raw.secret),
    group: String(raw.group || '').trim(),
    period: Number.isFinite(period) && period >= 5 && period <= 300 ? period : 30,
    digits: digits === 8 ? 8 : 6,
    algorithm: normalizeAlgorithm(raw.algorithm || raw.algo),
    favorite: Boolean(raw.favorite),
    order: Number.isFinite(Number(raw.order)) ? Number(raw.order) : index,
    lastUsed: Number.isFinite(Number(raw.lastUsed)) ? Number(raw.lastUsed) : 0,
    useCount: Number.isFinite(Number(raw.useCount)) ? Math.max(0, Math.floor(Number(raw.useCount))) : 0,
    icon: String(raw.icon || '').trim().slice(0, 16),
  };
}

export function normalizeWorkflowNote(raw = {}) {
  const sourceLinks = Array.isArray(raw.linkedKeys)
    ? raw.linkedKeys
    : (Array.isArray(raw.keyIds) ? raw.keyIds : []);
  const seen = new Set();
  const linkedKeys = [];
  for (const source of sourceLinks) {
    const link = typeof source === 'string' ? { keyId: source } : (source || {});
    const keyId = String(link.keyId || link.id || '').trim();
    if (!keyId || seen.has(keyId)) continue;
    seen.add(keyId);
    linkedKeys.push({
      keyId,
      name: String(link.name || '').trim().slice(0, 100),
      issuer: String(link.issuer || '').trim().slice(0, 100),
      account: String(link.account || '').trim().slice(0, 160),
    });
    if (linkedKeys.length >= 50) break;
  }
  const createdAt = Number(raw.createdAt || Date.now());
  const updatedAt = Number(raw.updatedAt || createdAt);
  return {
    id: String(raw.id || generateId()),
    title: String(raw.title || '未命名场景').trim().slice(0, 100) || '未命名场景',
    group: String(raw.group || '').trim().slice(0, 100),
    content: String(raw.content || raw.steps || '').trim().slice(0, 5000),
    linkedKeys,
    favorite: Boolean(raw.favorite),
    lastUsed: Number.isFinite(Number(raw.lastUsed)) ? Math.max(0, Number(raw.lastUsed)) : 0,
    useCount: Number.isFinite(Number(raw.useCount)) ? Math.max(0, Math.floor(Number(raw.useCount))) : 0,
    createdAt: Number.isFinite(createdAt) ? createdAt : Date.now(),
    updatedAt: Number.isFinite(updatedAt) ? updatedAt : Date.now(),
  };
}

export function normalizeWorkflowProtection(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const salt = String(raw.salt || '').trim();
  const hash = String(raw.hash || '').trim().toLocaleLowerCase('en-US');
  const iterations = Number(raw.iterations);
  if (!salt || salt.length > 256 || !/^[a-f0-9]{64}$/.test(hash)) return null;
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) return null;
  return { salt, hash, iterations };
}

export function getSmartSortScore(key, now = Date.now()) {
  const useCount = Math.max(0, Number(key?.useCount || 0));
  const lastUsed = Math.max(0, Number(key?.lastUsed || 0));
  const ageDays = lastUsed > 0 ? Math.max(0, Number(now) - lastUsed) / 86_400_000 : Number.POSITIVE_INFINITY;
  const frequencyScore = Math.log2(useCount + 1) * 100;
  const recencyScore = Number.isFinite(ageDays) ? 40 * Math.exp(-ageDays / 7) : 0;
  return frequencyScore + recencyScore;
}

export function compareSmartKeys(left, right, now = Date.now()) {
  if (left.favorite !== right.favorite) return left.favorite ? -1 : 1;
  const scoreDifference = getSmartSortScore(right, now) - getSmartSortScore(left, now);
  if (Math.abs(scoreDifference) > 0.001) return scoreDifference;
  const recentDifference = Number(right.lastUsed || 0) - Number(left.lastUsed || 0);
  if (recentDifference !== 0) return recentDifference;
  const orderDifference = Number(left.order || 0) - Number(right.order || 0);
  return orderDifference || left.name.localeCompare(right.name, 'zh-CN');
}

export function compareStaleKeys(left, right) {
  const lastUsedDifference = Math.max(0, Number(left?.lastUsed || 0)) - Math.max(0, Number(right?.lastUsed || 0));
  if (lastUsedDifference !== 0) return lastUsedDifference;
  return String(left?.name || '').localeCompare(String(right?.name || ''), 'zh-CN');
}

export function compareSmartWorkflowNotes(left, right, now = Date.now()) {
  if (Boolean(left.favorite) !== Boolean(right.favorite)) return left.favorite ? -1 : 1;
  const scoreDifference = getSmartSortScore(right, now) - getSmartSortScore(left, now);
  if (Math.abs(scoreDifference) > 0.001) return scoreDifference;
  const recentDifference = Number(right.lastUsed || 0) - Number(left.lastUsed || 0);
  if (recentDifference !== 0) return recentDifference;
  const updatedDifference = Number(right.updatedAt || 0) - Number(left.updatedAt || 0);
  return updatedDifference || String(left.title || '').localeCompare(String(right.title || ''), 'zh-CN');
}

export function compareStaleWorkflowNotes(left, right) {
  const lastUsedDifference = Math.max(0, Number(left?.lastUsed || 0)) - Math.max(0, Number(right?.lastUsed || 0));
  if (lastUsedDifference !== 0) return lastUsedDifference;
  return String(left?.title || '').localeCompare(String(right?.title || ''), 'zh-CN');
}

export function matchesKeyFilter(key = {}, query = '') {
  const terms = String(query).trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const searchableText = [key.name, key.account, key.issuer, key.group, key.note]
    .filter(Boolean)
    .join(' ')
    .toLocaleLowerCase();
  return terms.every((term) => searchableText.includes(term));
}

export function matchesWorkflowNoteFilter(note = {}, query = '') {
  const terms = String(query).trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const linkedText = (Array.isArray(note.linkedKeys) ? note.linkedKeys : [])
    .flatMap((link) => [link?.name, link?.issuer, link?.account]);
  const searchableText = [note.title, note.group, note.content, ...linkedText]
    .filter(Boolean)
    .join(' ')
    .toLocaleLowerCase();
  return terms.every((term) => searchableText.includes(term));
}

export function workflowLinkSnapshot(key = {}) {
  return {
    keyId: String(key.id || ''),
    name: String(key.name || '').trim().slice(0, 100),
    issuer: String(key.issuer || '').trim().slice(0, 100),
    account: String(key.account || '').trim().slice(0, 160),
  };
}

export function syncWorkflowLinksForKey(notes = [], key = {}, selectedNoteIds = [], updatedAt = Date.now()) {
  const selected = new Set([...selectedNoteIds].map(String));
  const snapshot = workflowLinkSnapshot(key);
  if (!snapshot.keyId) return [...notes];
  return notes.map((note) => {
    const links = Array.isArray(note.linkedKeys) ? note.linkedKeys : [];
    const index = links.findIndex((link) => link.keyId === snapshot.keyId);
    const shouldLink = selected.has(String(note.id));
    if (!shouldLink && index < 0) return note;
    if (!shouldLink) return { ...note, linkedKeys: links.filter((link) => link.keyId !== snapshot.keyId), updatedAt };
    if (index < 0) return { ...note, linkedKeys: [...links, snapshot], updatedAt };
    const current = links[index];
    if (current.name === snapshot.name && current.issuer === snapshot.issuer && current.account === snapshot.account) return note;
    const nextLinks = [...links];
    nextLinks[index] = snapshot;
    return { ...note, linkedKeys: nextLinks, updatedAt };
  });
}

export function normalizeVaultData(raw) {
  if (Array.isArray(raw)) {
    return { version: 3, keys: raw.map(normalizeKey), deletedItems: [], workflowNotes: [], deletedWorkflowNotes: [], workflowProtection: null };
  }
  const source = raw && typeof raw === 'object' ? raw : {};
  const keyList = Array.isArray(source.keys) ? source.keys : [];
  const deleted = Array.isArray(source.deletedItems) ? source.deletedItems : [];
  const workflowNotes = Array.isArray(source.workflowNotes) ? source.workflowNotes : [];
  const deletedWorkflowNotes = Array.isArray(source.deletedWorkflowNotes) ? source.deletedWorkflowNotes : [];
  return {
    version: 3,
    keys: keyList.map(normalizeKey),
    deletedItems: deleted.map((item, index) => ({
      ...normalizeKey(item.key || item, index),
      deletedAt: Number(item.deletedAt || Date.now()),
    })),
    workflowNotes: workflowNotes.map(normalizeWorkflowNote),
    deletedWorkflowNotes: deletedWorkflowNotes.map((item) => ({
      ...normalizeWorkflowNote(item.note || item),
      deletedAt: Number(item.deletedAt || Date.now()),
    })),
    workflowProtection: normalizeWorkflowProtection(source.workflowProtection),
  };
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export function bytesToBase32(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

export function downloadText(filename, content, type = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function formatDateTime(timestamp) {
  return new Date(timestamp).toLocaleString('zh-CN');
}

export function uniqueName(baseName, existingNames) {
  const base = String(baseName || '未命名').trim() || '未命名';
  if (!existingNames.has(base.toLocaleLowerCase())) return base;
  let suffix = 2;
  while (existingNames.has(`${base} (${suffix})`.toLocaleLowerCase())) suffix += 1;
  return `${base} (${suffix})`;
}
