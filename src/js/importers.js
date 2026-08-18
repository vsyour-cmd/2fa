import { scrypt } from 'scrypt-js';
import { decryptBackup, decryptAesGcmBytes, base64ToBytes, hexToBytes } from './crypto.js';
import { base32Decode, parseOtpauthUri } from './totp.js';
import {
  bytesToBase32,
  generateId,
  normalizeAlgorithm,
  normalizeKey,
  normalizeWorkflowNote,
  uniqueName,
} from './utils.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function importError(message, code = 'INVALID_IMPORT') {
  const error = new Error(message);
  error.code = code;
  return error;
}

function decodeFlexibleBase64(value) {
  let normalized = decodeURIComponent(String(value || '')).replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4)) % 4);
  return base64ToBytes(normalized);
}

function readVarint(bytes, start) {
  let value = 0;
  let shift = 0;
  let index = start;
  while (index < bytes.length && shift <= 63) {
    const byte = bytes[index];
    index += 1;
    value += (byte & 0x7f) * (2 ** shift);
    if ((byte & 0x80) === 0) return [value, index];
    shift += 7;
  }
  throw importError('Google Authenticator 迁移数据损坏');
}

function readLengthDelimited(bytes, start) {
  const [length, contentStart] = readVarint(bytes, start);
  const end = contentStart + length;
  if (end > bytes.length) throw importError('Google Authenticator 迁移数据不完整');
  return [bytes.slice(contentStart, end), end];
}

function skipProtobufField(bytes, start, wireType) {
  if (wireType === 0) return readVarint(bytes, start)[1];
  if (wireType === 1) return start + 8;
  if (wireType === 2) return readLengthDelimited(bytes, start)[1];
  if (wireType === 5) return start + 4;
  throw importError('Google Authenticator 包含不支持的字段');
}

function parseGoogleOtpParameters(bytes) {
  const result = { secret: null, name: '', issuer: '', algorithm: 1, digits: 1, type: 2 };
  let index = 0;
  while (index < bytes.length) {
    const [tag, next] = readVarint(bytes, index);
    index = next;
    const field = Math.floor(tag / 8);
    const wireType = tag & 7;
    if ([1, 2, 3].includes(field) && wireType === 2) {
      const [value, end] = readLengthDelimited(bytes, index);
      index = end;
      if (field === 1) result.secret = value;
      if (field === 2) result.name = decoder.decode(value);
      if (field === 3) result.issuer = decoder.decode(value);
    } else if ([4, 5, 6, 7].includes(field) && wireType === 0) {
      const [value, end] = readVarint(bytes, index);
      index = end;
      if (field === 4) result.algorithm = value;
      if (field === 5) result.digits = value;
      if (field === 6) result.type = value;
    } else {
      index = skipProtobufField(bytes, index, wireType);
    }
  }
  return result;
}

export function parseGoogleMigrationUri(uri) {
  if (!String(uri || '').startsWith('otpauth-migration://')) return [];
  const url = new URL(uri);
  const encoded = url.searchParams.get('data');
  if (!encoded) throw importError('Google Authenticator 链接缺少 data 参数');
  const payload = decodeFlexibleBase64(encoded);
  const entries = [];
  let index = 0;
  while (index < payload.length) {
    const [tag, next] = readVarint(payload, index);
    index = next;
    const field = Math.floor(tag / 8);
    const wireType = tag & 7;
    if (field === 1 && wireType === 2) {
      const [value, end] = readLengthDelimited(payload, index);
      index = end;
      const item = parseGoogleOtpParameters(value);
      if (!item.secret || item.type === 1) continue;
      const issuer = item.issuer.trim();
      const account = item.name.trim();
      entries.push(normalizeKey({
        name: issuer || account || '未命名',
        issuer,
        account,
        secret: bytesToBase32(item.secret),
        algorithm: { 2: 'SHA-256', 3: 'SHA-512' }[item.algorithm] || 'SHA-1',
        digits: item.digits === 2 ? 8 : 6,
        period: 30,
      }, entries.length));
    } else {
      index = skipProtobufField(payload, index, wireType);
    }
  }
  if (entries.length === 0) throw importError('迁移包中没有可导入的 TOTP 条目');
  return entries;
}

function parseOtpauthLines(text) {
  const lines = String(text || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const parsed = [];
  for (const line of lines) {
    if (line.startsWith('otpauth-migration://')) parsed.push(...parseGoogleMigrationUri(line));
    else {
      const item = parseOtpauthUri(line);
      if (item) parsed.push(normalizeKey(item, parsed.length));
    }
  }
  return parsed;
}

function mapAegisDatabase(database) {
  const groups = new Map((database.groups || []).map((group) => [group.uuid, group.name]));
  return (database.entries || [])
    .filter((entry) => String(entry.type || 'totp').toLowerCase() === 'totp' && entry.info?.secret)
    .map((entry, index) => normalizeKey({
      id: entry.uuid,
      name: entry.issuer || entry.name,
      issuer: entry.issuer,
      account: entry.name,
      secret: entry.info.secret,
      algorithm: entry.info.algo,
      digits: entry.info.digits,
      period: entry.info.period,
      favorite: entry.favorite,
      group: groups.get(entry.groups?.[0]) || '',
    }, index));
}

async function decryptAegisVault(payload, password) {
  if (!password) throw importError('请输入 Aegis 导出密码', 'PASSWORD_REQUIRED');
  const slot = payload.header?.slots?.find((item) => Number(item.type) === 1);
  if (!slot) throw importError('此 Aegis 备份不包含可用的密码槽');
  try {
    const wrappingKey = new Uint8Array(await scrypt(
      encoder.encode(password),
      hexToBytes(slot.salt),
      Number(slot.n),
      Number(slot.r),
      Number(slot.p),
      32,
    ));
    const masterKey = await decryptAesGcmBytes(
      hexToBytes(slot.key),
      wrappingKey,
      hexToBytes(slot.key_params.nonce),
      hexToBytes(slot.key_params.tag),
    );
    const databaseBytes = await decryptAesGcmBytes(
      base64ToBytes(payload.db),
      masterKey,
      hexToBytes(payload.header.params.nonce),
      hexToBytes(payload.header.params.tag),
    );
    return JSON.parse(decoder.decode(databaseBytes));
  } catch {
    throw importError('Aegis 备份密码错误或文件已损坏', 'BAD_PASSWORD');
  }
}

function parse2Fas(payload) {
  return (payload.services || []).map((service, index) => {
    const linked = parseOtpauthUri(service.otp?.link || '');
    return normalizeKey({
      id: service.id,
      name: service.name || service.otp?.issuer || service.otp?.label,
      issuer: service.otp?.issuer,
      account: service.otp?.account || service.otp?.label,
      secret: service.secret || linked?.secret,
      algorithm: linked?.algorithm,
      digits: linked?.digits,
      period: linked?.period,
      favorite: service.isFavorite,
      order: service.order?.position,
      icon: service.icon?.label?.text,
    }, index);
  }).filter((item) => item.secret);
}

function parseAndOtp(payload) {
  const list = Array.isArray(payload) ? payload : (payload.entries || payload.accounts || payload.tokens || []);
  return list.map((entry, index) => normalizeKey({
    id: entry.id,
    name: entry.issuer || entry.label || entry.name,
    issuer: entry.issuer,
    account: entry.label || entry.account,
    secret: entry.secret,
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    group: entry.tags?.[0] || entry.group,
  }, index)).filter((item) => item.secret);
}

export async function parseImportContent(content, password = '') {
  const text = String(content || '').trim();
  if (!text) throw importError('导入内容为空');
  if (text.startsWith('otpauth://') || text.startsWith('otpauth-migration://')) {
    return { source: 'OTPAuth', items: parseOtpauthLines(text) };
  }

  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    const items = parseOtpauthLines(text);
    if (items.length > 0) return { source: '文本', items };
    throw importError('无法识别导入格式');
  }

  if (payload?.format === '2fa-encrypted-backup') {
    if (!password) throw importError('请输入加密备份密码', 'PASSWORD_REQUIRED');
    try {
      payload = await decryptBackup(payload, password);
    } catch {
      throw importError('备份密码错误或文件已损坏', 'BAD_PASSWORD');
    }
  }

  if (payload?.header && Object.hasOwn(payload, 'db')) {
    const database = payload.header.slots == null ? payload.db : await decryptAegisVault(payload, password);
    return { source: 'Aegis', items: mapAegisDatabase(database) };
  }
  if (Array.isArray(payload?.services)) return { source: '2FAS', items: parse2Fas(payload) };
  if (Array.isArray(payload?.keys)) {
    return {
      source: '2FA Authenticator',
      items: payload.keys.map(normalizeKey),
      workflowNotes: Array.isArray(payload.workflowNotes) ? payload.workflowNotes.map(normalizeWorkflowNote) : [],
    };
  }
  if (Array.isArray(payload?.entries) && payload.entries.some((item) => item?.info?.secret)) {
    return { source: 'Aegis', items: mapAegisDatabase(payload) };
  }
  if (Array.isArray(payload) || payload?.entries || payload?.accounts || payload?.tokens) {
    return { source: 'andOTP', items: parseAndOtp(payload) };
  }
  throw importError('不支持的备份格式');
}

export async function validateImportedItems(items, generateTOTP) {
  const valid = [];
  const invalid = [];
  for (const [index, item] of items.entries()) {
    const normalized = normalizeKey(item, index);
    try {
      base32Decode(normalized.secret);
      await generateTOTP(normalized.secret, Date.now(), normalized);
      valid.push(normalized);
    } catch {
      invalid.push({ item: normalized, reason: '密钥格式无效' });
    }
  }
  return { valid, invalid, skipped: invalid.length };
}

function importName(value) {
  return String(value || '').toLocaleLowerCase();
}

export function createImportPlan(valid, existingKeys = [], strategy = 'skip', invalid = []) {
  if (!['skip', 'overwrite', 'all'].includes(strategy)) throw importError('不支持的同名处理方式');

  const occupiedNames = new Set(existingKeys.map((key) => importName(key.name)));
  const targetsByName = new Map(existingKeys.map((key) => [importName(key.name), {
    kind: 'existing',
    id: key.id,
    name: key.name,
  }]));
  const items = [];

  for (const [index, rawCandidate] of valid.entries()) {
    const original = normalizeKey(rawCandidate, index);
    const nameKey = importName(original.name);
    const target = targetsByName.get(nameKey);

    if (target && strategy === 'skip') {
      items.push({ action: 'skip', candidate: original, target });
      continue;
    }
    if (target && strategy === 'overwrite') {
      items.push({ action: 'overwrite', candidate: original, target });
      continue;
    }

    const finalName = strategy === 'all' ? uniqueName(original.name, occupiedNames) : original.name;
    const resultRef = `import-${index}`;
    const candidate = { ...original, name: finalName };
    items.push({
      action: 'add',
      candidate,
      originalName: finalName === original.name ? '' : original.name,
      resultRef,
    });
    occupiedNames.add(importName(finalName));
    if (strategy !== 'all') {
      targetsByName.set(importName(finalName), { kind: 'planned', ref: resultRef, name: finalName });
    }
  }

  for (const entry of invalid) {
    items.push({
      action: 'invalid',
      candidate: normalizeKey(entry?.item || entry),
      reason: entry?.reason || '密钥格式无效',
    });
  }

  const stats = {
    add: items.filter((item) => item.action === 'add').length,
    overwrite: items.filter((item) => item.action === 'overwrite').length,
    skip: items.filter((item) => item.action === 'skip').length,
    invalid: items.filter((item) => item.action === 'invalid').length,
  };
  stats.actionable = stats.add + stats.overwrite;
  return { strategy, items, stats };
}

export function applyImportPlan(plan, existingKeys = [], createId = generateId) {
  const keys = existingKeys.map((key) => ({ ...key }));
  const createdIds = new Map();
  const importedKeyIds = new Map();
  let nextOrder = Math.max(-1, ...keys.map((key) => Number(key.order || 0))) + 1;

  for (const item of plan?.items || []) {
    if (item.action === 'add') {
      const added = { ...item.candidate, id: createId(), order: nextOrder };
      nextOrder += 1;
      keys.push(added);
      createdIds.set(item.resultRef, added.id);
      importedKeyIds.set(item.candidate.id, added.id);
      continue;
    }
    if (item.action === 'skip') {
      const targetId = item.target.kind === 'planned' ? createdIds.get(item.target.ref) : item.target.id;
      if (targetId) importedKeyIds.set(item.candidate.id, targetId);
      continue;
    }
    if (item.action !== 'overwrite') continue;

    const targetId = item.target.kind === 'planned' ? createdIds.get(item.target.ref) : item.target.id;
    const existingIndex = keys.findIndex((key) => key.id === targetId);
    if (existingIndex < 0) throw importError('导入目标已变化，请重新预览后再确认', 'STALE_IMPORT');
    const previous = keys[existingIndex];
    keys[existingIndex] = {
      ...item.candidate,
      id: previous.id,
      order: previous.order,
      favorite: item.candidate.favorite || previous.favorite,
      lastUsed: previous.lastUsed,
      useCount: previous.useCount,
    };
    importedKeyIds.set(item.candidate.id, previous.id);
  }

  return { keys, importedKeyIds, stats: { ...plan.stats } };
}
