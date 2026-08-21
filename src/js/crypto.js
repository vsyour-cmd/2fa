import { normalizeAccountName } from './utils.js';

export const PBKDF2_ITERATIONS = Object.freeze({
  LEGACY_V1_HASH: 50_000,
  LEGACY_V1_KEY: 100_000,
  CURRENT: 600_000,
});

export const VAULT_VERSION = 3;
export const QUICK_UNLOCK_ITERATIONS = 200_000;
export const WORKFLOW_PROTECTION_ITERATIONS = 300_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64(bytes) {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(String(value || ''));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(value) {
  const hex = String(value || '').trim();
  if (!hex || hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) throw new Error('无效的十六进制数据');
  return Uint8Array.from(hex.match(/.{2}/g), (pair) => Number.parseInt(pair, 16));
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, item) => sum + item.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    output.set(item, offset);
    offset += item.length;
  }
  return output;
}

export function generateSalt(length = 16) {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(length)));
}

async function importPassword(password, usage) {
  return crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, usage);
}

export async function deriveKeyHash(password, accountName, mode = 'scoped') {
  let saltLabel = `2fa-sync-v3-key-hash:${normalizeAccountName(accountName).normalize('NFKC').toLocaleLowerCase('en-US')}`;
  let iterations = PBKDF2_ITERATIONS.CURRENT;
  if (mode === 'legacy-v1') {
    saltLabel = '2fa-sync-v1-key-hash';
    iterations = PBKDF2_ITERATIONS.LEGACY_V1_HASH;
  } else if (mode === 'legacy-v2') {
    saltLabel = '2fa-sync-v1-key-hash';
  }
  const material = await importPassword(password, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: encoder.encode(saltLabel),
    iterations,
    hash: 'SHA-256',
  }, material, 256);
  return bytesToHex(new Uint8Array(bits));
}

export async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS.CURRENT) {
  const saltBytes = typeof salt === 'string' ? base64ToBytes(salt) : salt;
  const material = await importPassword(password, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: saltBytes,
    iterations,
    hash: 'SHA-256',
  }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function deriveQuickUnlockHash(pin, salt, accountName, iterations = QUICK_UNLOCK_ITERATIONS) {
  const material = await importPassword(pin, ['deriveBits']);
  const scopedSalt = concatBytes(base64ToBytes(salt), encoder.encode(normalizeAccountName(accountName).normalize('NFKC')));
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: scopedSalt, iterations, hash: 'SHA-256' }, material, 256);
  return bytesToHex(new Uint8Array(bits));
}

export async function deriveWorkflowProtectionHash(password, salt, accountName, iterations = WORKFLOW_PROTECTION_ITERATIONS) {
  const material = await importPassword(password, ['deriveBits']);
  const scopedSalt = concatBytes(
    base64ToBytes(salt),
    encoder.encode(`workflow-edit:${normalizeAccountName(accountName).normalize('NFKC')}`),
  );
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: scopedSalt, iterations, hash: 'SHA-256' }, material, 256);
  return bytesToHex(new Uint8Array(bits));
}

export async function encryptJson(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(JSON.stringify(data)),
  ));
  return bytesToBase64(concatBytes(iv, encrypted));
}

export async function decryptJson(encryptedData, key) {
  const combined = base64ToBytes(encryptedData);
  if (combined.length < 29) throw new Error('加密数据不完整');
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: combined.slice(0, 12) },
    key,
    combined.slice(12),
  );
  return JSON.parse(decoder.decode(decrypted));
}

export async function importAesKey(value) {
  return crypto.subtle.importKey(
    'raw',
    base64ToBytes(value),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function aesKeysEqual(left, right) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  let decrypted;
  try {
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, left, challenge);
    decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, right, encrypted));
  } catch {
    return false;
  }
  if (challenge.length !== decrypted.length) return false;
  let difference = 0;
  for (let index = 0; index < challenge.length; index += 1) difference |= challenge[index] ^ decrypted[index];
  return difference === 0;
}

export async function decryptAesGcmBytes(ciphertext, keyBytes, nonce, tag) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: tag.length * 8 },
    key,
    concatBytes(ciphertext, tag),
  );
  return new Uint8Array(decrypted);
}

export async function encryptBackup(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS.CURRENT);
  const encryptedData = await encryptJson(data, key);
  return {
    format: '2fa-encrypted-backup',
    version: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ITERATIONS.CURRENT, salt: bytesToBase64(salt) },
    cipher: { name: 'AES-GCM', data: encryptedData },
  };
}

export async function decryptBackup(payload, password) {
  if (payload?.format !== '2fa-encrypted-backup' || !payload?.kdf?.salt || !payload?.cipher?.data) {
    throw new Error('不支持的加密备份格式');
  }
  const iterations = Number(payload.kdf.iterations);
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) {
    throw new Error('备份 KDF 参数无效');
  }
  const key = await deriveKey(password, payload.kdf.salt, iterations);
  return decryptJson(payload.cipher.data, key);
}

export function validatePassword(password) {
  if (String(password).length < 10) return { valid: false, error: '密码至少需要 10 个字符' };
  if (!/[a-zA-Z]/.test(password)) return { valid: false, error: '密码需要包含至少一个字母' };
  if (!/[0-9]/.test(password)) return { valid: false, error: '密码需要包含至少一个数字' };
  return { valid: true };
}

export function getPasswordStrength(password) {
  const value = String(password || '');
  let score = 0;
  if (value.length >= 10) score += 1;
  if (value.length >= 14) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^a-zA-Z0-9]/.test(value)) score += 1;
  const levels = [
    { label: '很弱', percent: 12 },
    { label: '较弱', percent: 30 },
    { label: '一般', percent: 52 },
    { label: '较强', percent: 74 },
    { label: '强', percent: 90 },
    { label: '很强', percent: 100 },
  ];
  return { score, ...levels[score] };
}
