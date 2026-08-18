import { normalizeAlgorithm, normalizeSecret } from './utils.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const formatted = String(input || '').toUpperCase().replace(/[\s=-]/g, '');
  if (!formatted || /[^A-Z2-7]/.test(formatted)) {
    throw new Error('密钥必须是有效的 Base32 字符串');
  }

  let buffer = 0;
  let bitsLeft = 0;
  const bytes = [];
  for (const char of formatted) {
    const value = BASE32_ALPHABET.indexOf(char);
    buffer = (buffer << 5) | value;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bytes.push((buffer >>> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
    }
  }

  if (bytes.length === 0) throw new Error('密钥长度不足');
  return new Uint8Array(bytes);
}

export function getTotpOptions(source = {}) {
  const period = Number.parseInt(source.period, 10);
  const digits = Number.parseInt(source.digits, 10);
  return {
    period: Number.isFinite(period) && period >= 5 && period <= 300 ? period : 30,
    digits: digits === 8 ? 8 : 6,
    algorithm: normalizeAlgorithm(source.algorithm || source.algo),
  };
}

export async function generateTOTP(secret, time = Date.now(), options = {}) {
  const { period, digits, algorithm } = getTotpOptions(options);
  const counter = Math.floor(Number(time) / (period * 1000));
  if (!Number.isFinite(counter) || counter < 0) throw new Error('时间参数无效');

  const counterBytes = new Uint8Array(8);
  let remainingCounter = counter;
  for (let index = 7; index >= 0; index -= 1) {
    counterBytes[index] = remainingCounter & 0xff;
    remainingCounter = Math.floor(remainingCounter / 256);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secret),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary = (
    ((signature[offset] & 0x7f) << 24)
    | ((signature[offset + 1] & 0xff) << 16)
    | ((signature[offset + 2] & 0xff) << 8)
    | (signature[offset + 3] & 0xff)
  ) >>> 0;
  const modulus = 10 ** digits;
  return String(binary % modulus).padStart(digits, '0');
}

export async function generateTOTPWindow(secret, time = Date.now(), options = {}) {
  const periodMs = getTotpOptions(options).period * 1000;
  const timestamp = Number(time);
  if (!Number.isFinite(timestamp) || timestamp < periodMs) throw new Error('时间参数无效');
  const [previous, current, next] = await Promise.all([
    generateTOTP(secret, timestamp - periodMs, options),
    generateTOTP(secret, timestamp, options),
    generateTOTP(secret, timestamp + periodMs, options),
  ]);
  return { previous, current, next };
}

export function parseOtpauthUri(uri) {
  if (!String(uri || '').toLowerCase().startsWith('otpauth://totp/')) return null;
  try {
    const url = new URL(uri);
    const secret = normalizeSecret(url.searchParams.get('secret'));
    if (!secret) return null;
    base32Decode(secret);

    const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
    const separator = label.indexOf(':');
    const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : '';
    const account = separator >= 0 ? label.slice(separator + 1).trim() : label.trim();
    const issuer = String(url.searchParams.get('issuer') || labelIssuer).trim();
    const options = getTotpOptions({
      period: url.searchParams.get('period'),
      digits: url.searchParams.get('digits'),
      algorithm: url.searchParams.get('algorithm'),
    });
    return {
      name: issuer || account || '未命名',
      issuer,
      account,
      secret,
      ...options,
    };
  } catch {
    return null;
  }
}

export function buildOtpauthUri(key) {
  const { period, digits, algorithm } = getTotpOptions(key);
  const issuer = String(key.issuer || key.name || '').trim();
  const account = String(key.account || key.name || '').trim();
  const label = issuer && account && issuer !== account ? `${issuer}:${account}` : (account || issuer || '未命名');
  const params = new URLSearchParams({
    secret: normalizeSecret(key.secret),
    issuer,
    algorithm: algorithm.replace('-', ''),
    digits: String(digits),
    period: String(period),
  });
  if (!issuer) params.delete('issuer');
  return `otpauth://totp/${encodeURIComponent(label).replace(/%3A/gi, ':')}?${params.toString()}`;
}

export function getRemainingSeconds(key, time = Date.now()) {
  const { period } = getTotpOptions(key);
  const elapsed = Math.floor(Number(time) / 1000) % period;
  return elapsed === 0 ? period : period - elapsed;
}

export function getNextPeriodDelay(key, time = Date.now(), safetyMs = 50) {
  const periodMs = getTotpOptions(key).period * 1000;
  const currentTime = Number(time);
  if (!Number.isFinite(currentTime) || currentTime < 0) throw new Error('时间参数无效');
  const nextPeriodStart = (Math.floor(currentTime / periodMs) + 1) * periodMs;
  return Math.max(0, nextPeriodStart - currentTime + Math.max(0, Number(safetyMs) || 0));
}

export function getCounter(key, time = Date.now()) {
  const { period } = getTotpOptions(key);
  return Math.floor(Number(time) / (period * 1000));
}

export function formatCode(code) {
  const middle = Math.ceil(String(code).length / 2);
  return `${String(code).slice(0, middle)} ${String(code).slice(middle)}`;
}
