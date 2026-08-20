const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}:,.?';
const UINT32_RANGE = 0x1_0000_0000;

function secureRandomIndex(max, cryptoSource) {
  if (!Number.isInteger(max) || max <= 0) throw new Error('可用字符不足');
  if (!cryptoSource?.getRandomValues) throw new Error('当前浏览器不支持安全随机数');
  const limit = Math.floor(UINT32_RANGE / max) * max;
  const value = new Uint32Array(1);
  do cryptoSource.getRandomValues(value); while (value[0] >= limit);
  return value[0] % max;
}

function filteredPool(characters, excluded) {
  return [...characters].filter((character) => !excluded.has(character)).join('');
}

export function generatePassword(options = {}, cryptoSource = globalThis.crypto) {
  const length = Number(options.length);
  if (!Number.isInteger(length) || length < 4 || length > 128) throw new Error('密码长度必须在 4～128 位之间');

  const excluded = new Set(String(options.exclude || ''));
  const requestedPools = [
    options.lowercase !== false ? LOWERCASE : '',
    options.uppercase !== false ? UPPERCASE : '',
    options.numbers !== false ? NUMBERS : '',
    options.symbols ? SYMBOLS : '',
  ].filter(Boolean);
  if (requestedPools.length === 0) throw new Error('请至少选择一种字符类型');

  const pools = requestedPools.map((pool) => filteredPool(pool, excluded));
  if (pools.some((pool) => pool.length === 0)) throw new Error('排除字符后，某种已选字符类型没有可用字符');
  if (length < pools.length) throw new Error(`密码长度不能少于已选字符类型数量（${pools.length}）`);

  const combined = pools.join('');
  const result = pools.map((pool) => pool[secureRandomIndex(pool.length, cryptoSource)]);
  while (result.length < length) result.push(combined[secureRandomIndex(combined.length, cryptoSource)]);
  for (let index = result.length - 1; index > 0; index -= 1) {
    const target = secureRandomIndex(index + 1, cryptoSource);
    [result[index], result[target]] = [result[target], result[index]];
  }
  return result.join('');
}

export function generatePasswords(options = {}, cryptoSource = globalThis.crypto) {
  const count = Number(options.count ?? 1);
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new Error('生成数量必须在 1～20 个之间');
  return Array.from({ length: count }, () => generatePassword(options, cryptoSource));
}
