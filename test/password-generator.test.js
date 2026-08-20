import { describe, expect, it } from 'vitest';
import { generatePassword, generatePasswords } from '../src/js/password-generator.js';

function deterministicCrypto(values = [0]) {
  let index = 0;
  return {
    getRandomValues(target) {
      target[0] = values[index % values.length] >>> 0;
      index += 1;
      return target;
    },
  };
}

describe('random password generator', () => {
  it('uses every selected character type and the requested length', () => {
    const password = generatePassword({ length: 16, lowercase: true, uppercase: true, numbers: true, symbols: true }, deterministicCrypto([0, 1, 2, 3, 4, 5]));
    expect(password).toHaveLength(16);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*()\-_=+\[\]{}:,.?]/);
  });

  it('removes every explicitly excluded character', () => {
    const password = generatePassword({ length: 32, lowercase: true, uppercase: true, numbers: true, symbols: false, exclude: 'aA0iIl1LoO' }, deterministicCrypto([0, 1, 2, 3, 4, 5, 6]));
    expect(password).not.toMatch(/[aA0iIl1LoO]/);
  });

  it('generates the requested number of passwords', () => {
    const passwords = generatePasswords({ count: 5, length: 12, lowercase: true, uppercase: true, numbers: true }, deterministicCrypto([1, 2, 3, 4]));
    expect(passwords).toHaveLength(5);
    expect(passwords.every((password) => password.length === 12)).toBe(true);
  });

  it('rejects unsafe or unusable configurations', () => {
    expect(() => generatePassword({ length: 16, lowercase: false, uppercase: false, numbers: false, symbols: false }, deterministicCrypto())).toThrow('至少选择一种字符类型');
    expect(() => generatePasswords({ count: 21, length: 16 }, deterministicCrypto())).toThrow('1～20');
    expect(() => generatePassword({ length: 3 }, deterministicCrypto())).toThrow('4～128');
  });
});
