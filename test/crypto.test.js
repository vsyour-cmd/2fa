import { describe, expect, it } from 'vitest';
import {
  aesKeysEqual,
  decryptBackup,
  decryptJson,
  deriveKey,
  deriveKeyHash,
  encryptBackup,
  encryptJson,
  generateSalt,
} from '../src/js/crypto.js';

describe('vault cryptography', () => {
  it('encrypts and decrypts JSON with AES-GCM', async () => {
    const key = await deriveKey('correct horse 123', generateSalt());
    const payload = { keys: [{ name: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' }] };
    const encrypted = await encryptJson(payload, key);
    expect(encrypted).not.toContain('GitHub');
    await expect(decryptJson(encrypted, key)).resolves.toEqual(payload);
  });

  it('detects different derived keys', async () => {
    const salt = generateSalt();
    const first = await deriveKey('password one 123', salt);
    const second = await deriveKey('password two 123', salt);
    await expect(aesKeysEqual(first, first)).resolves.toBe(true);
    await expect(aesKeysEqual(first, second)).resolves.toBe(false);
  });

  it('separates accounts in deriveKeyHash and preserves legacy determinism', async () => {
    const personal = await deriveKeyHash('password 123', 'Personal');
    const work = await deriveKeyHash('password 123', 'Work');
    expect(personal).toMatch(/^[a-f0-9]{64}$/);
    expect(personal).not.toBe(work);
    await expect(deriveKeyHash('password 123', 'ignored', 'legacy-v2')).resolves.toBe(
      await deriveKeyHash('password 123', 'another', 'legacy-v2'),
    );
  });

  it('round-trips password encrypted exports', async () => {
    const payload = { version: 3, keys: [{ name: 'Example' }] };
    const backup = await encryptBackup(payload, 'export password 123');
    expect(backup.format).toBe('2fa-encrypted-backup');
    await expect(decryptBackup(backup, 'export password 123')).resolves.toEqual(payload);
    await expect(decryptBackup(backup, 'wrong password 123')).rejects.toThrow();
  });
});
