import { describe, expect, it } from 'vitest';
import { scrypt } from 'scrypt-js';
import { parseGoogleMigrationUri, parseImportContent, validateImportedItems } from '../src/js/importers.js';
import { bytesToBase64, bytesToHex, concatBytes } from '../src/js/crypto.js';
import { generateTOTP } from '../src/js/totp.js';
import { normalizeVaultData } from '../src/js/utils.js';

const encoder = new TextEncoder();

function encodeVarint(value) {
  const output = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining > 0) byte |= 0x80;
    output.push(byte);
  } while (remaining > 0);
  return Uint8Array.from(output);
}

function protobufBytesField(field, value) {
  const bytes = value instanceof Uint8Array ? value : encoder.encode(value);
  return concatBytes(encodeVarint((field << 3) | 2), encodeVarint(bytes.length), bytes);
}

function protobufNumberField(field, value) {
  return concatBytes(encodeVarint(field << 3), encodeVarint(value));
}

async function encryptAesGcm(plaintext, keyBytes, nonce) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const combined = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext));
  return { ciphertext: combined.slice(0, -16), tag: combined.slice(-16) };
}

async function createEncryptedAegisFixture(password) {
  const masterKey = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const slotNonce = crypto.getRandomValues(new Uint8Array(12));
  const dbNonce = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = new Uint8Array(await scrypt(encoder.encode(password), salt, 1024, 8, 1, 32));
  const encryptedMaster = await encryptAesGcm(masterKey, wrappingKey, slotNonce);
  const database = {
    version: 3,
    groups: [{ uuid: 'group-1', name: '工作' }],
    entries: [{
      type: 'totp', uuid: 'aegis-1', name: 'alice', issuer: 'GitHub', favorite: true, groups: ['group-1'],
      info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA256', digits: 8, period: 45 },
    }],
  };
  const encryptedDatabase = await encryptAesGcm(encoder.encode(JSON.stringify(database)), masterKey, dbNonce);
  return {
    version: 1,
    header: {
      slots: [{
        type: 1, uuid: 'slot-1', key: bytesToHex(encryptedMaster.ciphertext), salt: bytesToHex(salt), n: 1024, r: 8, p: 1,
        key_params: { nonce: bytesToHex(slotNonce), tag: bytesToHex(encryptedMaster.tag) },
      }],
      params: { nonce: bytesToHex(dbNonce), tag: bytesToHex(encryptedDatabase.tag) },
    },
    db: bytesToBase64(encryptedDatabase.ciphertext),
  };
}

describe('backward compatibility', () => {
  it('loads legacy key arrays with safe defaults', () => {
    const vault = normalizeVaultData([{ id: 1, name: 'Legacy', secret: 'JBSWY3DPEHPK3PXP' }]);
    expect(vault.keys[0]).toMatchObject({ id: '1', group: '', period: 30, digits: 6, algorithm: 'SHA-1', favorite: false, useCount: 0 });
    expect(vault.deletedItems).toEqual([]);
  });

  it('imports 2FAS and andOTP JSON shapes', async () => {
    const twoFas = await parseImportContent(JSON.stringify({ services: [{ name: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', otp: { issuer: 'GitHub', account: 'alice' } }] }));
    const andOtp = await parseImportContent(JSON.stringify([{ issuer: 'GitLab', label: 'bob', secret: 'JBSWY3DPEHPK3PXP', period: 30 }]));
    expect(twoFas.items[0]).toMatchObject({ name: 'GitHub', account: 'alice' });
    expect(andOtp.items[0]).toMatchObject({ name: 'GitLab', account: 'bob' });
  });

  it('filters invalid secrets before import', async () => {
    const result = await validateImportedItems([
      { name: 'Valid', secret: 'JBSWY3DPEHPK3PXP' },
      { name: 'Invalid', secret: '!!!' },
    ], generateTOTP);
    expect(result.valid).toHaveLength(1);
    expect(result.skipped).toBe(1);
  });

  it('decodes Google Authenticator migration protobuf data', () => {
    const entry = concatBytes(
      protobufBytesField(1, Uint8Array.from([72, 101, 108, 108, 111, 33, 222, 173, 190, 239])),
      protobufBytesField(2, 'alice@example.com'),
      protobufBytesField(3, 'Example'),
      protobufNumberField(4, 2),
      protobufNumberField(5, 2),
      protobufNumberField(6, 2),
    );
    const migration = protobufBytesField(1, entry);
    const uri = `otpauth-migration://offline?data=${encodeURIComponent(bytesToBase64(migration))}`;
    expect(parseGoogleMigrationUri(uri)[0]).toMatchObject({
      name: 'Example', issuer: 'Example', account: 'alice@example.com', algorithm: 'SHA-256', digits: 8,
    });
  });

  it('decrypts password-protected Aegis JSON exports', async () => {
    const fixture = await createEncryptedAegisFixture('fixture-password');
    const result = await parseImportContent(JSON.stringify(fixture), 'fixture-password');
    expect(result.source).toBe('Aegis');
    expect(result.items[0]).toMatchObject({
      id: 'aegis-1', name: 'GitHub', account: 'alice', group: '工作', algorithm: 'SHA-256', digits: 8, period: 45,
    });
    await expect(parseImportContent(JSON.stringify(fixture), 'wrong-password')).rejects.toMatchObject({ code: 'BAD_PASSWORD' });
  });
});
