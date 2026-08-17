import { describe, expect, it } from 'vitest';
import { base32Decode, buildOtpauthUri, generateTOTP, getNextPeriodDelay, getRemainingSeconds, parseOtpauthUri } from '../src/js/totp.js';
import { bytesToBase32 } from '../src/js/utils.js';

const encoder = new TextEncoder();
const secrets = {
  'SHA-1': bytesToBase32(encoder.encode('12345678901234567890')),
  'SHA-256': bytesToBase32(encoder.encode('12345678901234567890123456789012')),
  'SHA-512': bytesToBase32(encoder.encode('1234567890123456789012345678901234567890123456789012345678901234')),
};

const vectors = [
  [59, '94287082', '46119246', '90693936'],
  [1_111_111_109, '07081804', '68084774', '25091201'],
  [1_111_111_111, '14050471', '67062674', '99943326'],
  [1_234_567_890, '89005924', '91819424', '93441116'],
  [2_000_000_000, '69279037', '90698825', '38618901'],
  [20_000_000_000, '65353130', '77737706', '47863826'],
];

describe('base32Decode', () => {
  it('decodes the RFC example and tolerates human formatting', () => {
    expect([...base32Decode('JBSW Y3DP-EHPK3PXP')]).toEqual([72, 101, 108, 108, 111, 33, 222, 173, 190, 239]);
  });

  it('rejects invalid or empty input', () => {
    expect(() => base32Decode('!!!')).toThrow(/Base32/);
    expect(() => base32Decode('')).toThrow(/Base32/);
  });
});

describe('generateTOTP', () => {
  it.each(vectors)('matches RFC 6238 at %s seconds', async (seconds, sha1, sha256, sha512) => {
    expect(await generateTOTP(secrets['SHA-1'], seconds * 1000, { digits: 8, algorithm: 'SHA-1' })).toBe(sha1);
    expect(await generateTOTP(secrets['SHA-256'], seconds * 1000, { digits: 8, algorithm: 'SHA-256' })).toBe(sha256);
    expect(await generateTOTP(secrets['SHA-512'], seconds * 1000, { digits: 8, algorithm: 'SHA-512' })).toBe(sha512);
  });

  it('supports custom periods and six digit output', async () => {
    const code = await generateTOTP(secrets['SHA-1'], 120_000, { period: 60, digits: 6 });
    expect(code).toMatch(/^\d{6}$/);
  });

  it('calculates the safe wait into the next period at the final second', async () => {
    const key = { period: 60 };
    expect(getRemainingSeconds(key, 59_250)).toBe(1);
    expect(getNextPeriodDelay(key, 59_250)).toBe(800);
    const expiringCode = await generateTOTP(secrets['SHA-1'], 59_250, { period: 60, digits: 8 });
    const nextCode = await generateTOTP(secrets['SHA-1'], 60_050, { period: 60, digits: 8 });
    expect(nextCode).not.toBe(expiringCode);
  });
});

describe('OTPAuth URI', () => {
  it('parses and rebuilds issuer, account and custom parameters', () => {
    const uri = `otpauth://totp/ACME:alice%40example.com?secret=${secrets['SHA-256']}&issuer=ACME&algorithm=SHA256&digits=8&period=60`;
    const parsed = parseOtpauthUri(uri);
    expect(parsed).toMatchObject({ issuer: 'ACME', account: 'alice@example.com', algorithm: 'SHA-256', digits: 8, period: 60 });
    expect(parseOtpauthUri(buildOtpauthUri(parsed))).toMatchObject(parsed);
  });

  it('rejects HOTP and missing secrets', () => {
    expect(parseOtpauthUri('otpauth://hotp/test?secret=ABC')).toBeNull();
    expect(parseOtpauthUri('otpauth://totp/test')).toBeNull();
  });
});
