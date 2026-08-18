import jsQR from 'jsqr';
import { describe, expect, it } from 'vitest';
import { createQrMatrix } from '../src/js/qrcode.js';

function matrixImage(modules, scale = 5, quiet = 4) {
  const size = (modules.length + quiet * 2) * scale;
  const data = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let y = 0; y < modules.length; y += 1) for (let x = 0; x < modules.length; x += 1) {
    if (!modules[y][x]) continue;
    for (let py = 0; py < scale; py += 1) for (let px = 0; px < scale; px += 1) {
      const offset = (((y + quiet) * scale + py) * size + (x + quiet) * scale + px) * 4;
      data[offset] = 0;
      data[offset + 1] = 0;
      data[offset + 2] = 0;
    }
  }
  return { data, size };
}

describe('offline OTPAuth QR generation', () => {
  it('round-trips a typical OTPAuth URI through jsQR', () => {
    const uri = 'otpauth://totp/GitHub%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30';
    const image = matrixImage(createQrMatrix(uri));
    expect(jsQR(image.data, image.size, image.size)?.data).toBe(uri);
  });

  it('rejects values that exceed the fixed offline QR capacity', () => {
    expect(() => createQrMatrix('x'.repeat(214))).toThrow('OTPAuth URI 太长');
  });
});
