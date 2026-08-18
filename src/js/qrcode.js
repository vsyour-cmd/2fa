const VERSION = 10;
const SIZE = 21 + 4 * (VERSION - 1);
const DATA_CAPACITY = 216;
const EC_BLOCK_SIZE = 26;
const ALIGNMENT_POSITIONS = [6, 28, 50];

function appendBits(bits, value, length) {
  for (let index = length - 1; index >= 0; index -= 1) bits.push((value >>> index) & 1);
}

function makeDataCodewords(text) {
  const bytes = new TextEncoder().encode(String(text));
  if (bytes.length > 213) throw new Error('OTPAuth URI 太长，无法生成离线二维码');
  const bits = [];
  appendBits(bits, 0b0100, 4);
  appendBits(bits, bytes.length, 16);
  for (const byte of bytes) appendBits(bits, byte, 8);
  const capacityBits = DATA_CAPACITY * 8;
  appendBits(bits, 0, Math.min(4, capacityBits - bits.length));
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let index = 0; index < bits.length; index += 8) {
    data.push(bits.slice(index, index + 8).reduce((value, bit) => (value << 1) | bit, 0));
  }
  for (let pad = 0; data.length < DATA_CAPACITY; pad += 1) data.push(pad % 2 ? 0x11 : 0xec);
  return data;
}

function gfMultiply(left, right) {
  let result = 0;
  for (let bit = 7; bit >= 0; bit -= 1) {
    result = (result << 1) ^ ((result >>> 7) * 0x11d);
    result ^= ((right >>> bit) & 1) * left;
  }
  return result;
}

function reedSolomonDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let index = 0; index < degree; index += 1) {
    for (let term = 0; term < result.length; term += 1) {
      result[term] = gfMultiply(result[term], root);
      if (term + 1 < result.length) result[term] ^= result[term + 1];
    }
    root = gfMultiply(root, 2);
  }
  return result;
}

function reedSolomonRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let index = 0; index < result.length; index += 1) result[index] ^= gfMultiply(divisor[index], factor);
  }
  return result;
}

function interleaveCodewords(data) {
  const divisor = reedSolomonDivisor(EC_BLOCK_SIZE);
  const blocks = [];
  let offset = 0;
  for (const length of [43, 43, 43, 43, 44]) {
    const block = data.slice(offset, offset + length);
    blocks.push({ data: block, error: [...reedSolomonRemainder(block, divisor)] });
    offset += length;
  }
  const result = [];
  for (let index = 0; index < 44; index += 1) for (const block of blocks) if (index < block.data.length) result.push(block.data[index]);
  for (let index = 0; index < EC_BLOCK_SIZE; index += 1) for (const block of blocks) result.push(block.error[index]);
  return result;
}

function bchRemainder(value, polynomial, degree) {
  let remainder = value;
  for (let bit = 31 - Math.clz32(remainder); bit >= degree; bit = 31 - Math.clz32(remainder)) {
    remainder ^= polynomial << (bit - degree);
  }
  return remainder;
}

function drawFunctionPatterns(modules) {
  const set = (x, y, value) => { if (x >= 0 && y >= 0 && x < SIZE && y < SIZE) modules[y][x] = value; };
  const finder = (left, top) => {
    for (let y = -1; y <= 7; y += 1) for (let x = -1; x <= 7; x += 1) {
      const distance = Math.max(Math.abs(x - 3), Math.abs(y - 3));
      set(left + x, top + y, distance !== 2 && distance !== 4);
    }
  };
  finder(0, 0); finder(SIZE - 7, 0); finder(0, SIZE - 7);
  for (let index = 8; index < SIZE - 8; index += 1) {
    if (modules[6][index] === null) set(index, 6, index % 2 === 0);
    if (modules[index][6] === null) set(6, index, index % 2 === 0);
  }
  for (const centerY of ALIGNMENT_POSITIONS) for (const centerX of ALIGNMENT_POSITIONS) {
    if ((centerX === 6 && centerY === 6) || (centerX === 6 && centerY === SIZE - 7) || (centerX === SIZE - 7 && centerY === 6)) continue;
    for (let y = -2; y <= 2; y += 1) for (let x = -2; x <= 2; x += 1) set(centerX + x, centerY + y, Math.max(Math.abs(x), Math.abs(y)) !== 1);
  }
  for (let index = 0; index <= 5; index += 1) set(8, index, false);
  set(8, 7, false); set(8, 8, false); set(7, 8, false);
  for (let index = 9; index < 15; index += 1) set(14 - index, 8, false);
  for (let index = 0; index < 8; index += 1) set(SIZE - 1 - index, 8, false);
  for (let index = 8; index < 15; index += 1) set(8, SIZE - 15 + index, false);
  set(8, SIZE - 8, true);
  const versionBits = (VERSION << 12) | bchRemainder(VERSION << 12, 0x1f25, 12);
  for (let index = 0; index < 18; index += 1) {
    const bit = ((versionBits >>> index) & 1) !== 0;
    const x = SIZE - 11 + (index % 3);
    const y = Math.floor(index / 3);
    set(x, y, bit); set(y, x, bit);
  }
}

function maskBit(mask, x, y) {
  return [
    (x + y) % 2 === 0,
    y % 2 === 0,
    x % 3 === 0,
    (x + y) % 3 === 0,
    (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
    (x * y) % 2 + (x * y) % 3 === 0,
    ((x * y) % 2 + (x * y) % 3) % 2 === 0,
    ((x + y) % 2 + (x * y) % 3) % 2 === 0,
  ][mask];
}

function drawFormatBits(modules, mask) {
  const raw = mask;
  const bits = ((raw << 10) | bchRemainder(raw << 10, 0x537, 10)) ^ 0x5412;
  const bit = (index) => ((bits >>> index) & 1) !== 0;
  for (let index = 0; index <= 5; index += 1) modules[index][8] = bit(index);
  modules[7][8] = bit(6); modules[8][8] = bit(7); modules[8][7] = bit(8);
  for (let index = 9; index < 15; index += 1) modules[8][14 - index] = bit(index);
  for (let index = 0; index < 8; index += 1) modules[8][SIZE - 1 - index] = bit(index);
  for (let index = 8; index < 15; index += 1) modules[SIZE - 15 + index][8] = bit(index);
  modules[SIZE - 8][8] = true;
}

function buildMatrix(codewords, mask) {
  const modules = Array.from({ length: SIZE }, () => Array(SIZE).fill(null));
  drawFunctionPatterns(modules);
  let bitIndex = 0;
  for (let right = SIZE - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vertical = 0; vertical < SIZE; vertical += 1) for (let column = 0; column < 2; column += 1) {
      const x = right - column;
      const upward = ((right + 1) & 2) === 0;
      const y = upward ? SIZE - 1 - vertical : vertical;
      if (modules[y][x] !== null) continue;
      const value = bitIndex < codewords.length * 8 ? ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) !== 0 : false;
      modules[y][x] = value !== maskBit(mask, x, y);
      bitIndex += 1;
    }
  }
  drawFormatBits(modules, mask);
  return modules;
}

function penaltyScore(modules) {
  let score = 0;
  const lines = [...modules, ...Array.from({ length: SIZE }, (_, x) => modules.map((row) => row[x]))];
  for (const line of lines) {
    let run = 1;
    for (let index = 1; index < SIZE; index += 1) {
      if (line[index] === line[index - 1]) run += 1;
      else { if (run >= 5) score += run - 2; run = 1; }
    }
    if (run >= 5) score += run - 2;
    const text = line.map((value) => value ? '1' : '0').join('');
    score += (text.match(/10111010000|00001011101/g) || []).length * 40;
  }
  for (let y = 0; y < SIZE - 1; y += 1) for (let x = 0; x < SIZE - 1; x += 1) {
    const value = modules[y][x];
    if (modules[y][x + 1] === value && modules[y + 1][x] === value && modules[y + 1][x + 1] === value) score += 3;
  }
  const dark = modules.flat().filter(Boolean).length;
  score += Math.floor(Math.abs(dark * 20 - SIZE * SIZE * 10) / (SIZE * SIZE)) * 10;
  return score;
}

export function createQrMatrix(text) {
  const codewords = interleaveCodewords(makeDataCodewords(text));
  const candidates = Array.from({ length: 8 }, (_, mask) => buildMatrix(codewords, mask));
  return candidates.reduce((best, current) => penaltyScore(current) < penaltyScore(best) ? current : best);
}

export function drawQrToCanvas(canvas, text, scale = 4) {
  const modules = createQrMatrix(text);
  const quiet = 4;
  const size = (modules.length + quiet * 2) * scale;
  canvas.width = size;
  canvas.height = size;
  const context = canvas.getContext('2d');
  context.imageSmoothingEnabled = false;
  context.fillStyle = '#ffffff';
  context.fillRect(0, 0, size, size);
  context.fillStyle = '#000000';
  for (let y = 0; y < modules.length; y += 1) for (let x = 0; x < modules.length; x += 1) {
    if (modules[y][x]) context.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
  }
}
