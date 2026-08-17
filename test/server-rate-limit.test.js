import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const key = 'b'.repeat(64);
const dbPath = join(tmpdir(), `2fa-server-rate-${process.pid}-${randomUUID()}.db`);

let db;
let server;
let baseUrl;

beforeAll(async () => {
  vi.stubEnv('DB_PATH', dbPath);
  const imported = await import('../src/server.js');
  const exported = imported.default || imported;
  db = exported.db;
  server = createServer(exported.app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
  if (db?.open) db.close();
  await rm(dbPath, { force: true });
  vi.unstubAllEnvs();
});

describe('Express API rate limiting', () => {
  it('allows 20 requests from one IP and rejects the 21st', async () => {
    for (let index = 0; index < 20; index += 1) {
      const response = await fetch(`${baseUrl}/api/data?key=${key}`);
      expect(response.status).toBe(200);
      expect(response.headers.get('ratelimit-limit')).toBe('20');
      expect(response.headers.get('ratelimit-remaining')).toBe(String(19 - index));
    }

    const blocked = await fetch(`${baseUrl}/api/data?key=${key}`);
    expect(blocked.status).toBe(429);
    expect(await blocked.json()).toEqual({ error: 'Too many requests' });
    expect(blocked.headers.get('ratelimit-limit')).toBe('20');
    expect(blocked.headers.get('ratelimit-remaining')).toBe('0');
    expect(Number(blocked.headers.get('ratelimit-reset'))).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(0);
  });
});
