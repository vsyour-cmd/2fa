import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const key = 'a'.repeat(64);
const data = 'encrypted-payload-longer-than-sixteen-characters';
const salt = '0123456789abcdef';
const dbPath = join(tmpdir(), `2fa-server-api-${process.pid}-${randomUUID()}.db`);

let db;
let server;
let baseUrl;

async function request(path, options) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const body = await response.json();
  return { response, body };
}

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

describe('Express data API', () => {
  it('returns a missing record without starting the production listener', async () => {
    const { response, body } = await request(`/api/data?key=${key}`);
    expect(response.status).toBe(200);
    expect(body).toEqual({ exists: false, data: null });
  });

  it('stores and retrieves an encrypted record', async () => {
    const put = await request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, data, salt, version: 3, expectedUpdatedAt: 0 }),
    });
    expect(put.response.status).toBe(200);
    expect(put.body).toMatchObject({ success: true });
    expect(put.body.updatedAt).toEqual(expect.any(Number));

    const get = await request(`/api/data?key=${key}`);
    expect(get.response.status).toBe(200);
    expect(get.body.exists).toBe(true);
    expect(JSON.parse(get.body.data)).toMatchObject({ encryptedData: data, salt, version: 3, updatedAt: put.body.updatedAt });
  });

  it('rejects invalid keys and payload fields', async () => {
    const invalidKey = await request('/api/data?key=short');
    expect(invalidKey.response.status).toBe(400);
    expect(invalidKey.body).toEqual({ error: 'Invalid key' });

    for (const payload of [
      { key, salt },
      { key, data: 'too-short', salt },
      { key, data, salt: 'short' },
    ]) {
      const result = await request('/api/data', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      expect(result.response.status).toBe(400);
      expect(result.body).toEqual({ error: 'Invalid data' });
    }
  });

  it('returns a JSON 400 response for malformed JSON', async () => {
    const { response, body } = await request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: '{',
    });
    expect(response.status).toBe(400);
    expect(body).toEqual({ error: 'Invalid JSON' });
  });

  it('rejects the second of two writes based on the same cloud version', async () => {
    const current = await request(`/api/data?key=${key}`);
    const expectedUpdatedAt = current.body.updatedAt;
    const save = (nextData) => request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, data: nextData, salt, version: 3, expectedUpdatedAt }),
    });

    const results = await Promise.all([
      save('device-one-encrypted-payload-longer-than-sixteen'),
      save('device-two-encrypted-payload-longer-than-sixteen'),
    ]);
    expect(results.map(({ response }) => response.status).sort()).toEqual([200, 409]);
    expect(results.find(({ response }) => response.status === 409).body).toMatchObject({ code: 'VERSION_CONFLICT' });

    const latest = await request(`/api/data?key=${key}`);
    expect([
      'device-one-encrypted-payload-longer-than-sixteen',
      'device-two-encrypted-payload-longer-than-sixteen',
    ]).toContain(JSON.parse(latest.body.data).encryptedData);
  });

  it('deletes an existing record', async () => {
    const deleted = await request(`/api/data?key=${key}`, { method: 'DELETE' });
    expect(deleted.response.status).toBe(200);
    expect(deleted.body).toEqual({ success: true });

    const get = await request(`/api/data?key=${key}`);
    expect(get.body).toEqual({ exists: false, data: null });
  });

  it('keeps health checks outside rate limiting and sends security headers', async () => {
    const { response, body } = await request('/health');
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ status: 'ok' });
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('content-security-policy')).toContain("script-src 'self' https://static.cloudflareinsights.com");
    expect(response.headers.get('ratelimit-limit')).toBeNull();
  });
});
