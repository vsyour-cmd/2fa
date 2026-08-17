import { describe, expect, it } from 'vitest';
import worker from '../worker.js';

class FakeKv {
  constructor() {
    this.values = new Map();
  }

  async get(key) { return this.values.get(key) ?? null; }

  async put(key, value) { this.values.set(key, value); }

  async delete(key) { this.values.delete(key); }

  async list({ prefix, limit }) {
    const keys = [...this.values.keys()].filter((key) => key.startsWith(prefix)).slice(0, limit).map((name) => ({ name }));
    return { keys, list_complete: true };
  }
}

function request(path, init = {}) {
  return new Request(`https://example.test${path}`, {
    ...init,
    headers: { 'CF-Connecting-IP': '203.0.113.10', ...(init.headers || {}) },
  });
}

describe('Cloudflare Worker API', () => {
  it('stores, reads, and deletes encrypted records', async () => {
    const env = { DATA_KV: new FakeKv() };
    const key = 'a'.repeat(64);
    const body = JSON.stringify({ key, data: 'encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3 });
    const put = await worker.fetch(request('/api/data', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body }), env);
    expect(put.status).toBe(200);
    expect(await put.json()).toMatchObject({ success: true });

    const get = await worker.fetch(request(`/api/data?key=${key}`), env);
    const record = await get.json();
    expect(record.exists).toBe(true);
    expect(JSON.parse(record.data)).toMatchObject({ encryptedData: 'encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3 });

    expect((await worker.fetch(request(`/api/data?key=${key}`, { method: 'DELETE' }), env)).status).toBe(200);
    expect(await (await worker.fetch(request(`/api/data?key=${key}`), env)).json()).toMatchObject({ exists: false });
  });

  it('rejects invalid and oversized requests', async () => {
    const env = { DATA_KV: new FakeKv() };
    expect((await worker.fetch(request('/api/data?key=bad'), env)).status).toBe(400);
    const oversized = await worker.fetch(request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(300 * 1024) },
      body: '{}',
    }), env);
    expect(oversized.status).toBe(413);
  });

  it('limits one IP to 20 API requests per minute', async () => {
    const env = { DATA_KV: new FakeKv() };
    for (let index = 0; index < 20; index += 1) {
      const response = await worker.fetch(request(`/api/data?key=${'b'.repeat(64)}`), env);
      expect(response.status).toBe(200);
    }
    const blocked = await worker.fetch(request(`/api/data?key=${'b'.repeat(64)}`), env);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('Retry-After')).toBeTruthy();
  });
});
