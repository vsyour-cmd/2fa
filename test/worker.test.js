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

  it('keeps the admin console closed until a password secret is configured', async () => {
    const env = { DATA_KV: new FakeKv() };
    const response = await worker.fetch(request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'not-configured' }),
    }), env);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ code: 'ADMIN_NOT_CONFIGURED' });
  });

  it('manages users, recoverable resets, and audit logs through authenticated admin APIs', async () => {
    const env = { DATA_KV: new FakeKv(), ADMIN_PASSWORD: 'strong-admin-password', ADMIN_USERNAME: 'admin' };
    const key = 'c'.repeat(64);
    const vaultBody = JSON.stringify({
      key,
      data: 'encrypted-payload-long-enough',
      salt: 'base64-salt-value',
      version: 3,
      accountName: '财务账户',
    });
    expect((await worker.fetch(request('/api/data', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: vaultBody,
    }), env)).status).toBe(200);

    const failedLogin = await worker.fetch(request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
    }), env);
    expect(failedLogin.status).toBe(401);

    const login = await worker.fetch(request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'strong-admin-password' }),
    }), env);
    expect(login.status).toBe(200);
    const { token } = await login.json();
    const adminHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const usersResponse = await worker.fetch(request('/api/admin/users', { headers: adminHeaders }), env);
    expect(usersResponse.status).toBe(200);
    const users = await usersResponse.json();
    expect(users.summary).toMatchObject({ total: 1, active: 1, disabled: 0 });
    expect(users.users[0]).toMatchObject({ keyHash: key, accountName: '财务账户', hasVault: true });

    const disabled = await worker.fetch(request(`/api/admin/users/${key}`, {
      method: 'PATCH', headers: adminHeaders, body: JSON.stringify({ status: 'disabled', displayName: '财务专用', adminNote: '交接中' }),
    }), env);
    expect(disabled.status).toBe(200);
    expect((await disabled.json()).user).toMatchObject({ status: 'disabled', displayName: '财务专用', adminNote: '交接中' });
    expect((await worker.fetch(request(`/api/data?key=${key}&account=${encodeURIComponent('财务账户')}`), env)).status).toBe(423);

    await worker.fetch(request(`/api/admin/users/${key}`, {
      method: 'PATCH', headers: adminHeaders, body: JSON.stringify({ status: 'active' }),
    }), env);
    const reset = await worker.fetch(request(`/api/admin/users/${key}/reset`, {
      method: 'POST', headers: adminHeaders, body: JSON.stringify({ confirmation: '重置保险库' }),
    }), env);
    expect(reset.status).toBe(200);
    expect((await reset.json()).user).toMatchObject({ status: 'reset_required', hasVault: false });
    expect(await (await worker.fetch(request(`/api/data?key=${key}`), env)).json()).toMatchObject({ exists: false });

    const restored = await worker.fetch(request(`/api/admin/users/${key}/restore`, {
      method: 'POST', headers: adminHeaders, body: JSON.stringify({ confirmation: '恢复保险库' }),
    }), env);
    expect(restored.status).toBe(200);
    expect((await restored.json()).user).toMatchObject({ status: 'active', hasVault: true });
    expect(await (await worker.fetch(request(`/api/data?key=${key}`), env)).json()).toMatchObject({ exists: true });

    const resetForDelete = await worker.fetch(request(`/api/admin/users/${key}/reset`, {
      method: 'POST', headers: adminHeaders, body: JSON.stringify({ confirmation: '重置保险库' }),
    }), env);
    const { user: resetUser } = await resetForDelete.json();
    expect(resetForDelete.status).toBe(200);
    expect((await worker.fetch(request(`/api/admin/users/${key}`, {
      method: 'DELETE', headers: adminHeaders, body: JSON.stringify({ confirmation: '错误文字' }),
    }), env)).status).toBe(400);

    const deleted = await worker.fetch(request(`/api/admin/users/${key}`, {
      method: 'DELETE', headers: adminHeaders, body: JSON.stringify({ confirmation: '删除用户' }),
    }), env);
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ success: true });
    expect(await env.DATA_KV.get(key)).toBeNull();
    expect(await env.DATA_KV.get(`$user$:${key}`)).toBeNull();
    expect(await env.DATA_KV.get(resetUser.archiveKey)).toBeNull();
    expect((await (await worker.fetch(request('/api/admin/users', { headers: adminHeaders }), env)).json()).summary.total).toBe(0);

    const logs = await worker.fetch(request('/api/admin/logs?action=admin.user.delete', { headers: adminHeaders }), env);
    expect(logs.status).toBe(200);
    expect((await logs.json()).logs[0]).toMatchObject({ action: 'admin.user.delete', result: 'success', targetKey: key });
  });
});
