import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const key = 'd'.repeat(64);
const data = 'encrypted-admin-test-payload-longer-than-sixteen-characters';
const salt = '0123456789abcdef';
const dbPath = join(tmpdir(), `2fa-admin-api-${process.pid}-${randomUUID()}.db`);

let db;
let server;
let baseUrl;

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const body = await response.json();
  return { response, body };
}

beforeAll(async () => {
  vi.stubEnv('DB_PATH', dbPath);
  vi.stubEnv('ADMIN_USERNAME', 'admin');
  vi.stubEnv('ADMIN_PASSWORD', 'strong-admin-password');
  const imported = await import('../src/server.js');
  const exported = imported.default || imported;
  db = exported.db;
  server = createServer(exported.app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
  if (db?.open) db.close();
  await rm(dbPath, { force: true });
  vi.unstubAllEnvs();
});

describe('Express admin API', () => {
  it('authenticates separately and manages a recoverable user vault reset', async () => {
    const stored = await request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, data, salt, version: 3, accountName: '运营账户' }),
    });
    expect(stored.response.status).toBe(200);

    const failedLogin = await request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
    });
    expect(failedLogin.response.status).toBe(401);
    expect(failedLogin.body).toEqual({ error: '用户名或密码错误' });

    const login = await request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'strong-admin-password' }),
    });
    expect(login.response.status).toBe(200);
    expect(login.body.token).toEqual(expect.any(String));
    const headers = { Authorization: `Bearer ${login.body.token}`, 'Content-Type': 'application/json' };

    const users = await request('/api/admin/users', { headers });
    expect(users.response.status).toBe(200);
    expect(users.body.summary).toMatchObject({ total: 1, active: 1, disabled: 0 });
    expect(users.body.users[0]).toMatchObject({ keyHash: key, accountName: '运营账户', hasVault: true });

    const disabled = await request(`/api/admin/users/${key}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ status: 'disabled', displayName: '运营专用', adminNote: '离职交接' }),
    });
    expect(disabled.response.status).toBe(200);
    expect(disabled.body.user).toMatchObject({ status: 'disabled', displayName: '运营专用', adminNote: '离职交接' });
    expect((await request(`/api/data?key=${key}`)).response.status).toBe(423);

    await request(`/api/admin/users/${key}`, {
      method: 'PATCH', headers, body: JSON.stringify({ status: 'active' }),
    });
    const reset = await request(`/api/admin/users/${key}/reset`, {
      method: 'POST', headers, body: JSON.stringify({ confirmation: '重置保险库' }),
    });
    expect(reset.response.status).toBe(200);
    expect(reset.body.user).toMatchObject({ status: 'reset_required', hasVault: false });
    expect((await request(`/api/data?key=${key}`)).body).toMatchObject({ exists: false });

    const restored = await request(`/api/admin/users/${key}/restore`, {
      method: 'POST', headers, body: JSON.stringify({ confirmation: '恢复保险库' }),
    });
    expect(restored.response.status).toBe(200);
    expect(restored.body.user).toMatchObject({ status: 'active', hasVault: true });
    expect((await request(`/api/data?key=${key}`)).body).toMatchObject({ exists: true });

    const logs = await request('/api/admin/logs?action=admin.vault.restore', { headers });
    expect(logs.response.status).toBe(200);
    expect(logs.body.logs[0]).toMatchObject({ action: 'admin.vault.restore', result: 'success', targetKey: key });
  });

  it('rejects missing or invalid admin sessions', async () => {
    expect((await request('/api/admin/users')).response.status).toBe(401);
    expect((await request('/api/admin/users', { headers: { Authorization: 'Bearer invalid-token' } })).response.status).toBe(401);
  });
});
