import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import Database from 'better-sqlite3';

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
  vi.stubEnv('ACCESS_DEV_EMAIL', 'developer@example.test');
  const legacyDb = new Database(dbPath);
  legacyDb.exec(`
    CREATE TABLE audit_logs (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      target_key TEXT NOT NULL DEFAULT '',
      target_label TEXT NOT NULL DEFAULT '',
      result TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT ''
    )
  `);
  legacyDb.close();
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
  it('provides an explicit local-development Access identity without changing vault encryption', async () => {
    const identity = await request('/api/access/me');
    expect(identity.response.status).toBe(200);
    expect(identity.body).toEqual({ authenticated: true, email: 'developer@example.test' });
  });

  it('authenticates separately and manages a recoverable user vault reset', async () => {
    expect(db.prepare('PRAGMA table_info(audit_logs)').all().map((column) => column.name)).toContain('ip_address');
    const stored = await request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, data, salt, version: 3, accountName: '运营账户', expectedUpdatedAt: 0 }),
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

    const beforeHistorySave = await request(`/api/data?key=${key}`);
    const historySave = await request('/api/data', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
        key,
        data: 'newer-encrypted-payload-long-enough',
        salt,
        version: 3,
        accountName: '运营账户',
        expectedUpdatedAt: beforeHistorySave.body.updatedAt,
      }),
    });
    expect(historySave.response.status).toBe(200);
    const history = await request(`/api/admin/users/${key}/history`, { headers });
    expect(history.response.status).toBe(200);
    expect(history.body.versions).toEqual(expect.arrayContaining([
      expect.objectContaining({ updatedAt: beforeHistorySave.body.updatedAt, version: 3 }),
    ]));
    const historyRestore = await request(`/api/admin/users/${key}/history/${beforeHistorySave.body.updatedAt}/restore`, {
      method: 'POST', headers, body: JSON.stringify({ confirmation: '恢复历史版本' }),
    });
    expect(historyRestore.response.status).toBe(200);
    const afterHistoryRestore = await request(`/api/data?key=${key}`);
    expect(JSON.parse(afterHistoryRestore.body.data).encryptedData).toBe(data);

    const resetForDelete = await request(`/api/admin/users/${key}/reset`, {
      method: 'POST', headers, body: JSON.stringify({ confirmation: '重置保险库' }),
    });
    expect(resetForDelete.response.status).toBe(200);
    const archiveKey = resetForDelete.body.user.archiveKey;
    expect(db.prepare('SELECT 1 FROM vault_archives WHERE id = ?').get(archiveKey)).toBeTruthy();

    const deleted = await request(`/api/admin/users/${key}`, {
      method: 'DELETE', headers, body: JSON.stringify({ confirmation: '删除用户' }),
    });
    expect(deleted.response.status).toBe(405);
    expect(deleted.body).toEqual({ error: '管理后台不提供永久删除用户功能' });
    expect(db.prepare('SELECT 1 FROM data_store WHERE key = ?').get(key)).toBeUndefined();
    expect(db.prepare('SELECT 1 FROM user_profiles WHERE key = ?').get(key)).toBeTruthy();
    expect(db.prepare('SELECT 1 FROM vault_archives WHERE key = ?').get(key)).toBeTruthy();
    expect((await request('/api/admin/users', { headers })).body.summary.total).toBe(1);
  });

  it('rejects missing or invalid admin sessions', async () => {
    expect((await request('/api/admin/users')).response.status).toBe(401);
    expect((await request('/api/admin/users', { headers: { Authorization: 'Bearer invalid-token' } })).response.status).toBe(401);
  });
});
