import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import worker, { VaultCoordinator } from '../worker.js';

const ACCESS_AUD = 'ec0202c941bf8f8a55c97d07071a01df8de0f57ad288a178e4daab58b4338274';
const wranglerConfig = JSON.parse(await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));

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

class FakeDoStorage {
  constructor() {
    this.values = new Map();
  }

  async get(key) { return this.values.get(key); }

  async put(key, value) { this.values.set(key, value); }

  async delete(key) { this.values.delete(key); }
}

class FakeVaultCoordinatorNamespace {
  constructor() {
    this.instances = new Map();
  }

  getByName(name) {
    if (!this.instances.has(name)) {
      const state = { storage: new FakeDoStorage() };
      this.instances.set(name, { object: new VaultCoordinator(state, {}), tail: Promise.resolve() });
    }
    const instance = this.instances.get(name);
    const invoke = (method) => (...args) => {
      const result = instance.tail.then(() => instance.object[method](...args));
      instance.tail = result.catch(() => {});
      return result;
    };
    return {
      read: invoke('read'),
      save: invoke('save'),
      replace: invoke('replace'),
      remove: invoke('remove'),
    };
  }
}

const coordinatorNamespaces = new WeakMap();

function coordinatorFor(env) {
  if (!coordinatorNamespaces.has(env)) coordinatorNamespaces.set(env, new FakeVaultCoordinatorNamespace());
  return coordinatorNamespaces.get(env);
}

function request(path, init = {}) {
  return new Request(`https://example.test${path}`, {
    ...init,
    headers: { 'CF-Connecting-IP': '203.0.113.10', ...(init.headers || {}) },
  });
}

function accessContext(email = 'owner@example.com', userId = 'access-user-1', aud = ACCESS_AUD) {
  return { access: { aud, getIdentity: async () => ({ email, user_uuid: userId }) } };
}

function fetchWorker(req, env, ctx = accessContext()) {
  return worker.fetch(req, { ACCESS_AUD, VAULT_COORDINATOR: coordinatorFor(env), ...env }, ctx);
}

describe('Cloudflare Worker API', () => {
  it('keeps the Worker Access audience and local identity simulation in Wrangler configuration', () => {
    expect(wranglerConfig.vars.ACCESS_AUD).toBe(ACCESS_AUD);
    expect(wranglerConfig.access.dev).toMatchObject({
      aud: ACCESS_AUD,
      identity: { email: 'developer@example.invalid', user_uuid: 'local-cloudflare-access-user' },
    });
    expect(wranglerConfig.durable_objects.bindings).toContainEqual({
      name: 'VAULT_COORDINATOR', class_name: 'VaultCoordinator',
    });
    expect(wranglerConfig.migrations).toContainEqual({
      tag: 'v1-vault-coordinator', new_sqlite_classes: ['VaultCoordinator'],
    });
  });

  it('keeps Access enforcement opt-in and exposes the verified email only when required', async () => {
    const env = { DATA_KV: new FakeKv(), ACCESS_AUD };
    const anonymous = await worker.fetch(request('/api/access/me'), env, {});
    expect(anonymous.status).toBe(200);
    expect(await anonymous.json()).toEqual({ authenticated: false, email: '' });

    const enforcedEnv = { ...env, REQUIRE_ACCESS: 'true' };
    const missing = await worker.fetch(request('/api/access/me'), enforcedEnv, {});
    expect(missing.status).toBe(403);
    expect(await missing.json()).toMatchObject({ code: 'ACCESS_DENIED' });

    const wrongAudience = await worker.fetch(request('/api/access/me'), enforcedEnv, accessContext('owner@example.com', 'owner-1', 'wrong-aud'));
    expect(wrongAudience.status).toBe(403);
    expect(await wrongAudience.json()).toMatchObject({ code: 'ACCESS_DENIED' });

    const verified = await worker.fetch(request('/api/access/me'), enforcedEnv, accessContext('Owner@Example.com', 'owner-1'));
    expect(verified.status).toBe(200);
    expect(await verified.json()).toEqual({ authenticated: true, email: 'owner@example.com' });
  });

  it('binds a legacy vault to its first verified Access user and blocks other Access users', async () => {
    const env = { DATA_KV: new FakeKv(), REQUIRE_ACCESS: 'true' };
    const key = 'e'.repeat(64);
    await env.DATA_KV.put(key, JSON.stringify({
      encryptedData: 'legacy-encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3, updatedAt: 123,
    }));

    const ownerContext = accessContext('owner@example.com', 'owner-1');
    const firstRead = await fetchWorker(request(`/api/data?key=${key}`, {
      headers: { 'X-Vault-Account': '5Liq5Lq65L-d6Zmp5bqT' },
    }), env, ownerContext);
    expect(firstRead.status).toBe(200);
    expect(await firstRead.json()).toMatchObject({ exists: true, updatedAt: 123 });

    const profile = JSON.parse(await env.DATA_KV.get(`$user$:${key}`));
    expect(profile).toMatchObject({ accessEmail: 'owner@example.com', hasVault: true });
    expect(profile.accessOwnerId).toMatch(/^[a-f0-9]{64}$/);

    const migratedSave = await fetchWorker(request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key,
        data: 'migrated-encrypted-payload-long-enough',
        salt: 'base64-salt-value',
        version: 3,
        expectedUpdatedAt: 123,
      }),
    }), env, ownerContext);
    expect(migratedSave.status).toBe(200);

    const otherContext = accessContext('other@example.com', 'owner-2');
    const blocked = await fetchWorker(request(`/api/data?key=${key}`), env, otherContext);
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ code: 'ACCESS_OWNER_MISMATCH' });
    expect((await fetchWorker(request(`/api/data?key=${key}`), env, ownerContext)).status).toBe(200);

    const audits = [...env.DATA_KV.values.entries()]
      .filter(([auditKey]) => auditKey.startsWith('$audit$:'))
      .map(([, value]) => JSON.parse(value));
    expect(audits).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor: 'owner@example.com', action: 'vault.read', result: 'success' }),
      expect.objectContaining({ actor: 'other@example.com', action: 'vault.access_denied', result: 'blocked' }),
    ]));
  });

  it('stores, reads, and deletes encrypted records', async () => {
    const env = { DATA_KV: new FakeKv() };
    const key = 'a'.repeat(64);
    const body = JSON.stringify({
      key, data: 'encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3, expectedUpdatedAt: 0,
    });
    const put = await fetchWorker(request('/api/data', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body }), env);
    expect(put.status).toBe(200);
    expect(await put.json()).toMatchObject({ success: true });

    const get = await fetchWorker(request(`/api/data?key=${key}`), env);
    const record = await get.json();
    expect(record.exists).toBe(true);
    expect(JSON.parse(record.data)).toMatchObject({ encryptedData: 'encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3 });

    expect((await fetchWorker(request(`/api/data?key=${key}`, { method: 'DELETE' }), env)).status).toBe(428);
    const staleDelete = await fetchWorker(request(`/api/data?key=${key}&expectedUpdatedAt=0`, { method: 'DELETE' }), env);
    expect(staleDelete.status).toBe(409);
    expect(await staleDelete.json()).toMatchObject({ code: 'VERSION_CONFLICT' });
    expect((await fetchWorker(request(`/api/data?key=${key}&expectedUpdatedAt=${record.updatedAt}`, { method: 'DELETE' }), env)).status).toBe(200);
    expect(await (await fetchWorker(request(`/api/data?key=${key}`), env)).json()).toMatchObject({ exists: false });
  });

  it('allows only one save when two devices write the same cloud version', async () => {
    const env = { DATA_KV: new FakeKv() };
    const key = 'd'.repeat(64);
    const initial = await fetchWorker(request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key, data: 'initial-encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3, expectedUpdatedAt: 0,
      }),
    }), env);
    const initialBody = await initial.json();

    const save = (data) => fetchWorker(request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, data, salt: 'base64-salt-value', version: 3, expectedUpdatedAt: initialBody.updatedAt }),
    }), env);
    const results = await Promise.all([
      save('device-one-encrypted-payload-long-enough'),
      save('device-two-encrypted-payload-long-enough'),
    ]);
    expect(results.map((response) => response.status).sort()).toEqual([200, 409]);
    const conflict = results.find((response) => response.status === 409);
    expect(await conflict.json()).toMatchObject({ code: 'VERSION_CONFLICT' });

    const stored = await (await fetchWorker(request(`/api/data?key=${key}`), env)).json();
    expect([
      'device-one-encrypted-payload-long-enough',
      'device-two-encrypted-payload-long-enough',
    ]).toContain(JSON.parse(stored.data).encryptedData);
  });

  it('rejects invalid and oversized requests', async () => {
    const env = { DATA_KV: new FakeKv() };
    expect((await fetchWorker(request('/api/data?key=bad'), env)).status).toBe(400);
    const missingVersion = await fetchWorker(request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: 'f'.repeat(64), data: 'encrypted-payload-long-enough', salt: 'base64-salt-value', version: 3,
      }),
    }), env);
    expect(missingVersion.status).toBe(428);
    expect(await missingVersion.json()).toMatchObject({ code: 'VERSION_REQUIRED' });
    const oversized = await fetchWorker(request('/api/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(300 * 1024) },
      body: '{}',
    }), env);
    expect(oversized.status).toBe(413);
  });

  it('limits one IP to 20 API requests per minute', async () => {
    const env = { DATA_KV: new FakeKv() };
    for (let index = 0; index < 20; index += 1) {
      const response = await fetchWorker(request(`/api/data?key=${'b'.repeat(64)}`), env);
      expect(response.status).toBe(200);
    }
    const blocked = await fetchWorker(request(`/api/data?key=${'b'.repeat(64)}`), env);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('Retry-After')).toBeTruthy();
  });

  it('keeps the admin console closed until a password secret is configured', async () => {
    const env = { DATA_KV: new FakeKv() };
    const response = await fetchWorker(request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'not-configured' }),
    }), env);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ code: 'ADMIN_NOT_CONFIGURED' });
  });

  it('manages users, recoverable resets, and audit logs through authenticated admin APIs', async () => {
    const env = { DATA_KV: new FakeKv(), REQUIRE_ACCESS: 'true', ADMIN_PASSWORD: 'strong-admin-password', ADMIN_USERNAME: 'admin' };
    const key = 'c'.repeat(64);
    const vaultBody = JSON.stringify({
      key,
      data: 'encrypted-payload-long-enough',
      salt: 'base64-salt-value',
      version: 3,
      accountName: '财务账户',
      expectedUpdatedAt: 0,
    });
    expect((await fetchWorker(request('/api/data', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: vaultBody,
    }), env)).status).toBe(200);

    const failedLogin = await fetchWorker(request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
    }), env);
    expect(failedLogin.status).toBe(401);

    const login = await fetchWorker(request('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'strong-admin-password' }),
    }), env);
    expect(login.status).toBe(200);
    const loginPayload = await login.json();
    expect(loginPayload.accessEmail).toBe('owner@example.com');
    const { token } = loginPayload;
    const adminHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const usersResponse = await fetchWorker(request('/api/admin/users', { headers: adminHeaders }), env);
    expect(usersResponse.status).toBe(200);
    const users = await usersResponse.json();
    expect(users.summary).toMatchObject({ total: 1, active: 1, disabled: 0 });
    expect(users.users[0]).toMatchObject({ keyHash: key, accountName: '财务账户', hasVault: true });
    expect(users.users[0]).toMatchObject({ accessEmail: 'owner@example.com' });

    const otherAccessUser = await fetchWorker(request('/api/admin/users', { headers: adminHeaders }), env, accessContext('other@example.com', 'access-user-2'));
    expect(otherAccessUser.status).toBe(401);

    const disabled = await fetchWorker(request(`/api/admin/users/${key}`, {
      method: 'PATCH', headers: adminHeaders, body: JSON.stringify({ status: 'disabled', displayName: '财务专用', adminNote: '交接中' }),
    }), env);
    expect(disabled.status).toBe(200);
    expect((await disabled.json()).user).toMatchObject({ status: 'disabled', displayName: '财务专用', adminNote: '交接中' });
    expect((await fetchWorker(request(`/api/data?key=${key}&account=${encodeURIComponent('财务账户')}`), env)).status).toBe(423);

    await fetchWorker(request(`/api/admin/users/${key}`, {
      method: 'PATCH', headers: adminHeaders, body: JSON.stringify({ status: 'active' }),
    }), env);
    const reset = await fetchWorker(request(`/api/admin/users/${key}/reset`, {
      method: 'POST', headers: adminHeaders, body: JSON.stringify({ confirmation: '重置保险库' }),
    }), env);
    expect(reset.status).toBe(200);
    expect((await reset.json()).user).toMatchObject({ status: 'reset_required', hasVault: false });
    expect(await (await fetchWorker(request(`/api/data?key=${key}`), env)).json()).toMatchObject({ exists: false });

    const restored = await fetchWorker(request(`/api/admin/users/${key}/restore`, {
      method: 'POST', headers: adminHeaders, body: JSON.stringify({ confirmation: '恢复保险库' }),
    }), env);
    expect(restored.status).toBe(200);
    expect((await restored.json()).user).toMatchObject({ status: 'active', hasVault: true });
    expect(await (await fetchWorker(request(`/api/data?key=${key}`), env)).json()).toMatchObject({ exists: true });

    const resetForDelete = await fetchWorker(request(`/api/admin/users/${key}/reset`, {
      method: 'POST', headers: adminHeaders, body: JSON.stringify({ confirmation: '重置保险库' }),
    }), env);
    const { user: resetUser } = await resetForDelete.json();
    expect(resetForDelete.status).toBe(200);
    const deleted = await fetchWorker(request(`/api/admin/users/${key}`, {
      method: 'DELETE', headers: adminHeaders, body: JSON.stringify({ confirmation: '删除用户' }),
    }), env);
    expect(deleted.status).toBe(405);
    expect(await deleted.json()).toEqual({ error: '管理后台不提供永久删除用户功能' });
    expect(await env.DATA_KV.get(key)).toBeNull();
    expect(await env.DATA_KV.get(`$user$:${key}`)).not.toBeNull();
    expect(await env.DATA_KV.get(resetUser.archiveKey)).not.toBeNull();
    expect((await (await fetchWorker(request('/api/admin/users', { headers: adminHeaders }), env)).json()).summary.total).toBe(1);
  });
});
