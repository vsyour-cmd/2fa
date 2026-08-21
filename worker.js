import { createRemoteJWKSet, jwtVerify } from 'jose';
import { VaultCoordinator } from './src/worker/vault-coordinator.js';

export { VaultCoordinator };

const DATA_RATE_LIMIT = 20;
const ADMIN_RATE_LIMIT = 120;
const ADMIN_LOGIN_RATE_LIMIT = 5;
const USER_PREFIX = '$user$:';
const ADMIN_SESSION_PREFIX = '$admin-session$:';
const AUDIT_PREFIX = '$audit$:';
const ARCHIVE_PREFIX = '$vault-archive$:';
const MAX_BODY_BYTES = 256 * 1024;
const ADMIN_SESSION_SECONDS = 30 * 60;
const AUDIT_RETENTION_SECONDS = 90 * 24 * 60 * 60;
const ARCHIVE_RETENTION_SECONDS = 30 * 24 * 60 * 60;
const encoder = new TextEncoder();
const accessJwksByUrl = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) {
      if (url.pathname === '/admin') return Response.redirect(`${url.origin}/admin.html`, 302);
      if (!env.ASSETS) return new Response('Not Found', { status: 404 });
      const response = await env.ASSETS.fetch(request);
      if (url.pathname !== '/admin.html') return response;
      const headers = new Headers(response.headers);
      headers.set('Cache-Control', 'no-store');
      headers.set('X-Frame-Options', 'DENY');
      headers.set('X-Content-Type-Options', 'nosniff');
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }

    try {
      const accessUser = await requireAccessIdentity(request, env, ctx);
      if (url.pathname === '/api/access/me') {
        if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'GET' });
        return jsonResponse({ authenticated: Boolean(accessUser.email), email: accessUser.email || '' }, 200);
      }
      if (url.pathname === '/api/data') return await handleDataRequest(request, url, env, accessUser);
      if (url.pathname === '/api/admin/login') return await handleAdminLoginRequest(request, env, accessUser);
      if (url.pathname.startsWith('/api/admin/')) return await handleAdminRequest(request, url, env, accessUser);
      return jsonResponse({ error: 'Not found' }, 404);
    } catch (error) {
      if (error?.status) return jsonResponse({ error: error.message, ...(error.code ? { code: error.code } : {}) }, error.status);
      console.error(JSON.stringify({ event: 'api_error', method: request.method, path: url.pathname, message: error.message }));
      return jsonResponse({ error: 'Internal error' }, 500);
    }
  },
};

async function handleDataRequest(request, url, env, accessUser) {
  const limited = await checkRateLimit(request, env, {
    limit: DATA_RATE_LIMIT, windowMs: 60_000, namespace: 'data',
  });
  if (limited) return limited;
  if (request.method === 'GET') return handleGet(request, url, env, accessUser);
  if (request.method === 'PUT') return handlePut(request, env, accessUser);
  if (request.method === 'DELETE') return handleDelete(request, url, env, accessUser);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { Allow: 'GET, PUT, DELETE, OPTIONS' } });
  return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'GET, PUT, DELETE, OPTIONS' });
}

async function handleAdminLoginRequest(request, env, accessUser) {
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  const limited = await checkRateLimit(request, env, {
    limit: ADMIN_LOGIN_RATE_LIMIT, windowMs: 10 * 60_000, namespace: 'admin-login',
  });
  if (limited) return limited;
  if (typeof env.ADMIN_PASSWORD !== 'string' || env.ADMIN_PASSWORD.length < 10) {
    return jsonResponse({ error: '管理后台尚未配置', code: 'ADMIN_NOT_CONFIGURED' }, 503);
  }

  const body = await readJsonWithLimit(request, 2048);
  const username = cleanSingleLine(body?.username, 80);
  const password = typeof body?.password === 'string' && body.password.length <= 256 ? body.password : '';
  const expectedUsername = cleanSingleLine(env.ADMIN_USERNAME || 'admin', 80) || 'admin';
  const [usernameValid, passwordValid] = await Promise.all([
    secureEqual(username, expectedUsername),
    secureEqual(password, env.ADMIN_PASSWORD),
  ]);
  const valid = usernameValid && passwordValid;
  if (!valid) {
    await writeAudit(env, request, {
      actor: adminAuditActor(accessUser, username || 'unknown'), action: 'admin.login', result: 'failure', details: '管理员凭据不正确',
    });
    return jsonResponse({ error: '用户名或密码错误' }, 401);
  }

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const session = {
    adminName: expectedUsername,
    accessOwnerId: accessUser.ownerId,
    accessEmail: accessUser.email,
    createdAt: now,
    expiresAt: now + ADMIN_SESSION_SECONDS * 1000,
  };
  await env.DATA_KV.put(`${ADMIN_SESSION_PREFIX}${tokenHash}`, JSON.stringify(session), { expirationTtl: ADMIN_SESSION_SECONDS });
  await writeAudit(env, request, {
    actor: adminAuditActor(accessUser, expectedUsername), action: 'admin.login', result: 'success', details: '管理员登录成功',
  });
  return jsonResponse({ token, adminName: expectedUsername, accessEmail: accessUser.email, expiresAt: session.expiresAt }, 200);
}

async function handleAdminRequest(request, url, env, accessUser) {
  const limited = await checkRateLimit(request, env, {
    limit: ADMIN_RATE_LIMIT, windowMs: 60_000, namespace: 'admin',
  });
  if (limited) return limited;
  const session = await authenticateAdmin(request, env, accessUser);
  if (!session) return jsonResponse({ error: '管理会话已失效，请重新登录' }, 401);

  if (url.pathname === '/api/admin/logout' && request.method === 'POST') {
    await env.DATA_KV.delete(`${ADMIN_SESSION_PREFIX}${session.tokenHash}`);
    await writeAudit(env, request, {
      actor: adminAuditActor(session, session.adminName), action: 'admin.logout', result: 'success', details: '管理员退出登录',
    });
    return jsonResponse({ success: true }, 200);
  }
  if (url.pathname === '/api/admin/users' && request.method === 'GET') return handleAdminUsers(url, env);
  if (url.pathname === '/api/admin/logs' && request.method === 'GET') return handleAdminLogs(url, env);

  const historyRoute = url.pathname.match(/^\/api\/admin\/users\/([a-f0-9]{64})\/history(?:\/([0-9]{1,16})\/restore)?$/i);
  if (historyRoute && !historyRoute[2] && request.method === 'GET') {
    return handleAdminVaultHistory(env, historyRoute[1].toLowerCase());
  }
  if (historyRoute?.[2] && request.method === 'POST') {
    return handleAdminVaultHistoryRestore(
      request,
      env,
      session,
      historyRoute[1].toLowerCase(),
      Number(historyRoute[2]),
    );
  }

  const userRoute = url.pathname.match(/^\/api\/admin\/users\/([a-f0-9]{64})(?:\/(reset|restore))?$/i);
  if (userRoute && !userRoute[2] && request.method === 'PATCH') {
    return handleAdminUserUpdate(request, env, session, userRoute[1].toLowerCase());
  }
  if (userRoute && !userRoute[2] && request.method === 'DELETE') {
    return jsonResponse({ error: '管理后台不提供永久删除用户功能' }, 405, { Allow: 'PATCH' });
  }
  if (userRoute?.[2] === 'reset' && request.method === 'POST') {
    return handleAdminVaultReset(request, env, session, userRoute[1].toLowerCase());
  }
  if (userRoute?.[2] === 'restore' && request.method === 'POST') {
    return handleAdminVaultRestore(request, env, session, userRoute[1].toLowerCase());
  }
  return jsonResponse({ error: 'Not found' }, 404);
}

async function checkRateLimit(request, env, { limit, windowMs, namespace }) {
  const ipHash = await requestSource(request);
  const result = await env.VAULT_COORDINATOR
    .getByName(`rate:${namespace}:${ipHash}`)
    .takeRateLimit(limit, windowMs, Date.now());
  const resetSeconds = Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000));
  const headers = {
    'RateLimit-Limit': String(result.limit),
    'RateLimit-Remaining': String(result.remaining),
    'RateLimit-Reset': String(Math.ceil(result.resetAt / 1000)),
  };
  if (!result.allowed) {
    return jsonResponse({ error: 'Too many requests' }, 429, { ...headers, 'Retry-After': String(resetSeconds) });
  }
  return null;
}

function isValidKey(key) {
  return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
}

function parseVaultRecord(data) {
  if (data === null || data === undefined) return null;
  try {
    const record = typeof data === 'string' ? JSON.parse(data) : data;
    if (!record || typeof record.encryptedData !== 'string' || typeof record.salt !== 'string') return null;
    const updatedAt = Number(record.updatedAt || 0);
    if (!Number.isFinite(updatedAt) || updatedAt <= 0) return null;
    return {
      encryptedData: record.encryptedData,
      salt: record.salt,
      version: Number(record.version || 1),
      updatedAt,
    };
  } catch {
    return null;
  }
}

async function legacyVaultRecord(env, keyHash) {
  return parseVaultRecord(await env.DATA_KV.get(keyHash));
}

function vaultCoordinator(env, keyHash) {
  return env.VAULT_COORDINATOR.getByName(keyHash);
}

function cleanSingleLine(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, maxLength);
}

function cleanNote(value, maxLength = 500) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, maxLength);
}

function accountNameFrom(value) {
  return cleanSingleLine(value, 80);
}

function accountNameFromRequest(request, url) {
  const encoded = request.headers.get('X-Vault-Account') || '';
  if (encoded && /^[A-Za-z0-9_-]{1,512}$/.test(encoded)) {
    try {
      const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(encoded.length / 4) * 4, '=');
      const binary = atob(base64);
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      return accountNameFrom(new TextDecoder().decode(bytes));
    } catch { /* use legacy query fallback */ }
  }
  return accountNameFrom(url.searchParams.get('account'));
}

function accessAudienceMatches(actual, expected) {
  if (typeof actual === 'string') return actual === expected;
  if (Array.isArray(actual)) return actual.includes(expected);
  return false;
}

function accessTeamDomain(env) {
  const raw = cleanSingleLine(env.ACCESS_TEAM_DOMAIN, 512);
  if (!raw) return '';
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return '';
    return url.origin;
  } catch {
    return '';
  }
}

function accessJwks(teamDomain) {
  const url = `${teamDomain}/cdn-cgi/access/certs`;
  if (!accessJwksByUrl.has(url)) accessJwksByUrl.set(url, createRemoteJWKSet(new URL(url)));
  return accessJwksByUrl.get(url);
}

async function verifyAccessJwt(request, env, expectedAudience) {
  const token = request.headers.get('CF-Access-Jwt-Assertion');
  const teamDomain = accessTeamDomain(env);
  if (!token || token.length > 32_768 || !teamDomain) throw new Error('Access JWT fallback unavailable');
  const { payload } = await jwtVerify(token, accessJwks(teamDomain), {
    algorithms: ['RS256'],
    audience: expectedAudience,
    issuer: teamDomain,
  });
  return payload;
}

async function requireAccessIdentity(request, env, ctx) {
  if (env.REQUIRE_ACCESS === 'false' || !env.ACCESS_AUD) {
    // Explicit opt-out is reserved for standalone/local development. Any
    // deployment carrying an Access audience fails closed by default.
    return { email: '', ownerId: '' };
  }
  const expectedAudience = cleanSingleLine(env.ACCESS_AUD, 256);
  if (!expectedAudience) {
    throw httpError('Cloudflare Access 尚未配置', 503, 'ACCESS_NOT_CONFIGURED');
  }
  const access = ctx?.access;
  let identity;
  const usableAccessContext = Boolean(access
    && accessAudienceMatches(access.aud, expectedAudience)
    && typeof access.getIdentity === 'function');
  if (usableAccessContext) {
    try {
      identity = await access.getIdentity();
    } catch (error) {
      console.warn(JSON.stringify({ event: 'access_context_identity_failed', message: error?.message || 'unknown' }));
    }
  }
  if (!identity) {
    try {
      identity = await verifyAccessJwt(request, env, expectedAudience);
      console.info(JSON.stringify({ event: 'access_jwt_fallback_used' }));
    } catch (error) {
      console.warn(JSON.stringify({
        event: 'access_identity_denied',
        hasAccessContext: Boolean(access),
        accessAudienceMatched: Boolean(access && accessAudienceMatches(access.aud, expectedAudience)),
        hasAccessJwt: Boolean(request.headers.get('CF-Access-Jwt-Assertion')),
        message: error?.code || error?.message || 'unknown',
      }));
      throw httpError('Cloudflare Access 身份验证失败', 403, 'ACCESS_DENIED');
    }
  }
  const email = cleanSingleLine(identity?.email, 254).toLocaleLowerCase('en-US');
  const subject = cleanSingleLine(identity?.user_uuid || identity?.sub || identity?.id || email, 512);
  if (!email || !subject) throw httpError('Cloudflare Access 身份信息不完整', 403, 'ACCESS_IDENTITY_INVALID');
  return { email, ownerId: await sha256Hex(`cloudflare-access:${subject}`) };
}

function profileBelongsToAnotherAccessUser(profile, accessUser) {
  if (!accessUser.ownerId) return false;
  return isValidKey(profile?.accessOwnerId) && profile.accessOwnerId.toLowerCase() !== accessUser.ownerId;
}

function accessProfileFields(accessUser) {
  if (!accessUser.ownerId) return {};
  return { accessOwnerId: accessUser.ownerId, accessEmail: accessUser.email };
}

function adminAuditActor(accessUser, adminName) {
  const email = accessUser.accessEmail || accessUser.email || '';
  const label = cleanSingleLine(adminName, 80) || 'admin';
  return email ? `${label} · ${email}` : label;
}

async function accessOwnerDenied(env, request, profile, accessUser, action, keyHash) {
  await writeAudit(env, request, {
    actor: accessUser.email,
    action,
    targetKey: keyHash,
    targetLabel: profile?.accountName || profile?.displayName || '',
    result: 'blocked',
    details: '当前 Cloudflare Access 用户与保险库绑定身份不一致',
  });
  return jsonResponse({ error: '此保险库属于另一个 Cloudflare Access 用户', code: 'ACCESS_OWNER_MISMATCH' }, 403);
}

async function handleGet(request, url, env, accessUser) {
  const key = url.searchParams.get('key');
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  const normalizedKey = key.toLowerCase();
  const profile = await getUserProfile(env, normalizedKey);
  if (profileBelongsToAnotherAccessUser(profile, accessUser)) {
    return accessOwnerDenied(env, request, profile, accessUser, 'vault.access_denied', normalizedKey);
  }
  if (profile?.status === 'disabled') {
    await writeAudit(env, request, {
      actor: accessUser.email, action: 'vault.access_blocked', targetKey: normalizedKey,
      targetLabel: profile.accountName, result: 'blocked', details: '账户已被管理员停用',
    });
    return jsonResponse({ error: '账户已被管理员停用，请联系管理员', code: 'ACCOUNT_DISABLED' }, 423);
  }

  const record = await vaultCoordinator(env, normalizedKey).read(await legacyVaultRecord(env, normalizedKey));
  if (!record) return jsonResponse({ exists: false, data: null }, 200);
  const updatedAt = Number(record.updatedAt || 0);
  const accountName = accountNameFromRequest(request, url);
  const nextProfile = await upsertUserProfile(env, normalizedKey, {
    accountName: accountName || profile?.accountName || '', lastSeenAt: Date.now(), updatedAt, hasVault: true,
    ...accessProfileFields(accessUser),
  });
  await writeAudit(env, request, {
    actor: accessUser.email, action: 'vault.read', targetKey: normalizedKey,
    targetLabel: nextProfile.accountName, result: 'success', details: '读取加密保险库',
  });
  return jsonResponse({ exists: true, data: JSON.stringify(record), updatedAt }, 200);
}

async function handlePut(request, env, accessUser) {
  const declaredLength = Number(request.headers.get('Content-Length') || 0);
  if (declaredLength > MAX_BODY_BYTES) return jsonResponse({ error: 'Payload too large' }, 413);
  const body = await readJsonWithLimit(request);
  const { key, data, salt, version } = body || {};
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  const normalizedKey = key.toLowerCase();
  if (typeof data !== 'string' || data.length <= 16 || data.length > 240_000) return jsonResponse({ error: 'Invalid data' }, 400);
  if (typeof salt !== 'string' || salt.length < 16 || salt.length > 128) return jsonResponse({ error: 'Invalid salt' }, 400);
  if (body.accountName !== undefined && (typeof body.accountName !== 'string' || body.accountName.trim().length > 80)) {
    return jsonResponse({ error: 'Invalid account name' }, 400);
  }
  const expectedUpdatedAt = body.expectedUpdatedAt;
  if (!Number.isSafeInteger(expectedUpdatedAt) || expectedUpdatedAt < 0) {
    return jsonResponse({ error: '请刷新页面后再保存', code: 'VERSION_REQUIRED' }, 428);
  }
  const profile = await getUserProfile(env, normalizedKey);
  if (profileBelongsToAnotherAccessUser(profile, accessUser)) {
    return accessOwnerDenied(env, request, profile, accessUser, 'vault.save_denied', normalizedKey);
  }
  if (profile?.status === 'disabled') {
    await writeAudit(env, request, {
      actor: accessUser.email, action: 'vault.save_blocked', targetKey: normalizedKey,
      targetLabel: profile.accountName, result: 'blocked', details: '账户已被管理员停用',
    });
    return jsonResponse({ error: '账户已被管理员停用，请联系管理员', code: 'ACCOUNT_DISABLED' }, 423);
  }

  const coordinated = await vaultCoordinator(env, normalizedKey).save(
    { encryptedData: data, salt, version: Number(version || 1) },
    expectedUpdatedAt,
    await legacyVaultRecord(env, normalizedKey),
  );
  if (!coordinated.saved) {
    await writeAudit(env, request, {
      actor: accessUser.email, action: 'vault.save_conflict', targetKey: normalizedKey,
      targetLabel: profile?.accountName || '', result: 'blocked', details: '另一设备已更新保险库，拒绝覆盖',
    });
    return jsonResponse({
      error: '另一设备已经更新了云端数据，请先处理同步冲突',
      code: 'VERSION_CONFLICT',
      currentUpdatedAt: coordinated.currentUpdatedAt,
    }, 409);
  }
  const { record } = coordinated;
  const updatedAt = record.updatedAt;
  try {
    await env.DATA_KV.put(normalizedKey, JSON.stringify(record));
  } catch (error) {
    console.error(JSON.stringify({ event: 'vault_kv_mirror_failed', key: normalizedKey, message: error.message }));
  }
  const accountName = accountNameFrom(body.accountName);
  const nextProfile = await upsertUserProfile(env, normalizedKey, {
    accountName: accountName || profile?.accountName || '',
    lastSeenAt: updatedAt,
    updatedAt,
    hasVault: true,
    status: profile?.status === 'reset_required' ? 'active' : (profile?.status || 'active'),
    ...accessProfileFields(accessUser),
  });
  await writeAudit(env, request, {
    actor: accessUser.email, action: 'vault.save', targetKey: normalizedKey,
    targetLabel: nextProfile.accountName, result: 'success', details: `保存加密保险库 v${Number(version || 1)}`,
  });
  return jsonResponse({ success: true, updatedAt }, 200);
}

async function readJsonWithLimit(request, maxBytes = MAX_BODY_BYTES) {
  if (!request.body) throw httpError('Missing body', 400);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw httpError('Payload too large', 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try { return JSON.parse(new TextDecoder().decode(bytes)); } catch { throw httpError('Invalid JSON', 400); }
}

async function handleDelete(request, url, env, accessUser) {
  const key = url.searchParams.get('key');
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  const normalizedKey = key.toLowerCase();
  const expectedUpdatedAtValue = url.searchParams.get('expectedUpdatedAt');
  const expectedUpdatedAt = Number(expectedUpdatedAtValue);
  if (expectedUpdatedAtValue === null || !Number.isSafeInteger(expectedUpdatedAt) || expectedUpdatedAt < 0) {
    return jsonResponse({ error: '删除前必须确认云端版本', code: 'VERSION_REQUIRED' }, 428);
  }
  const profile = await getUserProfile(env, normalizedKey);
  if (profileBelongsToAnotherAccessUser(profile, accessUser)) {
    return accessOwnerDenied(env, request, profile, accessUser, 'vault.delete_denied', normalizedKey);
  }
  const coordinated = await vaultCoordinator(env, normalizedKey).remove(
    expectedUpdatedAt,
    await legacyVaultRecord(env, normalizedKey),
  );
  if (!coordinated.removed) {
    return jsonResponse({
      error: '另一设备已经更新了云端数据，已取消删除',
      code: 'VERSION_CONFLICT',
      currentUpdatedAt: coordinated.currentUpdatedAt,
    }, 409);
  }
  await env.DATA_KV.delete(normalizedKey);
  await env.DATA_KV.delete(`${USER_PREFIX}${normalizedKey}`);
  await writeAudit(env, request, {
    actor: accessUser.email, action: 'vault.delete', targetKey: normalizedKey,
    targetLabel: profile?.accountName || '', result: 'success', details: '删除旧版加密保险库',
  });
  return jsonResponse({ success: true }, 200);
}

async function handleAdminUsers(url, env) {
  const query = cleanSingleLine(url.searchParams.get('query') || '', 100).toLocaleLowerCase();
  const status = cleanSingleLine(url.searchParams.get('status') || '', 30);
  const limit = clampInteger(url.searchParams.get('limit'), 1, 200, 100);
  const offset = clampInteger(url.searchParams.get('offset'), 0, 10_000, 0);
  const [profileEntries, allEntries] = await Promise.all([
    listAllKeys(env.DATA_KV, USER_PREFIX, 5000), listVaultKeys(env.DATA_KV),
  ]);
  const vaultKeys = new Set(allEntries.map((entry) => entry.name).filter(isValidKey));
  const profiles = await hydrateProfiles(env, profileEntries);
  const byKey = new Map(profiles.map((profile) => [profile.keyHash, { ...profile, hasVault: vaultKeys.has(profile.keyHash) }]));

  for (const keyHash of vaultKeys) {
    if (byKey.has(keyHash)) continue;
    const raw = await env.DATA_KV.get(keyHash);
    let updatedAt = 0;
    try { updatedAt = Number(JSON.parse(raw || '{}').updatedAt || 0); } catch { /* anonymous legacy record */ }
    byKey.set(keyHash, defaultProfile(keyHash, { updatedAt, hasVault: true }));
  }

  const allUsers = [...byKey.values()].sort((left, right) => activityTime(right) - activityTime(left));
  const filtered = allUsers.filter((profile) => {
    if (status && profile.status !== status) return false;
    if (!query) return true;
    return [profile.accountName, profile.displayName, profile.accessEmail, profile.adminNote, profile.keyHash]
      .some((value) => String(value || '').toLocaleLowerCase().includes(query));
  });
  const summary = {
    total: allUsers.length,
    active: allUsers.filter((profile) => profile.status === 'active').length,
    disabled: allUsers.filter((profile) => profile.status === 'disabled').length,
    resetRequired: allUsers.filter((profile) => profile.status === 'reset_required').length,
    anonymous: allUsers.filter((profile) => !profile.accountName).length,
  };
  return jsonResponse({
    users: filtered.slice(offset, offset + limit), total: filtered.length, offset, limit,
    hasMore: offset + limit < filtered.length, summary,
  }, 200);
}

async function handleAdminUserUpdate(request, env, session, keyHash) {
  const profile = await getUserOrLegacyProfile(env, keyHash);
  if (!profile) return jsonResponse({ error: '用户不存在' }, 404);
  const body = await readJsonWithLimit(request, 4096);
  const allowedStatuses = new Set(['active', 'disabled', 'reset_required']);
  if (body.status !== undefined && !allowedStatuses.has(body.status)) return jsonResponse({ error: 'Invalid status' }, 400);
  if (body.displayName !== undefined && (typeof body.displayName !== 'string' || body.displayName.length > 80)) {
    return jsonResponse({ error: 'Invalid display name' }, 400);
  }
  if (body.adminNote !== undefined && (typeof body.adminNote !== 'string' || body.adminNote.length > 500)) {
    return jsonResponse({ error: 'Invalid admin note' }, 400);
  }
  const next = await putUserProfile(env, {
    ...profile,
    status: body.status ?? profile.status,
    displayName: body.displayName === undefined ? profile.displayName : cleanSingleLine(body.displayName, 80),
    adminNote: body.adminNote === undefined ? profile.adminNote : cleanNote(body.adminNote),
    updatedAt: Date.now(),
  });
  await writeAudit(env, request, {
    actor: adminAuditActor(session, session.adminName), action: 'admin.user.update', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success', details: `状态：${next.status}；管理信息已更新`,
  });
  return jsonResponse({ success: true, user: next }, 200);
}

async function handleAdminVaultReset(request, env, session, keyHash) {
  const body = await readJsonWithLimit(request, 2048);
  if (body?.confirmation !== '重置保险库') return jsonResponse({ error: '确认文字不正确' }, 400);
  const coordinator = vaultCoordinator(env, keyHash);
  const record = await coordinator.read(await legacyVaultRecord(env, keyHash));
  const profile = await getUserOrLegacyProfile(env, keyHash);
  if (!profile || !record) return jsonResponse({ error: '当前没有可重置的保险库' }, 409);
  const now = Date.now();
  const archiveKey = `${ARCHIVE_PREFIX}${keyHash}:${now}`;
  const archivedUntil = now + ARCHIVE_RETENTION_SECONDS * 1000;
  await env.DATA_KV.put(archiveKey, JSON.stringify({ data: JSON.stringify(record), archivedAt: now, archivedUntil }), { expirationTtl: ARCHIVE_RETENTION_SECONDS });
  const removed = await coordinator.remove(record.updatedAt);
  if (!removed.removed) {
    await env.DATA_KV.delete(archiveKey);
    return jsonResponse({ error: '保险库刚刚发生更新，请刷新后再重置', code: 'VERSION_CONFLICT' }, 409);
  }
  await env.DATA_KV.delete(keyHash);
  const next = await putUserProfile(env, {
    ...profile, status: 'reset_required', hasVault: false, resetAt: now, archiveKey, archivedUntil, updatedAt: now,
  });
  await writeAudit(env, request, {
    actor: adminAuditActor(session, session.adminName), action: 'admin.vault.reset', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success',
    details: '保险库已重置，旧密文保留 30 天，可由管理员恢复',
  });
  return jsonResponse({ success: true, user: next }, 200);
}

async function handleAdminVaultRestore(request, env, session, keyHash) {
  const body = await readJsonWithLimit(request, 2048);
  if (body?.confirmation !== '恢复保险库') return jsonResponse({ error: '确认文字不正确' }, 400);
  const profile = await getUserProfile(env, keyHash);
  if (!profile?.archiveKey) return jsonResponse({ error: '没有可恢复的保险库备份' }, 409);
  const coordinator = vaultCoordinator(env, keyHash);
  if (profile.hasVault || await coordinator.read(await legacyVaultRecord(env, keyHash))) {
    return jsonResponse({ error: '当前保险库已有数据，不能覆盖恢复' }, 409);
  }
  const archived = await env.DATA_KV.get(profile.archiveKey);
  if (archived === null) return jsonResponse({ error: '备份已过期，无法恢复' }, 410);
  let archive;
  try { archive = JSON.parse(archived); } catch { return jsonResponse({ error: '备份已损坏，无法恢复' }, 500); }
  const record = parseVaultRecord(archive.data);
  if (!record) return jsonResponse({ error: '备份已损坏，无法恢复' }, 500);
  await coordinator.replace(record);
  await env.DATA_KV.put(keyHash, JSON.stringify(record));
  await env.DATA_KV.delete(profile.archiveKey);
  const next = await putUserProfile(env, {
    ...profile, status: 'active', hasVault: true, archiveKey: '', archivedUntil: 0, updatedAt: Date.now(),
  });
  await writeAudit(env, request, {
    actor: adminAuditActor(session, session.adminName), action: 'admin.vault.restore', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success', details: '已恢复重置前的加密保险库',
  });
  return jsonResponse({ success: true, user: next }, 200);
}

async function handleAdminVaultHistory(env, keyHash) {
  const profile = await getUserOrLegacyProfile(env, keyHash);
  if (!profile) return jsonResponse({ error: '用户不存在' }, 404);
  const coordinator = vaultCoordinator(env, keyHash);
  const current = await coordinator.read(await legacyVaultRecord(env, keyHash));
  return jsonResponse({
    currentUpdatedAt: Number(current?.updatedAt || 0),
    versions: await coordinator.listHistory(20),
  }, 200);
}

async function handleAdminVaultHistoryRestore(request, env, session, keyHash, historyUpdatedAt) {
  const body = await readJsonWithLimit(request, 2048);
  if (body?.confirmation !== '恢复历史版本') return jsonResponse({ error: '确认文字不正确' }, 400);
  if (!Number.isSafeInteger(historyUpdatedAt) || historyUpdatedAt <= 0) return jsonResponse({ error: '历史版本无效' }, 400);
  const profile = await getUserOrLegacyProfile(env, keyHash);
  if (!profile) return jsonResponse({ error: '用户不存在' }, 404);
  const coordinator = vaultCoordinator(env, keyHash);
  const current = await coordinator.read(await legacyVaultRecord(env, keyHash));
  const restored = await coordinator.restoreHistory(historyUpdatedAt, Number(current?.updatedAt || 0));
  if (!restored.restored) {
    if (restored.reason === 'conflict') {
      return jsonResponse({ error: '保险库刚刚发生更新，请刷新历史版本后重试', code: 'VERSION_CONFLICT' }, 409);
    }
    return jsonResponse({ error: '历史版本不存在或已被轮换清理' }, 404);
  }
  await env.DATA_KV.put(keyHash, JSON.stringify(restored.record));
  const next = await putUserProfile(env, {
    ...profile,
    status: 'active',
    hasVault: true,
    archiveKey: '',
    archivedUntil: 0,
    updatedAt: restored.record.updatedAt,
    lastSeenAt: restored.record.updatedAt,
  });
  await writeAudit(env, request, {
    actor: adminAuditActor(session, session.adminName), action: 'admin.vault.history_restore', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success',
    details: `恢复加密历史版本 ${historyUpdatedAt}；恢复前版本已自动保留`,
  });
  return jsonResponse({ success: true, updatedAt: restored.record.updatedAt, user: next }, 200);
}

async function handleAdminLogs(url, env) {
  const query = cleanSingleLine(url.searchParams.get('query') || '', 100).toLocaleLowerCase();
  const action = cleanSingleLine(url.searchParams.get('action') || '', 80);
  const result = cleanSingleLine(url.searchParams.get('result') || '', 30);
  const limit = clampInteger(url.searchParams.get('limit'), 1, 200, 100);
  const entries = await listAllKeys(env.DATA_KV, AUDIT_PREFIX, 5000);
  const logs = [];
  for (let index = 0; index < entries.length; index += 50) {
    const values = await Promise.all(entries.slice(index, index + 50).map((entry) => env.DATA_KV.get(entry.name)));
    for (const value of values) {
      try { if (value) logs.push(JSON.parse(value)); } catch { /* ignore malformed audit entries */ }
    }
  }
  const filtered = logs
    .filter((entry) => (!action || entry.action === action) && (!result || entry.result === result))
    .filter((entry) => !query || [entry.actor, entry.action, entry.targetLabel, entry.targetKey, entry.details, entry.ipAddress, entry.source]
      .some((value) => String(value || '').toLocaleLowerCase().includes(query)))
    .sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0));
  return jsonResponse({ logs: filtered.slice(0, limit), total: filtered.length, limit, scanned: logs.length }, 200);
}

function defaultProfile(keyHash, overrides = {}) {
  const now = Date.now();
  return {
    keyHash,
    accountName: '', displayName: '', status: 'active', adminNote: '', accessOwnerId: '', accessEmail: '',
    createdAt: Number(overrides.createdAt || now), updatedAt: Number(overrides.updatedAt || 0),
    lastSeenAt: Number(overrides.lastSeenAt || 0), hasVault: overrides.hasVault !== false,
    resetAt: Number(overrides.resetAt || 0), archiveKey: String(overrides.archiveKey || ''),
    archivedUntil: Number(overrides.archivedUntil || 0), ...overrides,
  };
}

async function getUserProfile(env, keyHash) {
  const raw = await env.DATA_KV.get(`${USER_PREFIX}${keyHash}`);
  if (!raw) return null;
  try { return { ...defaultProfile(keyHash), ...JSON.parse(raw), keyHash }; } catch { return null; }
}

async function getUserOrLegacyProfile(env, keyHash) {
  const profile = await getUserProfile(env, keyHash);
  if (profile) return profile;
  const data = await env.DATA_KV.get(keyHash);
  if (data === null) return null;
  let updatedAt = 0;
  try { updatedAt = Number(JSON.parse(data).updatedAt || 0); } catch { /* legacy record */ }
  return defaultProfile(keyHash, { updatedAt, hasVault: true });
}

async function upsertUserProfile(env, keyHash, changes) {
  const current = await getUserProfile(env, keyHash);
  const profile = defaultProfile(keyHash, { ...(current || {}), ...changes, keyHash });
  if (current?.createdAt) profile.createdAt = current.createdAt;
  return putUserProfile(env, profile);
}

async function putUserProfile(env, profile) {
  const normalized = defaultProfile(profile.keyHash, {
    ...profile,
    accountName: accountNameFrom(profile.accountName),
    displayName: cleanSingleLine(profile.displayName, 80),
    adminNote: cleanNote(profile.adminNote),
    accessOwnerId: isValidKey(profile.accessOwnerId) ? profile.accessOwnerId.toLowerCase() : '',
    accessEmail: cleanSingleLine(profile.accessEmail, 254).toLocaleLowerCase('en-US'),
  });
  await env.DATA_KV.put(`${USER_PREFIX}${normalized.keyHash}`, JSON.stringify(normalized));
  return normalized;
}

async function hydrateProfiles(env, entries) {
  const profiles = [];
  for (let index = 0; index < entries.length; index += 50) {
    const chunk = entries.slice(index, index + 50);
    const values = await Promise.all(chunk.map(async (entry) => {
      if (entry.metadata && typeof entry.metadata === 'object') return entry.metadata;
      const raw = await env.DATA_KV.get(entry.name);
      try { return raw ? JSON.parse(raw) : null; } catch { return null; }
    }));
    for (let offset = 0; offset < values.length; offset += 1) {
      const value = values[offset];
      const keyHash = chunk[offset].name.slice(USER_PREFIX.length);
      if (value && isValidKey(keyHash)) profiles.push({ ...defaultProfile(keyHash), ...value, keyHash });
    }
  }
  return profiles;
}

async function listAllKeys(kv, prefix, maximum) {
  const entries = [];
  let cursor;
  do {
    const page = await kv.list({ prefix, limit: Math.min(1000, maximum - entries.length), ...(cursor ? { cursor } : {}) });
    entries.push(...page.keys);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && entries.length < maximum);
  return entries;
}

async function listVaultKeys(kv) {
  const pages = await Promise.all('0123456789abcdef'.split('').map((prefix) => listAllKeys(kv, prefix, 5000)));
  return pages.flat().filter((entry) => isValidKey(entry.name));
}

function activityTime(profile) {
  return Number(profile.lastSeenAt || profile.updatedAt || profile.createdAt || 0);
}

function clampInteger(value, minimum, maximum, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, parsed));
}

async function authenticateAdmin(request, env, accessUser) {
  const authorization = request.headers.get('Authorization') || '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{40,128})$/);
  if (!match) return null;
  const tokenHash = await sha256Hex(match[1]);
  const raw = await env.DATA_KV.get(`${ADMIN_SESSION_PREFIX}${tokenHash}`);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw);
    if (Number(session.expiresAt || 0) <= Date.now()) {
      await env.DATA_KV.delete(`${ADMIN_SESSION_PREFIX}${tokenHash}`);
      return null;
    }
    if (accessUser.ownerId && (!isValidKey(session.accessOwnerId) || session.accessOwnerId.toLowerCase() !== accessUser.ownerId)) return null;
    return { ...session, tokenHash };
  } catch { return null; }
}

async function writeAudit(env, request, event) {
  try {
    await persistAudit(env, request, event);
  } catch (error) {
    console.error(JSON.stringify({ event: 'audit_write_error', action: cleanSingleLine(event?.action, 80), message: error.message }));
  }
}

async function persistAudit(env, request, event) {
  const timestamp = Date.now();
  const entry = {
    id: crypto.randomUUID(), timestamp,
    actor: cleanSingleLine(event.actor || 'system', 254) || 'system',
    action: cleanSingleLine(event.action, 80),
    targetKey: isValidKey(event.targetKey) ? event.targetKey.toLowerCase() : '',
    targetLabel: cleanSingleLine(event.targetLabel, 80),
    result: cleanSingleLine(event.result || 'success', 30),
    details: cleanNote(event.details || '', 300),
    ipAddress: requestIp(request),
    source: await requestSource(request),
  };
  const reverseTimestamp = String(9_999_999_999_999 - timestamp).padStart(13, '0');
  const key = `${AUDIT_PREFIX}${reverseTimestamp}:${entry.id}`;
  await env.DATA_KV.put(key, JSON.stringify(entry), { expirationTtl: AUDIT_RETENTION_SECONDS });
}

async function requestSource(request) {
  const ip = requestIp(request) || 'unknown';
  return (await sha256Hex(ip)).slice(0, 12);
}

function requestIp(request) {
  return cleanSingleLine(request.headers.get('CF-Connecting-IP') || '', 80);
}

async function secureEqual(left, right) {
  const [leftDigest, rightDigest] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(String(left))),
    crypto.subtle.digest('SHA-256', encoder.encode(String(right))),
  ]);
  if (typeof crypto.subtle.timingSafeEqual === 'function') {
    return crypto.subtle.timingSafeEqual(leftDigest, rightDigest);
  }
  const leftBytes = new Uint8Array(leftDigest);
  const rightBytes = new Uint8Array(rightDigest);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) difference |= leftBytes[index] ^ rightBytes[index];
  return difference === 0;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(String(value)));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function httpError(message, status, code = '') {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function jsonResponse(data, status, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', ...extraHeaders,
    },
  });
}
