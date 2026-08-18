const DATA_RATE_LIMIT = 20;
const ADMIN_RATE_LIMIT = 120;
const ADMIN_LOGIN_RATE_LIMIT = 5;
const RATE_PREFIX = '$ratelimit$:';
const USER_PREFIX = '$user$:';
const ADMIN_SESSION_PREFIX = '$admin-session$:';
const AUDIT_PREFIX = '$audit$:';
const ARCHIVE_PREFIX = '$vault-archive$:';
const MAX_BODY_BYTES = 256 * 1024;
const ADMIN_SESSION_SECONDS = 30 * 60;
const AUDIT_RETENTION_SECONDS = 90 * 24 * 60 * 60;
const ARCHIVE_RETENTION_SECONDS = 30 * 24 * 60 * 60;
const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
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
      if (url.pathname === '/api/data') return handleDataRequest(request, url, env);
      if (url.pathname === '/api/admin/login') return handleAdminLoginRequest(request, env);
      if (url.pathname.startsWith('/api/admin/')) return handleAdminRequest(request, url, env);
      return jsonResponse({ error: 'Not found' }, 404);
    } catch (error) {
      if (error?.status) return jsonResponse({ error: error.message }, error.status);
      console.error(JSON.stringify({ event: 'api_error', method: request.method, path: url.pathname, message: error.message }));
      return jsonResponse({ error: 'Internal error' }, 500);
    }
  },
};

async function handleDataRequest(request, url, env) {
  const limited = await checkRateLimit(request, env.DATA_KV, {
    limit: DATA_RATE_LIMIT, windowMs: 60_000, namespace: 'data',
  });
  if (limited) return limited;
  if (request.method === 'GET') return handleGet(request, url, env);
  if (request.method === 'PUT') return handlePut(request, env);
  if (request.method === 'DELETE') return handleDelete(request, url, env);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { Allow: 'GET, PUT, DELETE, OPTIONS' } });
  return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'GET, PUT, DELETE, OPTIONS' });
}

async function handleAdminLoginRequest(request, env) {
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  const limited = await checkRateLimit(request, env.DATA_KV, {
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
      actor: username || 'unknown', action: 'admin.login', result: 'failure', details: '管理员凭据不正确',
    });
    return jsonResponse({ error: '用户名或密码错误' }, 401);
  }

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const session = { adminName: expectedUsername, createdAt: now, expiresAt: now + ADMIN_SESSION_SECONDS * 1000 };
  await env.DATA_KV.put(`${ADMIN_SESSION_PREFIX}${tokenHash}`, JSON.stringify(session), { expirationTtl: ADMIN_SESSION_SECONDS });
  await writeAudit(env, request, {
    actor: expectedUsername, action: 'admin.login', result: 'success', details: '管理员登录成功',
  });
  return jsonResponse({ token, adminName: expectedUsername, expiresAt: session.expiresAt }, 200);
}

async function handleAdminRequest(request, url, env) {
  const limited = await checkRateLimit(request, env.DATA_KV, {
    limit: ADMIN_RATE_LIMIT, windowMs: 60_000, namespace: 'admin',
  });
  if (limited) return limited;
  const session = await authenticateAdmin(request, env);
  if (!session) return jsonResponse({ error: '管理会话已失效，请重新登录' }, 401);

  if (url.pathname === '/api/admin/logout' && request.method === 'POST') {
    await env.DATA_KV.delete(`${ADMIN_SESSION_PREFIX}${session.tokenHash}`);
    await writeAudit(env, request, {
      actor: session.adminName, action: 'admin.logout', result: 'success', details: '管理员退出登录',
    });
    return jsonResponse({ success: true }, 200);
  }
  if (url.pathname === '/api/admin/users' && request.method === 'GET') return handleAdminUsers(url, env);
  if (url.pathname === '/api/admin/logs' && request.method === 'GET') return handleAdminLogs(url, env);

  const userRoute = url.pathname.match(/^\/api\/admin\/users\/([a-f0-9]{64})(?:\/(reset|restore))?$/i);
  if (userRoute && !userRoute[2] && request.method === 'PATCH') {
    return handleAdminUserUpdate(request, env, session, userRoute[1].toLowerCase());
  }
  if (userRoute && !userRoute[2] && request.method === 'DELETE') {
    return handleAdminUserDelete(request, env, session, userRoute[1].toLowerCase());
  }
  if (userRoute?.[2] === 'reset' && request.method === 'POST') {
    return handleAdminVaultReset(request, env, session, userRoute[1].toLowerCase());
  }
  if (userRoute?.[2] === 'restore' && request.method === 'POST') {
    return handleAdminVaultRestore(request, env, session, userRoute[1].toLowerCase());
  }
  return jsonResponse({ error: 'Not found' }, 404);
}

async function checkRateLimit(request, kv, { limit, windowMs, namespace }) {
  const ipHash = await requestSource(request);
  const now = Date.now();
  const windowIndex = Math.floor(now / windowMs);
  const resetAt = (windowIndex + 1) * windowMs;
  const prefix = `${RATE_PREFIX}${namespace}:${ipHash}:${windowIndex}:`;
  const entries = await kv.list({ prefix, limit: limit + 1 });
  const remaining = Math.max(0, limit - entries.keys.length);
  const resetSeconds = Math.max(1, Math.ceil((resetAt - now) / 1000));
  const headers = {
    'RateLimit-Limit': String(limit),
    'RateLimit-Remaining': String(remaining),
    'RateLimit-Reset': String(Math.ceil(resetAt / 1000)),
  };
  if (entries.keys.length >= limit) {
    return jsonResponse({ error: 'Too many requests' }, 429, { ...headers, 'Retry-After': String(resetSeconds) });
  }
  await kv.put(`${prefix}${crypto.randomUUID()}`, '1', { expirationTtl: Math.max(120, Math.ceil(windowMs / 1000) * 2) });
  return null;
}

function isValidKey(key) {
  return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
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

async function handleGet(request, url, env) {
  const key = url.searchParams.get('key');
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  const normalizedKey = key.toLowerCase();
  const profile = await getUserProfile(env, normalizedKey);
  if (profile?.status === 'disabled') {
    await writeAudit(env, request, {
      actor: profile.accountName || 'vault-user', action: 'vault.access_blocked', targetKey: normalizedKey,
      targetLabel: profile.accountName, result: 'blocked', details: '账户已被管理员停用',
    });
    return jsonResponse({ error: '账户已被管理员停用，请联系管理员', code: 'ACCOUNT_DISABLED' }, 423);
  }

  const data = await env.DATA_KV.get(normalizedKey);
  if (data === null) return jsonResponse({ exists: false, data: null }, 200);
  let updatedAt = 0;
  try { updatedAt = Number(JSON.parse(data).updatedAt || 0); } catch { /* client validates the full record */ }
  const accountName = accountNameFromRequest(request, url);
  const nextProfile = await upsertUserProfile(env, normalizedKey, {
    accountName: accountName || profile?.accountName || '', lastSeenAt: Date.now(), updatedAt, hasVault: true,
  });
  await writeAudit(env, request, {
    actor: nextProfile.accountName || 'vault-user', action: 'vault.read', targetKey: normalizedKey,
    targetLabel: nextProfile.accountName, result: 'success', details: '读取加密保险库',
  });
  return jsonResponse({ exists: true, data, updatedAt }, 200);
}

async function handlePut(request, env) {
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
  const profile = await getUserProfile(env, normalizedKey);
  if (profile?.status === 'disabled') {
    await writeAudit(env, request, {
      actor: profile.accountName || 'vault-user', action: 'vault.save_blocked', targetKey: normalizedKey,
      targetLabel: profile.accountName, result: 'blocked', details: '账户已被管理员停用',
    });
    return jsonResponse({ error: '账户已被管理员停用，请联系管理员', code: 'ACCOUNT_DISABLED' }, 423);
  }

  const updatedAt = Date.now();
  await env.DATA_KV.put(normalizedKey, JSON.stringify({ encryptedData: data, salt, version: Number(version || 1), updatedAt }));
  const accountName = accountNameFrom(body.accountName);
  const nextProfile = await upsertUserProfile(env, normalizedKey, {
    accountName: accountName || profile?.accountName || '',
    lastSeenAt: updatedAt,
    updatedAt,
    hasVault: true,
    status: profile?.status === 'reset_required' ? 'active' : (profile?.status || 'active'),
  });
  await writeAudit(env, request, {
    actor: nextProfile.accountName || 'vault-user', action: 'vault.save', targetKey: normalizedKey,
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

async function handleDelete(request, url, env) {
  const key = url.searchParams.get('key');
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  const normalizedKey = key.toLowerCase();
  const profile = await getUserProfile(env, normalizedKey);
  await env.DATA_KV.delete(normalizedKey);
  await env.DATA_KV.delete(`${USER_PREFIX}${normalizedKey}`);
  await writeAudit(env, request, {
    actor: profile?.accountName || 'vault-user', action: 'vault.delete', targetKey: normalizedKey,
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
    return [profile.accountName, profile.displayName, profile.adminNote, profile.keyHash]
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
    actor: session.adminName, action: 'admin.user.update', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success', details: `状态：${next.status}；管理信息已更新`,
  });
  return jsonResponse({ success: true, user: next }, 200);
}

async function handleAdminUserDelete(request, env, session, keyHash) {
  const body = await readJsonWithLimit(request, 2048);
  if (body?.confirmation !== '删除用户') return jsonResponse({ error: '确认文字不正确' }, 400);
  const profile = await getUserOrLegacyProfile(env, keyHash);
  if (!profile) return jsonResponse({ error: '用户不存在' }, 404);
  const archiveKey = typeof profile.archiveKey === 'string' && profile.archiveKey.startsWith(`${ARCHIVE_PREFIX}${keyHash}:`)
    ? profile.archiveKey
    : '';
  await Promise.all([
    env.DATA_KV.delete(keyHash),
    env.DATA_KV.delete(`${USER_PREFIX}${keyHash}`),
    ...(archiveKey ? [env.DATA_KV.delete(archiveKey)] : []),
  ]);
  await writeAudit(env, request, {
    actor: session.adminName, action: 'admin.user.delete', targetKey: keyHash,
    targetLabel: profile.accountName || profile.displayName, result: 'success',
    details: '永久删除用户、云端保险库及可恢复备份；审计日志保留',
  });
  return jsonResponse({ success: true }, 200);
}

async function handleAdminVaultReset(request, env, session, keyHash) {
  const body = await readJsonWithLimit(request, 2048);
  if (body?.confirmation !== '重置保险库') return jsonResponse({ error: '确认文字不正确' }, 400);
  const data = await env.DATA_KV.get(keyHash);
  const profile = await getUserOrLegacyProfile(env, keyHash);
  if (!profile || data === null) return jsonResponse({ error: '当前没有可重置的保险库' }, 409);
  const now = Date.now();
  const archiveKey = `${ARCHIVE_PREFIX}${keyHash}:${now}`;
  const archivedUntil = now + ARCHIVE_RETENTION_SECONDS * 1000;
  await env.DATA_KV.put(archiveKey, JSON.stringify({ data, archivedAt: now, archivedUntil }), { expirationTtl: ARCHIVE_RETENTION_SECONDS });
  await env.DATA_KV.delete(keyHash);
  const next = await putUserProfile(env, {
    ...profile, status: 'reset_required', hasVault: false, resetAt: now, archiveKey, archivedUntil, updatedAt: now,
  });
  await writeAudit(env, request, {
    actor: session.adminName, action: 'admin.vault.reset', targetKey: keyHash,
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
  if (profile.hasVault || await env.DATA_KV.get(keyHash) !== null) {
    return jsonResponse({ error: '当前保险库已有数据，不能覆盖恢复' }, 409);
  }
  const archived = await env.DATA_KV.get(profile.archiveKey);
  if (archived === null) return jsonResponse({ error: '备份已过期，无法恢复' }, 410);
  let archive;
  try { archive = JSON.parse(archived); } catch { return jsonResponse({ error: '备份已损坏，无法恢复' }, 500); }
  await env.DATA_KV.put(keyHash, archive.data);
  await env.DATA_KV.delete(profile.archiveKey);
  const next = await putUserProfile(env, {
    ...profile, status: 'active', hasVault: true, archiveKey: '', archivedUntil: 0, updatedAt: Date.now(),
  });
  await writeAudit(env, request, {
    actor: session.adminName, action: 'admin.vault.restore', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success', details: '已恢复重置前的加密保险库',
  });
  return jsonResponse({ success: true, user: next }, 200);
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
    .filter((entry) => !query || [entry.actor, entry.action, entry.targetLabel, entry.targetKey, entry.details, entry.source]
      .some((value) => String(value || '').toLocaleLowerCase().includes(query)))
    .sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0));
  return jsonResponse({ logs: filtered.slice(0, limit), total: filtered.length, limit, scanned: logs.length }, 200);
}

function defaultProfile(keyHash, overrides = {}) {
  const now = Date.now();
  return {
    keyHash,
    accountName: '', displayName: '', status: 'active', adminNote: '',
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

async function authenticateAdmin(request, env) {
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
    actor: cleanSingleLine(event.actor || 'system', 80) || 'system',
    action: cleanSingleLine(event.action, 80),
    targetKey: isValidKey(event.targetKey) ? event.targetKey.toLowerCase() : '',
    targetLabel: cleanSingleLine(event.targetLabel, 80),
    result: cleanSingleLine(event.result || 'success', 30),
    details: cleanNote(event.details || '', 300),
    source: await requestSource(request),
  };
  const reverseTimestamp = String(9_999_999_999_999 - timestamp).padStart(13, '0');
  const key = `${AUDIT_PREFIX}${reverseTimestamp}:${entry.id}`;
  await env.DATA_KV.put(key, JSON.stringify(entry), { expirationTtl: AUDIT_RETENTION_SECONDS });
}

async function requestSource(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  return (await sha256Hex(ip)).slice(0, 12);
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

function httpError(message, status) {
  const error = new Error(message);
  error.status = status;
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
