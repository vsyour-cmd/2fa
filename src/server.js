const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');
const { createHash, randomBytes, randomUUID, timingSafeEqual } = require('node:crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || './data/2fa.db';
const TRUST_PROXY_HOPS = Math.max(0, Number.parseInt(process.env.TRUST_PROXY_HOPS || '0', 10) || 0);
const STATIC_PATH = path.join(__dirname, '../static');
const ADMIN_USERNAME = cleanSingleLine(process.env.ADMIN_USERNAME || 'admin', 80) || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_SESSION_MS = 30 * 60_000;
const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60_000;
const ARCHIVE_RETENTION_MS = 30 * 24 * 60 * 60_000;

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

const RATE_LIMIT = positiveInteger(process.env.RATE_LIMIT, 20);
const RATE_WINDOW_MS = positiveInteger(process.env.RATE_WINDOW_MS, 60_000);

if (TRUST_PROXY_HOPS > 0) app.set('trust proxy', TRUST_PROXY_HOPS);
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb', strict: true }));
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; media-src 'self' blob:; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(self), clipboard-read=(self), clipboard-write=(self)',
    'Cross-Origin-Opener-Policy': 'same-origin',
  });
  next();
});

const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS data_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rate_limits (
    bucket TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_profiles (
    key TEXT PRIMARY KEY,
    account_name TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    admin_note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0,
    last_seen_at INTEGER NOT NULL DEFAULT 0,
    has_vault INTEGER NOT NULL DEFAULT 1,
    reset_at INTEGER NOT NULL DEFAULT 0,
    archive_id TEXT NOT NULL DEFAULT '',
    archived_until INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    admin_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_key TEXT NOT NULL DEFAULT '',
    target_label TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS vault_archives (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    archived_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON user_profiles(status);
  CREATE INDEX IF NOT EXISTS idx_vault_archives_expiry ON vault_archives(expires_at);
`);

const auditLogColumns = new Set(db.prepare('PRAGMA table_info(audit_logs)').all().map((column) => column.name));
if (!auditLogColumns.has('ip_address')) {
  db.exec("ALTER TABLE audit_logs ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''");
}

const incrementRateLimit = db.prepare(`
  INSERT INTO rate_limits (bucket, count, reset_at)
  VALUES (?, 1, ?)
  ON CONFLICT(bucket) DO UPDATE SET count = rate_limits.count + 1, reset_at = excluded.reset_at
  RETURNING count, reset_at
`);
const deleteExpiredRateLimits = db.prepare('DELETE FROM rate_limits WHERE reset_at <= ?');

function createRateLimiter({ limit, windowMs, namespace }) {
  return (req, res, next) => {
    const now = Date.now();
    const windowIndex = Math.floor(now / windowMs);
    const resetAt = (windowIndex + 1) * windowMs;
    const bucketId = `${namespace}:${req.ip}:${windowIndex}`;
    deleteExpiredRateLimits.run(now);
    const current = incrementRateLimit.get(bucketId, resetAt);
    res.set({
      'RateLimit-Limit': String(limit),
      'RateLimit-Remaining': String(Math.max(0, limit - current.count)),
      'RateLimit-Reset': String(Math.ceil(current.reset_at / 1000)),
    });
    if (current.count > limit) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((current.reset_at - now) / 1000))));
      return res.status(429).json({ error: 'Too many requests' });
    }
    return next();
  };
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

function accountNameFromRequest(req) {
  const encoded = req.get('X-Vault-Account') || '';
  if (encoded && /^[A-Za-z0-9_-]{1,512}$/.test(encoded)) {
    try { return cleanSingleLine(Buffer.from(encoded, 'base64url').toString('utf8'), 80); } catch { /* use legacy query fallback */ }
  }
  return cleanSingleLine(typeof req.query.account === 'string' ? req.query.account : '', 80);
}

function isValidPayload(data, salt) {
  return typeof data === 'string'
    && data.length > 16
    && data.length <= 240_000
    && typeof salt === 'string'
    && salt.length >= 16
    && salt.length <= 128;
}

function hashText(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function safeEqual(left, right) {
  const leftDigest = createHash('sha256').update(String(left)).digest();
  const rightDigest = createHash('sha256').update(String(right)).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function requestSource(req) {
  return hashText(requestIp(req) || 'unknown').slice(0, 12);
}

function requestIp(req) {
  const value = cleanSingleLine(req.ip || req.socket?.remoteAddress || '', 80);
  return value.startsWith('::ffff:') ? value.slice(7) : value;
}

function cleanupExpired() {
  const now = Date.now();
  db.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?').run(now);
  db.prepare('DELETE FROM audit_logs WHERE timestamp <= ?').run(now - AUDIT_RETENTION_MS);
  db.prepare('DELETE FROM vault_archives WHERE expires_at <= ?').run(now);
}

function writeAudit(req, event) {
  try {
    db.prepare(`
      INSERT INTO audit_logs (id, timestamp, actor, action, target_key, target_label, result, details, source, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(),
      Date.now(),
      cleanSingleLine(event.actor || 'system', 80) || 'system',
      cleanSingleLine(event.action, 80),
      isValidKey(event.targetKey) ? event.targetKey.toLowerCase() : '',
      cleanSingleLine(event.targetLabel, 80),
      cleanSingleLine(event.result || 'success', 30),
      cleanNote(event.details || '', 300),
      requestSource(req),
      requestIp(req),
    );
  } catch (error) {
    console.error(JSON.stringify({ event: 'audit_write_error', action: cleanSingleLine(event?.action, 80), message: error.message }));
  }
}

function rowToProfile(row, keyOverride = '') {
  if (!row) return null;
  return {
    keyHash: keyOverride || row.key,
    accountName: row.account_name || '',
    displayName: row.display_name || '',
    status: row.status || 'active',
    adminNote: row.admin_note || '',
    createdAt: Number(row.created_at || 0),
    updatedAt: Number(row.updated_at || 0),
    lastSeenAt: Number(row.last_seen_at || 0),
    hasVault: Boolean(row.has_vault),
    resetAt: Number(row.reset_at || 0),
    archiveKey: row.archive_id || '',
    archivedUntil: Number(row.archived_until || 0),
  };
}

function defaultProfile(keyHash, overrides = {}) {
  return {
    keyHash,
    accountName: '',
    displayName: '',
    status: 'active',
    adminNote: '',
    createdAt: Date.now(),
    updatedAt: 0,
    lastSeenAt: 0,
    hasVault: true,
    resetAt: 0,
    archiveKey: '',
    archivedUntil: 0,
    ...overrides,
  };
}

function getProfile(keyHash) {
  return rowToProfile(db.prepare('SELECT * FROM user_profiles WHERE key = ?').get(keyHash));
}

function getUserOrLegacyProfile(keyHash) {
  const profile = getProfile(keyHash);
  if (profile) return profile;
  const row = db.prepare('SELECT updated_at FROM data_store WHERE key = ?').get(keyHash);
  return row ? defaultProfile(keyHash, { updatedAt: row.updated_at, hasVault: true }) : null;
}

function putProfile(profile) {
  const normalized = defaultProfile(profile.keyHash, {
    ...profile,
    accountName: cleanSingleLine(profile.accountName, 80),
    displayName: cleanSingleLine(profile.displayName, 80),
    adminNote: cleanNote(profile.adminNote),
  });
  db.prepare(`
    INSERT INTO user_profiles (
      key, account_name, display_name, status, admin_note, created_at, updated_at,
      last_seen_at, has_vault, reset_at, archive_id, archived_until
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      account_name = excluded.account_name,
      display_name = excluded.display_name,
      status = excluded.status,
      admin_note = excluded.admin_note,
      updated_at = excluded.updated_at,
      last_seen_at = excluded.last_seen_at,
      has_vault = excluded.has_vault,
      reset_at = excluded.reset_at,
      archive_id = excluded.archive_id,
      archived_until = excluded.archived_until
  `).run(
    normalized.keyHash,
    normalized.accountName,
    normalized.displayName,
    normalized.status,
    normalized.adminNote,
    normalized.createdAt,
    normalized.updatedAt,
    normalized.lastSeenAt,
    normalized.hasVault ? 1 : 0,
    normalized.resetAt,
    normalized.archiveKey,
    normalized.archivedUntil,
  );
  return normalized;
}

function upsertProfile(keyHash, changes) {
  const current = getProfile(keyHash);
  return putProfile(defaultProfile(keyHash, { ...(current || {}), ...changes, createdAt: current?.createdAt || Date.now() }));
}

function requireAdmin(req, res, next) {
  cleanupExpired();
  const match = (req.get('Authorization') || '').match(/^Bearer ([A-Za-z0-9_-]{40,128})$/);
  if (!match) return res.status(401).json({ error: '管理会话已失效，请重新登录' });
  const tokenHash = hashText(match[1]);
  const session = db.prepare('SELECT * FROM admin_sessions WHERE token_hash = ? AND expires_at > ?').get(tokenHash, Date.now());
  if (!session) return res.status(401).json({ error: '管理会话已失效，请重新登录' });
  req.admin = { name: session.admin_name, tokenHash };
  return next();
}

app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: Date.now() }));
app.use('/api/data', createRateLimiter({ limit: RATE_LIMIT, windowMs: RATE_WINDOW_MS, namespace: 'data' }));

app.get('/api/access/me', (req, res) => {
  const email = cleanSingleLine(process.env.ACCESS_DEV_EMAIL || '', 254).toLocaleLowerCase('en-US');
  return res.json({ authenticated: Boolean(email), email });
});

app.get('/api/data', (req, res) => {
  try {
    const key = req.query.key;
    if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid key' });
    const normalizedKey = key.toLowerCase();
    const profile = getProfile(normalizedKey);
    if (profile?.status === 'disabled') {
      writeAudit(req, {
        actor: profile.accountName || 'vault-user', action: 'vault.access_blocked', targetKey: normalizedKey,
        targetLabel: profile.accountName, result: 'blocked', details: '账户已被管理员停用',
      });
      return res.status(423).json({ error: '账户已被管理员停用，请联系管理员', code: 'ACCOUNT_DISABLED' });
    }
    const row = db.prepare('SELECT value, updated_at FROM data_store WHERE key = ?').get(normalizedKey);
    if (!row) return res.json({ exists: false, data: null });
    const accountName = accountNameFromRequest(req);
    const nextProfile = upsertProfile(normalizedKey, {
      accountName: accountName || profile?.accountName || '',
      lastSeenAt: Date.now(),
      updatedAt: row.updated_at,
      hasVault: true,
    });
    writeAudit(req, {
      actor: nextProfile.accountName || 'vault-user', action: 'vault.read', targetKey: normalizedKey,
      targetLabel: nextProfile.accountName, result: 'success', details: '读取加密保险库',
    });
    return res.json({ exists: true, data: row.value, updatedAt: row.updated_at });
  } catch (error) {
    console.error(JSON.stringify({ event: 'database_get_error', message: error.message }));
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.put('/api/data', (req, res) => {
  try {
    const { key, data, salt, version } = req.body || {};
    if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid key' });
    if (!isValidPayload(data, salt)) return res.status(400).json({ error: 'Invalid data' });
    if (req.body.accountName !== undefined && (typeof req.body.accountName !== 'string' || req.body.accountName.trim().length > 80)) {
      return res.status(400).json({ error: 'Invalid account name' });
    }
    const expectedUpdatedAt = req.body.expectedUpdatedAt;
    if (!Number.isSafeInteger(expectedUpdatedAt) || expectedUpdatedAt < 0) {
      return res.status(428).json({ error: '请刷新页面后再保存', code: 'VERSION_REQUIRED' });
    }
    const normalizedKey = key.toLowerCase();
    const profile = getProfile(normalizedKey);
    if (profile?.status === 'disabled') {
      writeAudit(req, {
        actor: profile.accountName || 'vault-user', action: 'vault.save_blocked', targetKey: normalizedKey,
        targetLabel: profile.accountName, result: 'blocked', details: '账户已被管理员停用',
      });
      return res.status(423).json({ error: '账户已被管理员停用，请联系管理员', code: 'ACCOUNT_DISABLED' });
    }
    const saved = db.transaction(() => {
      const current = db.prepare('SELECT updated_at FROM data_store WHERE key = ?').get(normalizedKey);
      const currentUpdatedAt = Number(current?.updated_at || 0);
      if (currentUpdatedAt !== expectedUpdatedAt) return { success: false, currentUpdatedAt };
      const updatedAt = Math.max(Date.now(), currentUpdatedAt + 1);
      const stored = JSON.stringify({ encryptedData: data, salt, version: Number(version || 1), updatedAt });
      db.prepare(`
        INSERT INTO data_store (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
      `).run(normalizedKey, stored, updatedAt);
      upsertProfile(normalizedKey, {
        accountName: cleanSingleLine(req.body.accountName || profile?.accountName || '', 80),
        lastSeenAt: updatedAt,
        updatedAt,
        hasVault: true,
        status: profile?.status === 'reset_required' ? 'active' : (profile?.status || 'active'),
      });
      return { success: true, updatedAt };
    })();
    if (!saved.success) {
      writeAudit(req, {
        actor: profile?.accountName || 'vault-user', action: 'vault.save_conflict', targetKey: normalizedKey,
        targetLabel: profile?.accountName || '', result: 'blocked', details: '另一设备已更新保险库，拒绝覆盖',
      });
      return res.status(409).json({
        error: '另一设备已经更新了云端数据，请先处理同步冲突',
        code: 'VERSION_CONFLICT',
        currentUpdatedAt: saved.currentUpdatedAt,
      });
    }
    const { updatedAt } = saved;
    const nextProfile = getProfile(normalizedKey);
    writeAudit(req, {
      actor: nextProfile?.accountName || 'vault-user', action: 'vault.save', targetKey: normalizedKey,
      targetLabel: nextProfile?.accountName || '', result: 'success', details: `保存加密保险库 v${Number(version || 1)}`,
    });
    return res.json({ success: true, updatedAt });
  } catch (error) {
    console.error(JSON.stringify({ event: 'database_put_error', message: error.message }));
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.delete('/api/data', (req, res) => {
  try {
    const key = req.query.key;
    if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid key' });
    const normalizedKey = key.toLowerCase();
    const profile = getProfile(normalizedKey);
    const expectedUpdatedAt = Number(req.query.expectedUpdatedAt);
    if (!Number.isSafeInteger(expectedUpdatedAt) || expectedUpdatedAt < 0) {
      return res.status(428).json({ error: '删除前必须确认云端版本', code: 'VERSION_REQUIRED' });
    }
    const removed = db.transaction(() => {
      const current = db.prepare('SELECT updated_at FROM data_store WHERE key = ?').get(normalizedKey);
      const currentUpdatedAt = Number(current?.updated_at || 0);
      if (currentUpdatedAt !== expectedUpdatedAt) return { success: false, currentUpdatedAt };
      db.prepare('DELETE FROM data_store WHERE key = ?').run(normalizedKey);
      db.prepare('DELETE FROM user_profiles WHERE key = ?').run(normalizedKey);
      return { success: true };
    })();
    if (!removed.success) {
      return res.status(409).json({
        error: '另一设备已经更新了云端数据，已取消删除',
        code: 'VERSION_CONFLICT',
        currentUpdatedAt: removed.currentUpdatedAt,
      });
    }
    writeAudit(req, {
      actor: profile?.accountName || 'vault-user', action: 'vault.delete', targetKey: normalizedKey,
      targetLabel: profile?.accountName || '', result: 'success', details: '删除旧版加密保险库',
    });
    return res.json({ success: true });
  } catch (error) {
    console.error(JSON.stringify({ event: 'database_delete_error', message: error.message }));
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/api/admin/login', createRateLimiter({ limit: 5, windowMs: 10 * 60_000, namespace: 'admin-login' }), (req, res) => {
  try {
    cleanupExpired();
    if (ADMIN_PASSWORD.length < 10) return res.status(503).json({ error: '管理后台尚未配置', code: 'ADMIN_NOT_CONFIGURED' });
    const username = cleanSingleLine(req.body?.username, 80);
    const password = typeof req.body?.password === 'string' && req.body.password.length <= 256 ? req.body.password : '';
    const usernameValid = safeEqual(username, ADMIN_USERNAME);
    const passwordValid = safeEqual(password, ADMIN_PASSWORD);
    const valid = usernameValid && passwordValid;
    if (!valid) {
      writeAudit(req, { actor: username || 'unknown', action: 'admin.login', result: 'failure', details: '管理员凭据不正确' });
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    const token = randomBytes(32).toString('base64url');
    const tokenHash = hashText(token);
    const now = Date.now();
    const expiresAt = now + ADMIN_SESSION_MS;
    db.prepare('INSERT INTO admin_sessions (token_hash, admin_name, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(tokenHash, ADMIN_USERNAME, now, expiresAt);
    writeAudit(req, { actor: ADMIN_USERNAME, action: 'admin.login', result: 'success', details: '管理员登录成功' });
    return res.json({ token, adminName: ADMIN_USERNAME, expiresAt });
  } catch (error) {
    console.error(JSON.stringify({ event: 'admin_login_error', message: error.message }));
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.use('/api/admin', createRateLimiter({ limit: 120, windowMs: 60_000, namespace: 'admin' }), requireAdmin);

app.post('/api/admin/logout', (req, res) => {
  db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(req.admin.tokenHash);
  writeAudit(req, { actor: req.admin.name, action: 'admin.logout', result: 'success', details: '管理员退出登录' });
  return res.json({ success: true });
});

app.get('/api/admin/users', (req, res) => {
  const query = cleanSingleLine(typeof req.query.query === 'string' ? req.query.query : '', 100).toLocaleLowerCase();
  const status = cleanSingleLine(typeof req.query.status === 'string' ? req.query.status : '', 30);
  const limit = clampInteger(req.query.limit, 1, 200, 100);
  const offset = clampInteger(req.query.offset, 0, 10_000, 0);
  const profiles = db.prepare('SELECT * FROM user_profiles').all().map((row) => rowToProfile(row));
  const profileMap = new Map(profiles.map((profile) => [profile.keyHash, profile]));
  const vaultRows = db.prepare('SELECT key, updated_at FROM data_store').all();
  for (const row of vaultRows) {
    const existing = profileMap.get(row.key);
    if (existing) existing.hasVault = true;
    else profileMap.set(row.key, defaultProfile(row.key, { updatedAt: row.updated_at, hasVault: true }));
  }
  const allUsers = [...profileMap.values()].sort((left, right) => activityTime(right) - activityTime(left));
  const filtered = allUsers.filter((profile) => {
    if (status && profile.status !== status) return false;
    if (!query) return true;
    return [profile.accountName, profile.displayName, profile.adminNote, profile.keyHash]
      .some((value) => String(value || '').toLocaleLowerCase().includes(query));
  });
  return res.json({
    users: filtered.slice(offset, offset + limit),
    total: filtered.length,
    offset,
    limit,
    hasMore: offset + limit < filtered.length,
    summary: {
      total: allUsers.length,
      active: allUsers.filter((profile) => profile.status === 'active').length,
      disabled: allUsers.filter((profile) => profile.status === 'disabled').length,
      resetRequired: allUsers.filter((profile) => profile.status === 'reset_required').length,
      anonymous: allUsers.filter((profile) => !profile.accountName).length,
    },
  });
});

app.patch('/api/admin/users/:key', (req, res) => {
  const keyHash = String(req.params.key || '').toLowerCase();
  if (!isValidKey(keyHash)) return res.status(400).json({ error: 'Invalid key' });
  const profile = getUserOrLegacyProfile(keyHash);
  if (!profile) return res.status(404).json({ error: '用户不存在' });
  const allowedStatuses = new Set(['active', 'disabled', 'reset_required']);
  if (req.body.status !== undefined && !allowedStatuses.has(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  if (req.body.displayName !== undefined && (typeof req.body.displayName !== 'string' || req.body.displayName.length > 80)) {
    return res.status(400).json({ error: 'Invalid display name' });
  }
  if (req.body.adminNote !== undefined && (typeof req.body.adminNote !== 'string' || req.body.adminNote.length > 500)) {
    return res.status(400).json({ error: 'Invalid admin note' });
  }
  const next = putProfile({
    ...profile,
    status: req.body.status ?? profile.status,
    displayName: req.body.displayName === undefined ? profile.displayName : cleanSingleLine(req.body.displayName, 80),
    adminNote: req.body.adminNote === undefined ? profile.adminNote : cleanNote(req.body.adminNote),
    updatedAt: Date.now(),
  });
  writeAudit(req, {
    actor: req.admin.name, action: 'admin.user.update', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success', details: `状态：${next.status}；管理信息已更新`,
  });
  return res.json({ success: true, user: next });
});

app.delete('/api/admin/users/:key', (req, res) => (
  res.status(405).set('Allow', 'PATCH').json({ error: '管理后台不提供永久删除用户功能' })
));

app.post('/api/admin/users/:key/reset', (req, res) => {
  const keyHash = String(req.params.key || '').toLowerCase();
  if (!isValidKey(keyHash)) return res.status(400).json({ error: 'Invalid key' });
  if (req.body?.confirmation !== '重置保险库') return res.status(400).json({ error: '确认文字不正确' });
  const profile = getUserOrLegacyProfile(keyHash);
  const row = db.prepare('SELECT value FROM data_store WHERE key = ?').get(keyHash);
  if (!profile || !row) return res.status(409).json({ error: '当前没有可重置的保险库' });
  const now = Date.now();
  const archiveId = randomUUID();
  const archivedUntil = now + ARCHIVE_RETENTION_MS;
  let next;
  db.transaction(() => {
    db.prepare('INSERT INTO vault_archives (id, key, value, archived_at, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(archiveId, keyHash, row.value, now, archivedUntil);
    db.prepare('DELETE FROM data_store WHERE key = ?').run(keyHash);
    next = putProfile({
      ...profile,
      status: 'reset_required',
      hasVault: false,
      resetAt: now,
      archiveKey: archiveId,
      archivedUntil,
      updatedAt: now,
    });
  })();
  writeAudit(req, {
    actor: req.admin.name, action: 'admin.vault.reset', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success',
    details: '保险库已重置，旧密文保留 30 天，可由管理员恢复',
  });
  return res.json({ success: true, user: next });
});

app.post('/api/admin/users/:key/restore', (req, res) => {
  const keyHash = String(req.params.key || '').toLowerCase();
  if (!isValidKey(keyHash)) return res.status(400).json({ error: 'Invalid key' });
  if (req.body?.confirmation !== '恢复保险库') return res.status(400).json({ error: '确认文字不正确' });
  const profile = getProfile(keyHash);
  if (!profile?.archiveKey) return res.status(409).json({ error: '没有可恢复的保险库备份' });
  if (profile.hasVault || db.prepare('SELECT 1 FROM data_store WHERE key = ?').get(keyHash)) {
    return res.status(409).json({ error: '当前保险库已有数据，不能覆盖恢复' });
  }
  const archive = db.prepare('SELECT * FROM vault_archives WHERE id = ? AND expires_at > ?').get(profile.archiveKey, Date.now());
  if (!archive) return res.status(410).json({ error: '备份已过期，无法恢复' });
  let next;
  db.transaction(() => {
    let updatedAt = Date.now();
    try { updatedAt = Number(JSON.parse(archive.value).updatedAt || updatedAt); } catch { /* encrypted record validation remains client-side */ }
    db.prepare('INSERT INTO data_store (key, value, updated_at) VALUES (?, ?, ?)').run(keyHash, archive.value, updatedAt);
    db.prepare('DELETE FROM vault_archives WHERE id = ?').run(archive.id);
    next = putProfile({
      ...profile,
      status: 'active',
      hasVault: true,
      archiveKey: '',
      archivedUntil: 0,
      updatedAt: Date.now(),
    });
  })();
  writeAudit(req, {
    actor: req.admin.name, action: 'admin.vault.restore', targetKey: keyHash,
    targetLabel: next.accountName || next.displayName, result: 'success', details: '已恢复重置前的加密保险库',
  });
  return res.json({ success: true, user: next });
});

app.get('/api/admin/logs', (req, res) => {
  cleanupExpired();
  const query = cleanSingleLine(typeof req.query.query === 'string' ? req.query.query : '', 100).toLocaleLowerCase();
  const action = cleanSingleLine(typeof req.query.action === 'string' ? req.query.action : '', 80);
  const result = cleanSingleLine(typeof req.query.result === 'string' ? req.query.result : '', 30);
  const limit = clampInteger(req.query.limit, 1, 200, 100);
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 5000').all().map((row) => ({
    id: row.id,
    timestamp: row.timestamp,
    actor: row.actor,
    action: row.action,
    targetKey: row.target_key,
    targetLabel: row.target_label,
    result: row.result,
    details: row.details,
    source: row.source,
    ipAddress: row.ip_address || '',
  }));
  const filtered = logs
    .filter((entry) => (!action || entry.action === action) && (!result || entry.result === result))
    .filter((entry) => !query || [entry.actor, entry.action, entry.targetLabel, entry.targetKey, entry.details, entry.ipAddress, entry.source]
      .some((value) => String(value || '').toLocaleLowerCase().includes(query)));
  return res.json({ logs: filtered.slice(0, limit), total: filtered.length, limit, scanned: logs.length });
});

function activityTime(profile) {
  return Number(profile.lastSeenAt || profile.updatedAt || profile.createdAt || 0);
}

function clampInteger(value, minimum, maximum, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, parsed));
}

app.get('/admin.html', (req, res) => {
  res.set('Cache-Control', 'no-store');
  return res.sendFile(path.join(STATIC_PATH, 'admin.html'));
});
app.use(express.static(STATIC_PATH, { index: false, maxAge: '1h' }));
app.get('*', (req, res) => res.sendFile(path.join(STATIC_PATH, 'index.html')));

app.use((error, req, res, next) => {
  if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  if (error instanceof SyntaxError) return res.status(400).json({ error: 'Invalid JSON' });
  return next(error);
});

let server = null;

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down...`);
  const finish = () => {
    db.close();
    process.exit(0);
  };
  if (server?.listening) server.close(finish);
  else finish();
}

if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`2FA Authenticator server running on port ${PORT}`);
    console.log(`Database: ${path.resolve(DB_PATH)}`);
  });
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = { app, db };
