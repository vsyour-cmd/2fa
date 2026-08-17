const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || './data/2fa.db';
const TRUST_PROXY_HOPS = Math.max(0, Number.parseInt(process.env.TRUST_PROXY_HOPS || '0', 10) || 0);
const STATIC_PATH = path.join(__dirname, '../static');
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;
const rateBuckets = new Map();

if (TRUST_PROXY_HOPS > 0) app.set('trust proxy', TRUST_PROXY_HOPS);
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb', strict: true }));
app.use((req, res, next) => {
  res.set({
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
  )
`);

function rateLimitApi(req, res, next) {
  const now = Date.now();
  const bucketId = `${req.ip}:${Math.floor(now / RATE_WINDOW_MS)}`;
  const current = rateBuckets.get(bucketId) || { count: 0, resetAt: (Math.floor(now / RATE_WINDOW_MS) + 1) * RATE_WINDOW_MS };
  current.count += 1;
  rateBuckets.set(bucketId, current);
  res.set({
    'RateLimit-Limit': String(RATE_LIMIT),
    'RateLimit-Remaining': String(Math.max(0, RATE_LIMIT - current.count)),
    'RateLimit-Reset': String(Math.ceil(current.resetAt / 1000)),
  });
  if (current.count > RATE_LIMIT) {
    res.set('Retry-After', String(Math.max(1, Math.ceil((current.resetAt - now) / 1000))));
    return res.status(429).json({ error: 'Too many requests' });
  }
  return next();
}

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [bucketId, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(bucketId);
  }
}, RATE_WINDOW_MS);
cleanupTimer.unref();

function isValidKey(key) {
  return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
}

function isValidPayload(data, salt) {
  return typeof data === 'string'
    && data.length > 16
    && data.length <= 240_000
    && typeof salt === 'string'
    && salt.length >= 16
    && salt.length <= 128;
}

app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: Date.now() }));
app.use('/api/data', rateLimitApi);

app.get('/api/data', (req, res) => {
  try {
    const key = req.query.key;
    if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid key' });
    const row = db.prepare('SELECT value, updated_at FROM data_store WHERE key = ?').get(key);
    if (!row) return res.json({ exists: false, data: null });
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
    const updatedAt = Date.now();
    const stored = JSON.stringify({ encryptedData: data, salt, version: Number(version || 1), updatedAt });
    db.prepare(`
      INSERT INTO data_store (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).run(key, stored, updatedAt);
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
    db.prepare('DELETE FROM data_store WHERE key = ?').run(key);
    return res.json({ success: true });
  } catch (error) {
    console.error(JSON.stringify({ event: 'database_delete_error', message: error.message }));
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.use(express.static(STATIC_PATH, { index: false, maxAge: '1h' }));
app.get('*', (req, res) => res.sendFile(path.join(STATIC_PATH, 'index.html')));

app.use((error, req, res, next) => {
  if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  if (error instanceof SyntaxError) return res.status(400).json({ error: 'Invalid JSON' });
  return next(error);
});

const server = app.listen(PORT, () => {
  console.log(`2FA Authenticator server running on port ${PORT}`);
  console.log(`Database: ${path.resolve(DB_PATH)}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down...`);
  clearInterval(cleanupTimer);
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = { app, db };
