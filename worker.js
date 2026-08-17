const RATE_LIMIT = 20;
const RATE_PREFIX = '$ratelimit$:';
const MAX_BODY_BYTES = 256 * 1024;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) {
      return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Not Found', { status: 404 });
    }
    if (url.pathname !== '/api/data') return jsonResponse({ error: 'Not found' }, 404);

    try {
      const limited = await checkRateLimit(request, env.DATA_KV);
      if (limited) return limited;
      if (request.method === 'GET') return handleGet(url, env);
      if (request.method === 'PUT') return handlePut(request, env);
      if (request.method === 'DELETE') return handleDelete(url, env);
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { Allow: 'GET, PUT, DELETE, OPTIONS' } });
      return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: 'GET, PUT, DELETE, OPTIONS' });
    } catch (error) {
      console.error(JSON.stringify({ event: 'api_error', method: request.method, message: error.message }));
      return jsonResponse({ error: 'Internal error' }, 500);
    }
  },
};

async function checkRateLimit(request, kv) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
  const ipHash = [...new Uint8Array(digest)].slice(0, 12).map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const minute = Math.floor(Date.now() / 60_000);
  const prefix = `${RATE_PREFIX}${ipHash}:${minute}:`;
  const entries = await kv.list({ prefix, limit: RATE_LIMIT + 1 });
  const remaining = Math.max(0, RATE_LIMIT - entries.keys.length);
  const resetSeconds = 60 - (Math.floor(Date.now() / 1000) % 60);
  const headers = {
    'RateLimit-Limit': String(RATE_LIMIT),
    'RateLimit-Remaining': String(remaining),
    'RateLimit-Reset': String(Math.ceil(Date.now() / 1000) + resetSeconds),
  };
  if (entries.keys.length >= RATE_LIMIT) {
    return jsonResponse({ error: 'Too many requests' }, 429, { ...headers, 'Retry-After': String(resetSeconds) });
  }
  await kv.put(`${prefix}${crypto.randomUUID()}`, '1', { expirationTtl: 120 });
  return null;
}

function isValidKey(key) {
  return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
}

async function handleGet(url, env) {
  const key = url.searchParams.get('key');
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  const data = await env.DATA_KV.get(key);
  if (data === null) return jsonResponse({ exists: false, data: null }, 200);
  let updatedAt = 0;
  try { updatedAt = Number(JSON.parse(data).updatedAt || 0); } catch { /* client validates the full record */ }
  return jsonResponse({ exists: true, data, updatedAt }, 200);
}

async function handlePut(request, env) {
  const declaredLength = Number(request.headers.get('Content-Length') || 0);
  if (declaredLength > MAX_BODY_BYTES) return jsonResponse({ error: 'Payload too large' }, 413);
  let body;
  try {
    body = await readJsonWithLimit(request);
  } catch (error) {
    return jsonResponse({ error: error.message }, error.status || 400);
  }
  const { key, data, salt, version } = body || {};
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  if (typeof data !== 'string' || data.length <= 16 || data.length > 240_000) return jsonResponse({ error: 'Invalid data' }, 400);
  if (typeof salt !== 'string' || salt.length < 16 || salt.length > 128) return jsonResponse({ error: 'Invalid salt' }, 400);
  const updatedAt = Date.now();
  await env.DATA_KV.put(key, JSON.stringify({
    encryptedData: data,
    salt,
    version: Number(version || 1),
    updatedAt,
  }));
  return jsonResponse({ success: true, updatedAt }, 200);
}

async function readJsonWithLimit(request) {
  if (!request.body) {
    const error = new Error('Missing body');
    error.status = 400;
    throw error;
  }
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      const error = new Error('Payload too large');
      error.status = 413;
      throw error;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    const error = new Error('Invalid JSON');
    error.status = 400;
    throw error;
  }
}

async function handleDelete(url, env) {
  const key = url.searchParams.get('key');
  if (!isValidKey(key)) return jsonResponse({ error: 'Invalid key' }, 400);
  await env.DATA_KV.delete(key);
  return jsonResponse({ success: true }, 200);
}

function jsonResponse(data, status, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extraHeaders,
    },
  });
}
