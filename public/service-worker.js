const CACHE_VERSION = 'v2.1.0';
const STATIC_CACHE = `2fa-static-${CACHE_VERSION}`;
const PRECACHE_URLS = ['/manifest.json', '/icons/icon.svg'];
const APP_SHELL_RESOURCE_PATTERN = /\b(?:src|href)=["']([^"'#]+)["']/gi;

function appShellResources(html) {
  const resources = [...html.matchAll(APP_SHELL_RESOURCE_PATTERN)]
    .map((match) => new URL(match[1], self.location.origin))
    .filter((url) => url.origin === self.location.origin)
    .map((url) => `${url.pathname}${url.search}`);
  return [...new Set([...PRECACHE_URLS, ...resources])];
}

async function cacheApplicationShell(indexResponse) {
  const cache = await caches.open(STATIC_CACHE);
  const html = await indexResponse.clone().text();
  await Promise.all([
    cache.put('/', indexResponse.clone()),
    cache.put('/index.html', indexResponse.clone()),
    cache.addAll(appShellResources(html)),
  ]);
}

async function fetchAndCache(request) {
  const response = await fetch(request);
  if (response.ok) {
    const cache = await caches.open(STATIC_CACHE);
    await cache.put(request, response.clone());
  }
  return response;
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    fetch('/index.html', { cache: 'reload' })
      .then((response) => {
        if (!response.ok) throw new Error('Application shell is unavailable');
        return cacheApplicationShell(response);
      })
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names.filter((name) => name !== STATIC_CACHE).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(request).catch(() => new Response(
      JSON.stringify({ error: 'Network unavailable', offline: true }),
      { status: 503, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } },
    )));
    return;
  }

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            event.waitUntil(Promise.all([
              caches.open(STATIC_CACHE).then((cache) => cache.put(request, copy)),
              cacheApplicationShell(response.clone()),
            ]));
          }
          return response;
        })
        .catch(async () => (await caches.match(request, { ignoreVary: true }))
          || (await caches.match('/index.html', { ignoreVary: true }))
          || new Response('Offline', { status: 503 })),
    );
    return;
  }

  event.respondWith(
    caches.match(request, { ignoreVary: true }).then((cached) => {
      if (!cached) return fetchAndCache(request).catch(() => new Response('Offline', { status: 503 }));
      event.waitUntil(fetchAndCache(request).catch(() => undefined));
      return cached;
    }),
  );
});

self.addEventListener('message', (event) => {
  if (event.data?.type === 'CLEAR_CACHE') {
    event.waitUntil(caches.keys().then((names) => Promise.all(names.map((name) => caches.delete(name)))));
  }
});
