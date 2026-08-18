import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';

const source = await readFile(new URL('../public/service-worker.js', import.meta.url), 'utf8');

describe('offline application shell', () => {
  it('caches the built JavaScript and CSS discovered in index.html during installation', async () => {
    const listeners = {};
    const added = [];
    const stored = [];
    const cache = {
      addAll: vi.fn(async (urls) => { added.push(...urls); }),
      put: vi.fn(async (request) => { stored.push(typeof request === 'string' ? request : request.url); }),
    };
    const index = new Response(`<!doctype html>
      <link rel="manifest" href="/manifest.json">
      <link rel="stylesheet" href="/assets/index-a1b2.css">
      <script type="module" src="/assets/index-c3d4.js"></script>`, {
      headers: { 'Content-Type': 'text/html' },
    });
    const skipWaiting = vi.fn();
    const context = {
      URL,
      Response,
      fetch: vi.fn(async () => index.clone()),
      caches: { open: vi.fn(async () => cache) },
      self: {
        location: { origin: 'https://example.test' },
        addEventListener: (type, listener) => { listeners[type] = listener; },
        skipWaiting,
        clients: { claim: vi.fn() },
      },
    };
    vm.runInNewContext(source, context);

    let installation;
    listeners.install({ waitUntil: (promise) => { installation = promise; } });
    await installation;

    expect(context.fetch).toHaveBeenCalledWith('/index.html', { cache: 'reload' });
    expect(stored).toEqual(expect.arrayContaining(['/', '/index.html']));
    expect(added).toEqual(expect.arrayContaining([
      '/manifest.json',
      '/icons/icon.svg',
      '/assets/index-a1b2.css',
      '/assets/index-c3d4.js',
    ]));
    expect(skipWaiting).toHaveBeenCalledOnce();
  });

  it('serves cached static assets even when response Vary headers differ', async () => {
    const listeners = {};
    const cached = new Response('cached stylesheet');
    const match = vi.fn(async () => cached);
    const context = {
      URL,
      Request,
      Response,
      fetch: vi.fn(async () => { throw new Error('offline'); }),
      caches: {
        match,
        open: vi.fn(async () => ({ put: vi.fn() })),
        keys: vi.fn(async () => []),
      },
      self: {
        location: { origin: 'https://example.test' },
        addEventListener: (type, listener) => { listeners[type] = listener; },
        skipWaiting: vi.fn(),
        clients: { claim: vi.fn() },
      },
    };
    vm.runInNewContext(source, context);

    const request = new Request('https://example.test/assets/index.css');
    let responsePromise;
    let refreshPromise;
    listeners.fetch({
      request,
      respondWith: (promise) => { responsePromise = promise; },
      waitUntil: (promise) => { refreshPromise = promise; },
    });

    expect(await responsePromise).toBe(cached);
    await refreshPromise;
    expect(match).toHaveBeenCalledWith(request, { ignoreVary: true });
  });

  it('keeps the admin console network-only', async () => {
    const listeners = {};
    const live = new Response('admin');
    const context = {
      URL,
      Request,
      Response,
      fetch: vi.fn(async () => live),
      caches: {
        match: vi.fn(),
        open: vi.fn(),
        keys: vi.fn(async () => []),
      },
      self: {
        location: { origin: 'https://example.test' },
        addEventListener: (type, listener) => { listeners[type] = listener; },
        skipWaiting: vi.fn(),
        clients: { claim: vi.fn() },
      },
    };
    vm.runInNewContext(source, context);

    const request = new Request('https://example.test/admin.html');
    let responsePromise;
    listeners.fetch({ request, respondWith: (promise) => { responsePromise = promise; }, waitUntil: vi.fn() });

    expect(await responsePromise).toBe(live);
    expect(context.fetch).toHaveBeenCalledWith(request);
    expect(context.caches.match).not.toHaveBeenCalled();
  });
});
