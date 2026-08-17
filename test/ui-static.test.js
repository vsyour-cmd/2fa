import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const app = await readFile(new URL('../src/js/app.js', import.meta.url), 'utf8');

describe('static application shell', () => {
  it('uses a strict CSP and contains no inline event handlers', () => {
    expect(html).toContain("script-src 'self'");
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toContain("'unsafe-inline'");
  });

  it('contains the core accessible views and dialogs', () => {
    for (const id of ['unlock-screen', 'main-app', 'token-list', 'add-modal', 'settings-modal', 'import-modal', 'conflict-modal']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('role="dialog"');
  });

  it('defines every statically referenced application element', () => {
    const referencedIds = [...app.matchAll(/\$\(\s*['"]#([A-Za-z][\w-]*)['"]\s*\)/g)].map((match) => match[1]);
    for (const id of new Set(referencedIds)) expect(html, `missing #${id}`).toContain(`id="${id}"`);
  });
});
