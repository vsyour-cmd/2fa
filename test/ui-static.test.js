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

  it('loads the external theme boot script before the stylesheet', () => {
    const themeBoot = html.indexOf('<script src="/theme-boot.js"></script>');
    const stylesheet = html.indexOf('<link rel="stylesheet" href="/src/styles.css">');
    expect(themeBoot).toBeGreaterThan(-1);
    expect(themeBoot).toBeLessThan(stylesheet);
  });

  it('contains the core accessible views and dialogs', () => {
    for (const id of ['unlock-screen', 'main-app', 'token-list', 'add-modal', 'quick-group-modal', 'confirm-modal', 'rename-group-modal', 'settings-modal', 'import-modal', 'conflict-modal']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('role="dialog"');
  });

  it('defines every statically referenced application element', () => {
    const referencedIds = [...app.matchAll(/\$\(\s*['"]#([A-Za-z][\w-]*)['"]\s*\)/g)].map((match) => match[1]);
    for (const id of new Set(referencedIds)) expect(html, `missing #${id}`).toContain(`id="${id}"`);
  });

  it('offers direct group assignment from each token card', () => {
    expect(html).toContain('id="quick-group-form"');
    expect(html).toContain('id="quick-group"');
    expect(app).toContain('data-action="quick-group"');
    expect(app).toContain("openQuickGroupModal(key.id)");
  });

  it('offers a persistent per-row column selector', () => {
    expect(html).toContain('id="columns-quick"');
    expect(app).toContain("columnsPerRow: event.target.value");
    expect(app).toContain("grid.dataset.columns = value");
  });

  it('supports encrypted notes when adding, editing, displaying, and searching keys', () => {
    expect(html).toContain('id="add-note"');
    expect(html).toContain('id="edit-note"');
    expect(html).toContain('maxlength="500"');
    expect(app).toContain('class="token-note"');
    expect(app).toContain('${key.note}');
  });

  it('waits for a fresh verification code during the final second', () => {
    expect(app).toContain('验证码即将过期，正在复制新码');
    expect(app).toContain('验证码即将过期，注意尽快粘贴');
    expect(app).toContain("classList.add('waiting-next-code')");
    expect(app).toContain('getNextPeriodDelay(key, startedAt)');
  });

  it('uses accessible application dialogs instead of native prompt and confirm calls', () => {
    expect(app).not.toMatch(/\bprompt\s*\(/);
    expect(app).not.toMatch(/\bconfirm\s*\(/);
    expect(html).toContain('id="confirm-modal"');
    expect(html).toContain('id="rename-group-modal"');
  });
});
