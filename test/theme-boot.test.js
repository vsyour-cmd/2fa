import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

const source = await readFile(new URL('../public/theme-boot.js', import.meta.url), 'utf8');

function runThemeBoot({ stored = null, prefersDark = false, storageError = false } = {}) {
  const themeColor = { content: '#2563eb' };
  const document = {
    documentElement: { dataset: { theme: 'light' }, style: {} },
    querySelector: () => themeColor,
  };
  const localStorage = {
    getItem() {
      if (storageError) throw new Error('Storage unavailable');
      return stored;
    },
  };

  vm.runInNewContext(source, {
    document,
    localStorage,
    matchMedia: () => ({ matches: prefersDark }),
  });

  return { document, themeColor };
}

describe('theme boot', () => {
  it('applies a saved dark theme before the application module starts', () => {
    const { document, themeColor } = runThemeBoot({ stored: JSON.stringify({ theme: 'dark' }) });
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(document.documentElement.style.colorScheme).toBe('dark');
    expect(themeColor.content).toBe('#070b14');
  });

  it('uses the system preference by default and when explicitly selected', () => {
    expect(runThemeBoot({ prefersDark: true }).document.documentElement.dataset.theme).toBe('dark');
    expect(runThemeBoot({ stored: JSON.stringify({ theme: 'system' }), prefersDark: true }).document.documentElement.dataset.theme).toBe('dark');
  });

  it('keeps the light shell for a saved light theme', () => {
    const { document, themeColor } = runThemeBoot({ stored: JSON.stringify({ theme: 'light' }), prefersDark: true });
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(document.documentElement.style.colorScheme).toBeUndefined();
    expect(themeColor.content).toBe('#2563eb');
  });

  it('fails silently when settings cannot be read or parsed', () => {
    expect(() => runThemeBoot({ storageError: true })).not.toThrow();
    expect(() => runThemeBoot({ stored: '{invalid' })).not.toThrow();
  });
});
