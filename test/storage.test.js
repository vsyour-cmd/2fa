import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, OfflineManager, loadSettings, saveSettings } from '../src/js/storage.js';

function memoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
}

afterEach(() => vi.unstubAllGlobals());

describe('settings migration', () => {
  it('uses smart ordering for new installations', () => {
    vi.stubGlobal('localStorage', memoryStorage());
    expect(loadSettings().sortMode).toBe('smart');
    expect(DEFAULT_SETTINGS.settingsVersion).toBe(2);
  });

  it('migrates the old default custom mode once and still allows opting back into it', () => {
    vi.stubGlobal('localStorage', memoryStorage({
      '2fa_settings_v3': JSON.stringify({ sortMode: 'custom', theme: 'dark' }),
    }));
    expect(loadSettings()).toMatchObject({ sortMode: 'smart', theme: 'dark', settingsVersion: 2 });
    expect(saveSettings({ ...DEFAULT_SETTINGS, sortMode: 'custom' }).sortMode).toBe('custom');
  });
});

describe('offline conflict detection', () => {
  const manager = Object.create(OfflineManager.prototype);

  it('uploads a local edit automatically when its cloud base is unchanged', () => {
    expect(manager.detectConflict({ locallyModified: true, baseCloudUpdatedAt: 100 }, 100)).toBe(false);
  });

  it('requires a choice when local and cloud both changed', () => {
    expect(manager.detectConflict({ locallyModified: true, baseCloudUpdatedAt: 100 }, 200)).toBe(true);
  });

  it('treats an old cache without a cloud base conservatively', () => {
    expect(manager.detectConflict({ locallyModified: true }, 200)).toBe(true);
    expect(manager.detectConflict({ locallyModified: false }, 200)).toBe(false);
  });
});
