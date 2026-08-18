import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, OfflineManager, getQuickUnlockConfig, loadSettings, removeQuickUnlockConfig, saveQuickUnlockConfig, saveSettings } from '../src/js/storage.js';

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
    expect(loadSettings().columnsPerRow).toBe('auto');
    expect(DEFAULT_SETTINGS.settingsVersion).toBe(3);
  });

  it('migrates the old default custom mode once and still allows opting back into it', () => {
    vi.stubGlobal('localStorage', memoryStorage({
      '2fa_settings_v3': JSON.stringify({ sortMode: 'custom', theme: 'dark' }),
    }));
    expect(loadSettings()).toMatchObject({ sortMode: 'smart', theme: 'dark', columnsPerRow: 'auto', settingsVersion: 3 });
    expect(saveSettings({ ...DEFAULT_SETTINGS, sortMode: 'custom' }).sortMode).toBe('custom');
  });

  it('persists supported column counts and rejects invalid values', () => {
    vi.stubGlobal('localStorage', memoryStorage());
    expect(saveSettings({ ...DEFAULT_SETTINGS, columnsPerRow: '4' }).columnsPerRow).toBe('4');
    expect(saveSettings({ ...DEFAULT_SETTINGS, columnsPerRow: '9' }).columnsPerRow).toBe('auto');
  });

  it('persists the oldest-used sorting mode', () => {
    vi.stubGlobal('localStorage', memoryStorage());
    expect(saveSettings({ ...DEFAULT_SETTINGS, sortMode: 'stale' }).sortMode).toBe('stale');
  });

  it('defaults copy vibration on and preserves an explicit opt-out', () => {
    vi.stubGlobal('localStorage', memoryStorage());
    expect(loadSettings().vibrateOnCopy).toBe(true);
    expect(saveSettings({ ...DEFAULT_SETTINGS, vibrateOnCopy: false }).vibrateOnCopy).toBe(false);
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

describe('quick unlock configuration', () => {
  it('stores PIN verification metadata per account without storing the PIN', () => {
    const storage = memoryStorage();
    vi.stubGlobal('localStorage', storage);
    saveQuickUnlockConfig('个人', { salt: 'salt', hash: 'hash', iterations: 200_000 });
    expect(getQuickUnlockConfig('个人')).toEqual({ salt: 'salt', hash: 'hash', iterations: 200_000 });
    expect(getQuickUnlockConfig('工作')).toBeNull();
    expect(storage.getItem('2fa_quick_unlock_v1')).not.toContain('123456');
    removeQuickUnlockConfig('个人');
    expect(getQuickUnlockConfig('个人')).toBeNull();
  });
});
