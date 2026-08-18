import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const app = await readFile(new URL('../src/js/app.js', import.meta.url), 'utf8');
const styles = await readFile(new URL('../src/styles.css', import.meta.url), 'utf8');

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

  it('lets touch and keyboard users expand long notes without cluttering short notes', () => {
    expect(app).toContain('class="token-note-wrap"');
    expect(app).toContain('data-action="toggle-note"');
    expect(app).toContain('aria-expanded="false"');
    expect(app).toContain('updateTokenNoteControls()');
    expect(app).toContain('note.scrollHeight > lineHeight * 2 + 1');
    expect(app).toContain('noteResizeFrame = requestAnimationFrame(updateTokenNoteControls)');
    expect(app).toContain("replace(/^收起 /, '展开 ')");
    expect(app).toContain("button.setAttribute('aria-expanded', String(expanded))");
    expect(styles).toContain('.token-note-toggle { display: inline-flex; min-width: 88px; min-height: 44px;');
    expect(styles).toContain('.token-item.selectable .token-note-toggle { display: none; }');
  });

  it('explains key identity fields in both add and edit forms', () => {
    for (const prefix of ['add', 'edit']) {
      for (const field of ['name', 'issuer', 'account', 'group', 'secret', 'icon']) {
        expect(html).toContain(`aria-describedby="${prefix}-${field}-hint"`);
        expect(html).toContain(`id="${prefix}-${field}-hint"`);
      }
    }
    expect(html.match(/账号 \/ 用户标识/g)).toHaveLength(2);
    expect(html.match(/提供验证码的服务或网站/g)).toHaveLength(2);
    expect(html.match(/用于区分同一服务的不同账号/g)).toHaveLength(2);
  });

  it('explains account, security, import, export, and password-change fields', () => {
    for (const field of ['login-account', 'login-password', 'setup-account', 'auto-lock-minutes', 'import-file', 'import-text', 'import-password', 'import-strategy', 'export-format', 'export-password']) {
      expect(html).toContain(`aria-describedby="${field}-hint"`);
      expect(html).toContain(`id="${field}-hint"`);
    }
    expect(html).toContain('aria-describedby="setup-password-hint setup-strength-label"');
    expect(html).toContain('id="setup-password-hint"');
    expect(html).toContain('aria-describedby="change-password-description"');
    expect(html).toContain('id="change-password-description"');
    expect(html).toContain('aria-describedby="change-strength-label"');
    expect(html).toContain('预览确认前不会写入保险库');
  });

  it('offers accessible visibility toggles for every sensitive input', () => {
    const sensitiveFields = [
      'login-password', 'quick-unlock-pin', 'new-password', 'confirm-password',
      'add-secret', 'edit-secret', 'quick-unlock-new-pin', 'quick-unlock-confirm-pin',
      'import-password', 'export-password', 'current-password', 'changed-password',
      'changed-password-confirm',
    ];
    for (const field of sensitiveFields) {
      expect(html).toContain(`data-toggle-password="${field}"`);
    }
    expect(html.match(/data-toggle-password=/g)).toHaveLength(sensitiveFields.length);
    expect(html.match(/aria-pressed="false">显示<\/button>/g)).toHaveLength(sensitiveFields.length);
    expect(app).toContain("toggle.setAttribute('aria-pressed', String(reveal))");
    expect(app).toContain("modal.addEventListener('modal:close', () => concealSensitiveFields(modal))");
    expect(app).toContain("concealSensitiveFields($('#unlock-screen'))");
    expect(app).toContain("document.addEventListener('reset'");
    expect(styles).toContain('.input-action { position: absolute; top: 50%; right: 2px; min-width: 58px; height: 44px;');
    expect(styles).toContain('.input-action:active:not(:disabled) { transform: translateY(-50%) scale(0.97); }');
    expect(styles).toContain('.input-with-action .pin-input { padding-left: 70px; }');
  });

  it('shows recent use and offers an oldest-used view', () => {
    expect(html.match(/<option value="stale">最久未使用<\/option>/g)).toHaveLength(2);
    expect(app).toContain('compareStaleKeys(left, right)');
    expect(app).toContain('class="token-last-used"');
    expect(app).toContain("'从未使用'");
    expect(app).toContain('setTimeout(() => renderKeys(), 650)');
  });

  it('shows the previous, current, and next verification codes together', () => {
    expect(app).toContain('generateTOTPWindow(key.secret, cardNow, key)');
    expect(app).toContain('class="token-code-panel"');
    expect(app).toContain('class="token-code-label">当前验证码</span>');
    expect(app).toContain('class="token-code-previous"');
    expect(app).toContain('class="token-code-next"');
    expect(app).toContain('上一期');
    expect(app).toContain('下一期');
  });

  it('moves keys to a recoverable trash before permanent deletion', () => {
    expect(html).toContain('id="trash-retention-label"');
    expect(html).toContain('id="trash-retention-days"');
    expect(app).toContain('${retentionDays} 天内可以随时恢复');
    expect(app).toContain('data-action="delete">移入回收站</button>');
    expect(app).toContain('state.deletedItems.unshift({ ...removed, deletedAt: Date.now() })');
    expect(app).toContain('data-trash-action="restore">恢复</button>');
    expect(app).toContain('此操作无法撤销');
  });

  it('waits for a fresh verification code during the final second', () => {
    expect(app).toContain('验证码即将过期，正在复制新码');
    expect(app).toContain('验证码即将过期，注意尽快粘贴');
    expect(app).toContain("classList.add('waiting-next-code')");
    expect(app).toContain('getNextPeriodDelay(key, startedAt)');
  });

  it('previews every import action before applying the frozen plan', () => {
    expect(html).toContain('先解析预览，再确认写入');
    expect(html).toContain('id="import-preview"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('>预览导入</button>');
    expect(app).toContain('createImportPlan(valid, state.keys');
    expect(app).toContain('applyImportPlan(pending.plan, state.keys');
    expect(app).toContain('确认导入 ${count} 条');
    expect(app).toContain("input.addEventListener(input.matches('select, input[type=\"file\"]') ? 'change' : 'input'");
    expect(app).toContain("$('#import-modal').addEventListener('modal:close'");
    expect(app).not.toContain('解析并导入');
  });

  it('handles pasted OTPAuth text globally before preserving image paste fallback', () => {
    const pasteHandler = app.indexOf("document.addEventListener('paste'");
    const textRead = app.indexOf("clipboardData?.getData('text/plain')", pasteHandler);
    const imageRead = app.indexOf("item.type.startsWith('image/')", pasteHandler);
    expect(pasteHandler).toBeGreaterThan(-1);
    expect(textRead).toBeGreaterThan(pasteHandler);
    expect(imageRead).toBeGreaterThan(textRead);
    expect(app).toContain('/^otpauth(?:-migration)?:\\/\\//i.test(clipboardText)');
    expect(app).toContain("showToast('请先解锁保险库')");
    expect(app).toContain("showToast('剪贴板中的 OTPAuth 链接无效')");
    expect(app).toContain("openOtpAuthValue(value, 'paste')");
    expect(app).toContain('resetImportPreview({ resetForm: true })');
    expect(app).toContain('scanQrImage(imageItem.getAsFile())');
  });

  it('supports accessible bulk selection over the current filtered results', () => {
    for (const id of ['multi-select-toggle', 'multi-select-tools', 'select-visible', 'bulk-actions', 'bulk-group-select', 'bulk-favorite', 'bulk-unfavorite', 'bulk-export', 'bulk-delete', 'bulk-cancel']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(app).toContain('const visibleIds = getVisibleKeys().map((key) => key.id)');
    expect(app).toContain("if (state.multiSelectMode) {");
    expect(app).toContain("state.deletedItems.unshift(...keys.map((key) => ({ ...key, deletedAt })))");
    expect(app).toContain("state.multiSelectMode || state.settings.sortMode !== 'custom'");
    expect(app).toContain("if (event.key === 'Escape')");
    expect(app).toContain('if (state.multiSelectMode)');
    expect(app).toContain('await saveVault();');
  });

  it('adds global shortcuts, install guidance, dynamic retention, and account titles', () => {
    expect(html).toContain('快捷键：<kbd>/</kbd> 搜索');
    expect(html).toContain('id="install-app"');
    expect(html).toContain('id="trash-retention-days"');
    expect(html).toContain('id="vault-eyebrow"');
    expect(app).toContain("document.addEventListener('compositionstart'");
    expect(app).toContain("event.key.toLocaleLowerCase() === 'n'");
    expect(app).toContain("window.addEventListener('beforeinstallprompt'");
    expect(app).toContain('trashRetentionDays:');
    expect(app).toContain('document.title = `${state.accountName} · 2FA Authenticator`');
  });

  it('adds copy feedback, cloning, backup reminders, and deterministic avatar tones', () => {
    expect(html).toContain('id="vibrate-on-copy"');
    expect(html).toContain('id="duplicate-key"');
    expect(html).toContain('id="backup-reminder"');
    expect(app).toContain("if (!document.hidden) showToast('剪贴板已自动清空')");
    expect(app).toContain('navigator.vibrate?.(10)');
    expect(app).toContain('uniqueName(');
    expect(app).toContain("const LAST_EXPORT_KEY = '2fa_last_export_v1'");
    expect(app).toContain('state.keys.length >= 10');
    expect(app).toContain('avatar-tone-');
  });

  it('labels keys used during the last seven days', () => {
    expect(app).toContain('const RECENT_USAGE_WINDOW_MS = 7 * 86_400_000');
    expect(app).toContain('class="usage-badge recent"');
    expect(app).toContain('>最近使用</span>');
    expect(styles).toContain('.usage-badge.recent');
  });

  it('groups responsive toolbar controls and card status badges', () => {
    expect(html).toContain('class="header-actions"');
    expect(html).toContain('class="toolbar-primary"');
    expect(html).toContain('class="toolbar-controls"');
    expect(app).toContain('class="token-badges"');
    expect(styles).toContain('@container token-card');
  });

  it('shows offline migration QR codes and limits quick PIN unlock to a short in-tab cache', () => {
    expect(html).toContain('id="show-qr"');
    expect(html).toContain('id="edit-qr-canvas"');
    expect(html).toContain('id="quick-unlock-form"');
    expect(html).toContain('id="quick-unlock-enabled"');
    expect(app).toContain('drawQrToCanvas');
    expect(app).toContain('expiresAt: Date.now() + 5 * 60_000');
    expect(app).toContain('cache.attempts >= 3');
    expect(app).toContain('deriveQuickUnlockHash');
  });

  it('uses accessible application dialogs instead of native prompt and confirm calls', () => {
    expect(app).not.toMatch(/\bprompt\s*\(/);
    expect(app).not.toMatch(/\bconfirm\s*\(/);
    expect(html).toContain('id="confirm-modal"');
    expect(html).toContain('id="rename-group-modal"');
  });
});
