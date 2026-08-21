import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const app = await readFile(new URL('../src/js/app.js', import.meta.url), 'utf8');
const styles = await readFile(new URL('../src/styles.css', import.meta.url), 'utf8');
const ui = await readFile(new URL('../src/js/ui.js', import.meta.url), 'utf8');
const passwordGenerator = await readFile(new URL('../src/js/password-generator.js', import.meta.url), 'utf8');

describe('static application shell', () => {
  it('uses a strict CSP and contains no inline event handlers', () => {
    expect(html).toContain("script-src 'self'");
    expect(html).toContain("script-src 'self' https://static.cloudflareinsights.com");
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toContain("'unsafe-inline'");
  });

  it('sends credentials when Cloudflare Access fetches the PWA manifest', () => {
    expect(html).toContain('<link rel="manifest" href="/manifest.json" crossorigin="use-credentials">');
    expect(html).toContain("manifest-src 'self'");
  });

  it('loads the external theme boot script before the stylesheet', () => {
    const themeBoot = html.indexOf('<script src="/theme-boot.js"></script>');
    const stylesheet = html.indexOf('<link rel="stylesheet" href="/src/styles.css">');
    expect(themeBoot).toBeGreaterThan(-1);
    expect(themeBoot).toBeLessThan(stylesheet);
  });

  it('keeps the login view hidden until session restoration chooses the initial screen', () => {
    expect(html).toContain('<html lang="zh-CN" data-theme="light" class="app-booting">');
    expect(html).toContain('id="app-boot-screen"');
    expect(html).toContain('正在检查本机加密会话');
    expect(styles).toContain('.app-booting .app-boot-screen { display: grid; }');
    expect(styles).toContain('.app-booting .shell { display: none; }');
    expect(app).toContain("document.documentElement.classList.remove('app-booting')");
    expect(app).toMatch(/function showAuthScreen[\s\S]*?finishInitialBoot\(\);\r?\n}/);
    expect(app).toMatch(/function showMainApp[\s\S]*?finishInitialBoot\(\);\r?\n}/);
  });

  it('does not clear the saved session when a page refresh looks like a background transition', () => {
    expect(app).toContain('hiddenLockTimer: null');
    expect(app).toContain("document.addEventListener('visibilitychange'");
    expect(app).toContain('state.hiddenLockTimer = setTimeout(() => {');
    expect(app).toContain("}, 300)");
    expect(app).toMatch(/window\.addEventListener\('beforeunload'[\s\S]*?clearTimeout\(state\.hiddenLockTimer\)/);
    expect(app).toContain("recordSource = 'cloud'");
    expect(app).toContain("record.version || VAULT_VERSION");
    expect(app).toContain("console.warn('Session cloud snapshot cache failed:'");
    expect(app).toContain('for (const accountName of sessionAccounts)');
    expect(app).toContain('if (await restoreSession(accountName)) return');
  });

  it('shows the verified Cloudflare Access identity without replacing the vault master password', () => {
    expect(html.match(/data-access-identity/g)).toHaveLength(2);
    expect(html.match(/data-access-email/g)).toHaveLength(2);
    expect(html).toContain('Cloudflare Access 已验证');
    expect(html).toContain('保险库仍需主密码解密');
    expect(app).toContain('apiGetAccessIdentity');
    expect(app).toContain('function renderAccessIdentity()');
    expect(app).toContain("$$('[data-access-identity]')");
    expect(styles).toContain('.access-identity-card { display: flex;');
    expect(styles).toContain('.access-identity-inline { display: flex;');
  });

  it('uses a responsive 3D gradient background with an accessible static fallback', () => {
    expect(styles).toContain('body::before, body::after');
    expect(styles).toContain('@keyframes ambient-orbit');
    expect(styles).toContain('@keyframes perspective-grid-drift');
    expect(styles).toContain('transform: perspective(620px) rotateX(66deg)');
    expect(styles).toContain('body::before, body::after { animation: none !important; }');
  });

  it('contains the core accessible views and dialogs', () => {
    for (const id of ['unlock-screen', 'main-app', 'token-list', 'add-modal', 'quick-group-modal', 'token-workflow-modal', 'workflow-protection-modal', 'workflow-edit-modal', 'workflow-run-modal', 'confirm-modal', 'rename-group-modal', 'settings-modal', 'import-modal', 'conflict-modal']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('role="dialog"');
  });

  it('offers accessible item-level choices for multi-device conflicts', () => {
    for (const id of ['conflict-summary', 'local-conflict-info', 'cloud-conflict-info', 'conflict-list', 'conflict-selection-status', 'conflict-apply']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(html).toContain('data-conflict-all="local"');
    expect(html).toContain('data-conflict-all="cloud"');
    expect(app).toContain('createConflictPlan(localVault, cloudVault)');
    expect(app).toContain('mergeConflictPlan(');
    expect(app).toContain('不同内容：');
    const sideSummary = app.slice(app.indexOf('function conflictSideSummary'), app.indexOf('function renderConflictPlan'));
    expect(sideSummary).not.toContain('item.secret');
    expect(sideSummary).not.toContain('item.content');
  });

  it('creates and automatically links a new token without discarding the workflow draft', () => {
    expect(html).toContain('id="workflow-create-key"');
    expect(html).toContain('aria-describedby="workflow-key-hint"');
    expect(app).toContain('workflowAddKeyReturn: false');
    expect(app).toContain('function openAddKeyFromWorkflow()');
    expect(app).toContain('state.editingWorkflowLinks.push(workflowLinkSnapshot(key))');
    expect(app).toMatch(/#workflow-edit-modal'[\s\S]*?if \(state\.workflowAddKeyReturn\) return;/);
    expect(app).toContain("openModal('workflow-edit-modal', '#workflow-create-key')");
    expect(app).toContain('验证码已创建并关联到当前场景');
  });

  it('requires a hashed secondary password before editing workflow content', () => {
    expect(html).toContain('id="workflow-protection-modal"');
    expect(html).toContain('id="workflow-password-manage"');
    expect(html).toContain('忘记编辑密码？使用主密码重设');
    expect(app).toContain('deriveWorkflowProtectionHash');
    expect(app).toContain('WORKFLOW_EDIT_UNLOCK_MS');
    expect(app).toMatch(/function openWorkflowEditor[\s\S]*?workflowEditAccessActive\(\)/);
    expect(app).toContain('state.workflowEditUnlockedUntil = Date.now() + WORKFLOW_EDIT_UNLOCK_MS');
    expect(app).toContain('await aesKeysEqual(masterKey, state.masterKey)');
    expect(app).not.toContain('workflowProtection.password');
  });

  it('dismisses modal backdrops only after a stationary pointer gesture', () => {
    expect(ui).toContain("document.addEventListener('pointerdown'");
    expect(ui).toContain("document.addEventListener('pointerup'");
    expect(ui).toContain('BACKDROP_DRAG_TOLERANCE');
    expect(ui).toContain('event.target !== started.overlay');
    expect(ui).not.toContain("document.addEventListener('click', (event) => {\n    const overlay");
  });

  it('moves focus before hiding dialogs and marks hidden dialogs inert', () => {
    const closeModal = ui.slice(ui.indexOf('export function closeModal'), ui.indexOf('export function askConfirm'));
    expect(closeModal.indexOf('modal.contains(document.activeElement)')).toBeGreaterThan(-1);
    expect(closeModal.indexOf("modal.setAttribute('aria-hidden', 'true')")).toBeGreaterThan(closeModal.indexOf('modal.contains(document.activeElement)'));
    expect(closeModal).toContain('modal.inert = true');
    expect(ui).toContain('modal.inert = false');
    expect(ui).toContain("modal.inert = modal.classList.contains('hidden')");
  });

  it('provides an accessible responsive back-to-top control', () => {
    expect(html).toContain('id="back-to-top"');
    expect(html).toContain('aria-label="返回页面顶部"');
    expect(app).toContain("window.addEventListener('scroll', queueBackToTopUpdate, { passive: true })");
    expect(app).toContain("matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'");
    expect(styles).toContain('.back-to-top { position: fixed;');
    expect(styles).toContain('width: 48px; height: 48px;');
    expect(styles).toContain('env(safe-area-inset-bottom)');
  });

  it('keeps mobile toast feedback clear of navigation and fixed controls', () => {
    expect(html).toContain('id="app-toast"');
    expect(html).toContain('role="status" aria-live="polite"');
    expect(styles).toContain('.toast { top: auto; bottom: max(18px, calc(env(safe-area-inset-bottom) + 18px));');
    expect(styles).toContain('.toast-action { min-height: 44px;');
    expect(styles).toContain('#back-to-top.visible ~ .toast { bottom: max(78px, calc(env(safe-area-inset-bottom) + 78px));');
    expect(styles).toContain('body.bulk-mode .toast { bottom: max(268px, calc(env(safe-area-inset-bottom) + 268px));');
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
    expect(html).toContain('id="workflow-columns"');
    expect(app).toContain("workflowColumnsPerRow: event.target.value");
    expect(app).toContain('function applyWorkflowColumnsPerRow');
    expect(styles).toContain('.workflow-note-grid[data-columns="4"]');
    expect(styles).toContain('.workflow-heading-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); align-items: end; }');
  });

  it('supports encrypted notes when adding, editing, displaying, and searching keys', () => {
    expect(html).toContain('id="add-note"');
    expect(html).toContain('id="edit-note"');
    expect(html).toContain('maxlength="500"');
    expect(app).toContain('class="token-note"');
    expect(app).toContain('${key.note}');
  });

  it('stores encrypted workflow notes with ordered 2FA links and a guided run view', () => {
    for (const id of ['vault-view-tabs', 'workflow-view', 'workflow-note-list', 'workflow-form', 'workflow-title', 'workflow-group', 'workflow-group-options', 'workflow-group-filter', 'workflow-content', 'workflow-character-count', 'workflow-generate-secret', 'workflow-content-preview', 'workflow-key-combobox', 'workflow-key-filter', 'workflow-key-filter-status', 'workflow-key-select', 'workflow-key-dropdown', 'workflow-key-options', 'workflow-selected-keys', 'workflow-run-content', 'workflow-run-keys']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(html).toContain('data-vault-view="workflow"');
    expect(html).toContain('操作流程（Markdown）');
    expect(html).toContain('换行不再自动变成步骤');
    expect(app).toContain('workflowNotes: state.workflowNotes');
    expect(app).toContain('deletedWorkflowNotes: state.deletedWorkflowNotes');
    expect(app).toContain('state.editingWorkflowLinks.push(workflowLinkSnapshot(key))');
    expect(html).toContain('id="token-workflow-list"');
    expect(html).toContain('id="token-workflow-selection-count"');
    expect(html).toContain('id="token-workflow-filter"');
    expect(html).toContain('id="token-workflow-no-results"');
    expect(app).toContain('data-action="link-workflows"');
    expect(app).toContain('syncWorkflowLinksForKey(state.workflowNotes, key, state.editingTokenWorkflowNoteIds)');
    expect(app).toContain("$('#token-workflow-filter').addEventListener('input', renderTokenWorkflowPicker)");
    expect(app).toContain('matchesWorkflowNoteFilter(note, query)');
    expect(styles).toContain('.token-workflow-option { display: flex; min-height: 58px;');
    expect(app).toContain('renderWorkflowMarkdownPreview()');
    expect(app).toContain('renderMarkdown(note.content, workflowSecretStores.list)');
    expect(app).toContain('data-workflow-group-filter=');
    expect(app).toContain("group: $('#workflow-group').value");
    expect(app).toContain('function renderWorkflowGroupFilters()');
    expect(app).toContain("matchesKeyFilter(key, query)");
    expect(app).toContain("$('#workflow-key-filter').addEventListener('input', renderWorkflowKeyPicker)");
    expect(app).toContain("$('#workflow-key-options').addEventListener('click'");
    expect(app).toContain('openWorkflowKeyDropdown()');
    expect(app).toContain('没有匹配的 2FA 条目');
    expect(styles).toContain('.workflow-key-dropdown { padding: 10px;');
    expect(app).toContain('data-workflow-link-action="up"');
    expect(app).toContain('data-workflow-run-key-id=');
    expect(app).toContain('await copyKeyCode(key, null)');
    expect(app).toContain("const cloudSaved = await saveVault({ silent: true, cloudRetries: 2 })");
    expect(app).toContain("const action = previous ? '使用场景已更新' : '使用场景已创建'");
    expect(app).toContain('`${action}，已同步到云端`');
    expect(app).toContain("actionLabel: '立即同步'");
    expect(app).toContain('onAction: manualSync');
    expect(styles).toContain('.workflow-note-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));');
    expect(styles).toContain('.workflow-markdown-editor { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));');
    expect(styles).toContain('.markdown-body code {');
    expect(styles).toContain('.workflow-order-button { display: inline-grid; width: 44px; height: 44px;');
    expect(html).toContain('id="workflow-sort"');
    expect(app).toContain('compareSmartWorkflowNotes(left, right, now)');
    expect(app).toContain('note.useCount = Math.max(0, Number(note.useCount || 0)) + 1');
    expect(app).toContain('class="workflow-note-card${frequent ? \' frequent\' : \'\'}"');
    expect(app).toContain('class="usage-badge recent"');
    expect(app).toContain('data-workflow-action="favorite"');
    expect(styles).toContain('.workflow-note-card.frequent::before');
  });

  it('inserts a masked random password and prefills the active workflow group for new scenes', () => {
    expect(html).toContain('id="workflow-generate-secret"');
    expect(html).toContain('生成并插入密码');
    expect(app).toContain("import { generatePassword, generatePasswords } from './password-generator.js'");
    expect(app).toContain('function insertGeneratedWorkflowPassword()');
    expect(app).toContain("exclude: 'iIl1Lo0O'");
    expect(app).toContain("import { encodeWorkflowSecretMarker } from './workflow-secrets.js'");
    expect(app).toContain('const marker = encodeWorkflowSecretMarker(password)');
    expect(app).toContain("$('#workflow-generate-secret').addEventListener('click', insertGeneratedWorkflowPassword)");
    expect(app).toContain('function selectedWorkflowGroupForNewNote()');
    expect(app).toContain("note ? (note.group || '') : selectedWorkflowGroupForNewNote()");
    expect(styles).toContain('.workflow-editor-tools { display: flex;');
  });

  it('resolves workflow passwords from volatile memory instead of DOM attributes', () => {
    expect(app).toContain('const workflowSecretStores = {');
    expect(app).toContain("event.target.closest('[data-secret-ref]')");
    expect(app).toContain('workflowSecretStores.run.get(reference)');
    expect(app).toContain('workflowSecretStores.editor.clear()');
    expect(app).toContain('workflowSecretStores.run.clear()');
    expect(app).not.toContain('decodeMarkdownSecret');
    expect(app).not.toContain('dataset.secretCopy');
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
      'changed-password-confirm', 'workflow-protection-current', 'workflow-protection-new',
      'workflow-protection-confirm',
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
    expect(html.match(/<option value="stale">最久未使用<\/option>/g)).toHaveLength(3);
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
    expect(app).toContain('state.deletedWorkflowNotes.unshift({ ...note, deletedAt: Date.now() })');
    expect(app).toContain('data-trash-kind="workflow"');
  });

  it('shows token and workflow group filters as direct accessible chips', () => {
    expect(html).toContain('id="group-filters" class="group-filter-chips" role="group"');
    expect(html).toContain('id="workflow-group-filter" class="group-filter-chips" role="group"');
    expect(html).not.toContain('id="group-filters" data-searchable-filter');
    expect(html).not.toContain('id="workflow-group-filter" data-searchable-filter');
    expect(app).toContain('data-token-group-filter=');
    expect(app).toContain('data-workflow-group-chip=');
    expect(app).toContain('aria-pressed="${String(active)}"');
    expect(app).toContain("$('#group-filters').addEventListener('click'");
    expect(app).toContain("$('#workflow-group-filter').addEventListener('click'");
    expect(styles).toContain('.group-filter-chips { display: flex; min-width: 0; min-height: 44px;');
    expect(styles).toContain('.group-filter-chip { display: inline-flex;');
    expect(styles).toContain('.group-filter-chip.active { color: white;');
  });

  it('filters tokens that are not linked to an active workflow', () => {
    expect(app).toContain('function getLinkedWorkflowKeyIds()');
    expect(app).toContain("{ value: '__unlinked_workflow', label: '未关联场景'");
    expect(app).toContain("state.groupFilter === '__unlinked_workflow'");
    expect(app).toContain('!linkedWorkflowKeyIds.has(key.id)');
    expect(app).toContain("relationFilterActive ? '清除关联筛选'");
  });

  it('keeps active token and workflow filters visible and easy to reset', () => {
    for (const id of ['token-filter-reset', 'token-filter-reset-label', 'workflow-filter-reset', 'workflow-filter-reset-label']) expect(html).toContain(`id="${id}"`);
    expect(app).toContain('function clearTokenFilters()');
    expect(app).toContain('function clearWorkflowFilters()');
    expect(app).toContain("$$('#clear-filters, #token-filter-reset')");
    expect(app).toContain("$$('#workflow-clear-search, #workflow-filter-reset')");
    expect(app).toContain("`清除 ${activeFilterCount} 项筛选`");
    expect(styles).toContain('.active-filter-reset { display: inline-flex; min-height: 44px;');
    expect(styles).toContain('.workflow-filter-bar .active-filter-reset { min-height: 42px;');
  });

  it('searches deleted keys and usage scenarios inside the recycle bin', () => {
    expect(html).toContain('id="trash-search"');
    expect(html).toContain('id="trash-list-summary"');
    expect(html).toContain('aria-controls="trash-list"');
    expect(app).toContain('matchesKeyFilter(item, query)');
    expect(app).toContain('matchesWorkflowNoteFilter(note, query)');
    expect(app).toContain('`显示 ${visible} / ${total} 条`');
    expect(app).toContain('data-trash-action="clear-search"');
    expect(styles).toContain('.trash-filter-bar { display: flex;');
  });

  it('opens the shared recycle bin directly from usage scenarios', () => {
    expect(html).toContain('id="workflow-trash-open"');
    expect(html.match(/class="[^"]*trash-open/g)).toHaveLength(2);
    expect(html.match(/class="[^"]*trash-count/g)).toHaveLength(2);
    expect(app).toContain("for (const badge of $$('.trash-count')) badge.textContent = trashCount");
    expect(app).toContain("for (const button of $$('.trash-open')) button.addEventListener('click', openTrashModal)");
    expect(styles).toContain('.workflow-heading-buttons { grid-column: 1 / -1; display: grid;');
  });

  it('keeps one complete import and export entry inside settings', () => {
    const settingsModal = html.indexOf('id="settings-modal"');
    const settingsImport = html.indexOf('id="settings-import-open"');
    const settingsExport = html.indexOf('id="settings-export-open"');
    expect(settingsImport).toBeGreaterThan(settingsModal);
    expect(settingsExport).toBeGreaterThan(settingsModal);
    for (const id of ['import-open', 'export-open', 'workflow-import-open', 'workflow-export-open', 'backup-reminder-export', 'bulk-export']) {
      expect(html).not.toContain(`id="${id}"`);
    }
    expect(html).toContain('完整导出包含验证码、使用场景和回收站；导入会同时恢复验证码与使用场景');
    expect(html).toContain('id="backup-reminder-settings"');
    expect(app).toContain("$('#settings-import-open').addEventListener('click'");
    expect(app).toContain("$('#settings-export-open').addEventListener('click'");
    expect(app).toContain("$('#backup-reminder-settings').addEventListener('click', openSettingsDialog)");
    expect(app).toContain("format: '2fa-authenticator-backup'");
    expect(app).toContain('将导出 ${state.keys.length} 个验证码、${state.workflowNotes.length} 个使用场景和回收站数据');
    expect(app).toContain('state.deletedItems.length + state.deletedWorkflowNotes.length > 0');
    expect(app).not.toContain('2fa-workflow-backup');
    expect(app).not.toContain('importScope');
    expect(app).not.toContain('exportScope');
    expect(styles).toContain('.settings-backup-panel { display: flex;');
  });

  it('provides a secure inline password generator tab with local history', () => {
    const workflowTab = html.indexOf('id="workflow-tab"');
    const passwordGeneratorTab = html.indexOf('id="password-generator-tab"');
    const tokenView = html.indexOf('id="tokens-view"');
    expect(passwordGeneratorTab).toBeGreaterThan(workflowTab);
    expect(passwordGeneratorTab).toBeLessThan(tokenView);
    expect(html).toContain('id="password-generator-tab" type="button" role="tab"');
    expect(html).toContain('aria-controls="password-generator-view" data-vault-view="password"');
    expect(html).toContain('id="password-generator-view" class="password-generator-view hidden" role="tabpanel"');
    expect(html).not.toContain('id="password-generator-modal"');
    const generateButton = html.indexOf('id="password-generate"');
    const currentResults = html.indexOf('id="password-results"');
    const generatorForm = html.indexOf('id="password-generator-form"');
    const passwordHistory = html.indexOf('id="password-history"');
    expect(generateButton).toBeLessThan(currentResults);
    expect(currentResults).toBeLessThan(generatorForm);
    expect(generatorForm).toBeLessThan(passwordHistory);
    expect(html).toContain('form="password-generator-form">生成密码</button>');
    expect(html).toContain('>当前生成结果</h3>');
    expect(html).toContain('<h3>生成配置</h3>');
    expect(html).toContain('启用历史时最多保存最近 100 条到当前浏览器');
    expect(html).toContain('使用当前保险库密钥加密后保存在本地');
    for (const id of ['password-lowercase', 'password-uppercase', 'password-numbers', 'password-symbols', 'password-length', 'password-count', 'password-exclude-enabled', 'password-excluded-chars', 'password-copy-all', 'password-history-enabled', 'password-history-clear', 'password-history-list']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(app).toContain("generatePasswords(passwordGeneratorOptions())");
    expect(app).toContain("generatedPasswords.fill('')");
    expect(app).toMatch(/function clearSensitiveState[\s\S]*?clearGeneratedPasswords\(\)/);
    expect(app).toContain("setHidden('#password-generator-view', state.vaultView !== 'password')");
    expect(app).toContain('function resetPasswordGeneratorView()');
    expect(app).toContain('async function preparePasswordGeneratorView()');
    expect(app).not.toContain("openModal('password-generator-modal'");
    expect(app).toContain("copyText(generatedPasswords.join('\\n')");
    expect(app).toContain("const PASSWORD_HISTORY_LIMIT = 100");
    expect(app).toContain("await encryptJson(passwordHistory, state.masterKey)");
    expect(app).toContain("await decryptJson(encrypted, state.masterKey)");
    expect(app).toContain("localStorage.removeItem(passwordHistoryStorageKey())");
    expect(app).toContain("savePasswordHistoryEnabled(event.target.checked)");
    expect(app).toContain("clearPasswordHistoryMemory()");
    expect(app).toContain("await reencryptPasswordHistory(nextKey)");
    expect(passwordGenerator).toContain('cryptoSource.getRandomValues(value)');
    expect(passwordGenerator).toContain('Math.floor(UINT32_RANGE / max) * max');
    expect(styles).toContain('.password-generator-view { outline: 0;');
    expect(styles).toContain('.password-generator-card { padding:');
    expect(styles).toContain('.password-results.password-results-primary { margin: 0 0 20px;');
    expect(styles).toContain('.password-config-header { display: flex;');
    expect(styles).toContain('.password-character-options { display: grid;');
    expect(styles).toContain('.password-result-row { display: flex;');
    expect(styles).toContain('.password-history-content { display: grid;');
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
    expect(app).toContain('const icon = getKeyIcon(candidate)');
    expect(app).toContain('token-icon import-preview-icon');
    expect(app).toContain('共 <strong>${totalCount}</strong> 条');
    expect(app).toContain('重名时自动重命名');
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
    for (const id of ['multi-select-toggle', 'multi-select-tools', 'select-visible', 'bulk-actions', 'bulk-group-select', 'bulk-favorite', 'bulk-unfavorite', 'bulk-delete', 'bulk-cancel']) {
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
    expect(html).toContain('id="workflow-search"');
    expect(html).toContain('id="workflow-no-results"');
    expect(html).toContain('id="install-app"');
    expect(html).toContain('id="trash-retention-days"');
    expect(html).toContain('id="vault-eyebrow"');
    expect(app).toContain("document.addEventListener('compositionstart'");
    expect(app).toContain("event.key.toLocaleLowerCase() === 'n'");
    expect(app).toContain("state.vaultView === 'workflow' ? '#workflow-search' : '#search-input'");
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
    expect(html).toContain('class="account-switcher"');
    expect(html).toContain('class="toolbar-primary"');
    expect(html).toContain('class="toolbar-controls"');
    expect(html).toContain('class="toolbar-heading"');
    expect(app).toContain('class="token-badges"');
    expect(styles).toContain('.vault-view-tabs { position: sticky;');
    expect(styles).toContain('.workflow-heading-actions { display: grid;');
    expect(styles).toContain('@container token-card');
  });

  it('keeps network feedback in normal flow so it cannot cover mobile actions', () => {
    const toolbarMeta = html.indexOf('class="toolbar-meta"');
    const networkStatus = html.indexOf('id="network-status"');
    const toolbarEnd = html.indexOf('id="multi-select-tools"');
    expect(toolbarMeta).toBeGreaterThan(-1);
    expect(networkStatus).toBeGreaterThan(toolbarMeta);
    expect(networkStatus).toBeLessThan(toolbarEnd);
    expect(html.match(/id="network-status"/g)).toHaveLength(1);
    expect(styles).toContain('.toolbar-meta-status { display: flex; min-width: 0;');
    expect(styles).toContain('.network-status { display: inline-flex; min-height: 28px;');
    expect(styles).toContain('.offline-banner { position: sticky; top: 0;');
    expect(styles).toContain('.toolbar { position: sticky; top: calc(72px + var(--offline-banner-offset, 0px));');
    expect(styles).toContain('.toast { position: fixed; top: calc(18px + var(--offline-banner-offset, 0px));');
    expect(ui).toContain("setHidden(banner, isOnline);");
    expect(ui).toContain("offlineBannerObserver = new ResizeObserver(() => updateOfflineBannerOffset(banner));");
    expect(ui).toContain("const offset = banner.classList.contains('hidden') ? 0 : banner.offsetHeight;");
    expect(ui).toContain("document.documentElement.style.setProperty('--offline-banner-offset', `${offset}px`);");
    expect(styles).not.toContain('.network-status { position: fixed;');
  });

  it('offers a one-click manual cloud sync with visible feedback', () => {
    expect(html).toContain('id="sync-now"');
    expect(html).toContain('aria-label="立即与云端同步"');
    expect(app).toContain("$('#sync-now').addEventListener('click', manualSync)");
    expect(app).toContain('async function performSyncCheck({ preserveCurrentLocal = false } = {})');
    expect(app).toContain('async function manualSync()');
    expect(app).toContain('async function preserveCurrentVaultForManualSync()');
    expect(app).toContain('if (!saved) throw new Error(\'无法保存当前本机数据，已取消同步以防止数据被覆盖\')');
    expect(app).toContain('const result = await performSyncCheck({ preserveCurrentLocal: true })');
    expect(app.indexOf('if (preserveCurrentLocal) await preserveCurrentVaultForManualSync();')).toBeLessThan(app.indexOf('const cloud = await loadCloudRecord(state.keyHash);'));
    expect(app).toContain("button.classList.add('syncing')");
    expect(app).toContain('showToast(result.message');
    expect(styles).toContain('.icon-btn.syncing svg { animation: app-boot-spin 900ms linear infinite; }');
    expect(app).toContain('const uploaded = await saveVault({ silent: true })');
    expect(app).toContain("{ ok: false, message: '云端暂无数据，但上传失败；更改已保存在本机' }");
    expect(app).toContain('cloud.version || VAULT_VERSION');
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

  it('autosaves encrypted drafts for new tokens and usage scenarios', () => {
    for (const id of ['add-draft-status', 'add-draft-status-text', 'add-draft-clear', 'workflow-draft-status', 'workflow-draft-status-text', 'workflow-draft-clear']) {
      expect(html).toContain(`id="${id}"`);
    }
    expect(html.match(/class="draft-status hidden" role="status" aria-live="polite"/g)).toHaveLength(2);
    expect(app).toContain("import { EncryptedDraftStore } from './drafts.js'");
    expect(app).toContain("scheduleFormDraft('token')");
    expect(app).toContain("scheduleFormDraft('workflow')");
    expect(app).toContain("await encryptedDrafts.load(state.keyHash, 'token', state.masterKey)");
    expect(app).toContain("await encryptedDrafts.load(state.keyHash, 'workflow', state.masterKey)");
    expect(app).toContain("if (!previous) clearFormDraft('workflow')");
    expect(app).toContain("clearFormDraft('token')");
    expect(app).toContain("if (type === 'workflow' && $('#workflow-id').value) return");
    expect(app).toContain("encryptedDrafts.prepareMigration(oldHash, nextHash, state.masterKey, nextKey)");
    expect(app).toContain("$('#add-modal').addEventListener('modal:close', () => { flushFormDraft('token'); })");
    expect(app).toContain("window.addEventListener('pagehide', () => { flushPendingFormDrafts(); })");
    expect(styles).toContain('.draft-status {');
    expect(styles).toContain('.draft-status button:focus-visible');
  });
});
