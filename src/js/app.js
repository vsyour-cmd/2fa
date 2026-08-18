import {
  PBKDF2_ITERATIONS,
  VAULT_VERSION,
  aesKeysEqual,
  decryptJson,
  deriveKey,
  deriveKeyHash,
  encryptBackup,
  encryptJson,
  exportAesKey,
  generateSalt,
  getPasswordStrength,
  importAesKey,
  validatePassword,
} from './crypto.js';
import {
  applyImportPlan,
  createImportPlan,
  parseGoogleMigrationUri,
  parseImportContent,
  validateImportedItems,
} from './importers.js';
import { QrScanner, scanQrImage } from './qr.js';
import {
  ApiError,
  OfflineManager,
  apiDelete,
  apiGet,
  apiSave,
  clearAllSessions,
  getActiveAccount,
  getKnownAccounts,
  getSession,
  getSessions,
  loadSettings,
  parseStoredCloudRecord,
  removeSession,
  saveSession,
  saveSettings,
  setActiveAccount,
} from './storage.js';
import {
  buildOtpauthUri,
  formatCode,
  generateTOTP,
  getCounter,
  getNextPeriodDelay,
  getRemainingSeconds,
  getTotpOptions,
  parseOtpauthUri,
} from './totp.js';
import {
  $,
  $$,
  applyTheme,
  askConfirm,
  askText,
  closeModal,
  getKeyIcon,
  hideError,
  openModal,
  setBusy,
  setHidden,
  setNetworkStatus,
  setupModalAccessibility,
  showError,
  showToast,
  updatePasswordStrength,
  watchSystemTheme,
} from './ui.js';
import {
  DEFAULT_ACCOUNT,
  compareSmartKeys,
  compareStaleKeys,
  downloadText,
  escapeHtml,
  formatDateTime,
  generateId,
  normalizeAccountName,
  normalizeKey,
  normalizeSecret,
  normalizeVaultData,
  uniqueName,
} from './utils.js';

const offline = new OfflineManager();
const state = {
  masterKey: null,
  keyHash: '',
  salt: '',
  accountName: '',
  keyIterations: PBKDF2_ITERATIONS.CURRENT,
  keys: [],
  deletedItems: [],
  settings: loadSettings(),
  search: '',
  groupFilter: '__all',
  renderVersion: 0,
  updateTimer: null,
  autoLockTimer: null,
  saveTimer: null,
  clipboardTimer: null,
  pendingCodeCopies: new Map(),
  conflict: null,
  draggedId: '',
  importPreview: null,
  importRevision: 0,
  multiSelectMode: false,
  selectedKeyIds: new Set(),
  exportKeyIds: null,
};

let qrScanner;

function vaultPayload() {
  return { version: VAULT_VERSION, keys: state.keys, deletedItems: state.deletedItems };
}

function useVaultData(raw) {
  const normalized = normalizeVaultData(raw);
  state.keys = normalized.keys;
  state.deletedItems = normalized.deletedItems;
}

function clearSensitiveState() {
  state.masterKey = null;
  state.keyHash = '';
  state.salt = '';
  state.accountName = '';
  state.keys = [];
  state.deletedItems = [];
  state.keyIterations = PBKDF2_ITERATIONS.CURRENT;
  state.search = '';
  state.groupFilter = '__all';
  state.conflict = null;
  state.importPreview = null;
  state.importRevision += 1;
  state.multiSelectMode = false;
  state.selectedKeyIds.clear();
  state.exportKeyIds = null;
  document.body.classList.remove('bulk-mode');
  clearTimeout(state.saveTimer);
  clearTimeout(state.clipboardTimer);
  for (const [timer, resolve] of state.pendingCodeCopies) {
    clearTimeout(timer);
    resolve(false);
  }
  state.pendingCodeCopies.clear();
  clearTimeout(state.autoLockTimer);
  if (state.updateTimer) clearInterval(state.updateTimer);
  state.updateTimer = null;
  qrScanner?.stop();
}

async function rememberCurrentSession() {
  if (!state.masterKey) return;
  saveSession({
    accountName: state.accountName,
    keyHash: state.keyHash,
    salt: state.salt,
    keyStr: await exportAesKey(state.masterKey),
    keyIterations: state.keyIterations,
  });
}

async function loadCloudRecord(keyHash) {
  return parseStoredCloudRecord(await apiGet(keyHash));
}

async function saveVault({ silent = false } = {}) {
  if (!state.masterKey || !state.keyHash) return false;
  const encryptedData = await encryptJson(vaultPayload(), state.masterKey);
  if (offline.isOnline) {
    try {
      const result = await apiSave(state.keyHash, encryptedData, state.salt, VAULT_VERSION);
      await offline.save(state.keyHash, encryptedData, state.salt, VAULT_VERSION, Number(result.updatedAt || Date.now()));
      return true;
    } catch (error) {
      console.error('Cloud save failed:', error);
      await offline.save(state.keyHash, encryptedData, state.salt, VAULT_VERSION);
      if (!silent) showToast('已保存到本机，云端同步失败');
      return false;
    }
  }
  await offline.save(state.keyHash, encryptedData, state.salt, VAULT_VERSION);
  if (!silent) showToast('已保存到本机（离线）');
  return false;
}

function scheduleSave() {
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => saveVault({ silent: true }), 900);
}

async function decryptRecord(record, password, iterations) {
  const key = await deriveKey(password, record.salt, iterations);
  const raw = await decryptJson(record.encryptedData, key);
  return { key, raw };
}

function loginCandidates(password, accountName) {
  const candidates = [{ mode: 'scoped', iterations: PBKDF2_ITERATIONS.CURRENT }];
  if (normalizeAccountName(accountName) === DEFAULT_ACCOUNT) {
    candidates.push(
      { mode: 'legacy-v2', iterations: PBKDF2_ITERATIONS.CURRENT },
      { mode: 'legacy-v1', iterations: PBKDF2_ITERATIONS.LEGACY_V1_KEY },
    );
  }
  return Promise.all(candidates.map(async (candidate) => ({
    ...candidate,
    hash: await deriveKeyHash(password, accountName, candidate.mode),
  })));
}

async function migrateLegacyVault(password, legacyHash) {
  if (!offline.isOnline) return;
  const newHash = await deriveKeyHash(password, state.accountName, 'scoped');
  const newSalt = generateSalt();
  const newKey = await deriveKey(password, newSalt, PBKDF2_ITERATIONS.CURRENT);
  const encrypted = await encryptJson(vaultPayload(), newKey);
  const result = await apiSave(newHash, encrypted, newSalt, VAULT_VERSION);
  const verification = await loadCloudRecord(newHash);
  if (!verification.exists) throw new Error('新账户数据验证失败');
  await decryptJson(verification.encryptedData, newKey);

  state.keyHash = newHash;
  state.salt = newSalt;
  state.masterKey = newKey;
  state.keyIterations = PBKDF2_ITERATIONS.CURRENT;
  await offline.save(newHash, encrypted, newSalt, VAULT_VERSION, Number(result.updatedAt || Date.now()));
  await rememberCurrentSession();
  try {
    await apiDelete(legacyHash);
    await offline.delete(legacyHash);
    showToast('旧版账户已安全迁移');
  } catch (error) {
    console.warn('Legacy cleanup deferred:', error);
    showToast('新版数据已保存，旧数据尚未清理');
  }
}

async function unlockWithPassword(password, accountName) {
  const normalizedAccount = normalizeAccountName(accountName);
  const candidates = await loginCandidates(password, normalizedAccount);
  let sawEncryptedRecord = false;

  for (const candidate of candidates) {
    let record = null;
    if (offline.isOnline) {
      try {
        const cloud = await loadCloudRecord(candidate.hash);
        if (cloud.exists) record = cloud;
      } catch (error) {
        if (!(error instanceof ApiError)) throw error;
      }
    }
    if (!record) {
      const cached = await offline.get(candidate.hash);
      if (cached) record = cached;
    }
    if (!record) continue;
    sawEncryptedRecord = true;
    try {
      const { key, raw } = await decryptRecord(record, password, candidate.iterations);
      state.masterKey = key;
      state.keyHash = candidate.hash;
      state.salt = record.salt;
      state.accountName = normalizedAccount;
      state.keyIterations = candidate.iterations;
      useVaultData(raw);
      if (candidate.mode !== 'scoped' && offline.isOnline) await migrateLegacyVault(password, candidate.hash);
      await rememberCurrentSession();
      return true;
    } catch (error) {
      console.warn('Vault decryption failed:', error);
    }
  }
  throw new Error(sawEncryptedRecord ? '密码错误或数据已损坏' : '密码错误或账户不存在');
}

async function setupAccount(password, accountName) {
  if (!offline.isOnline) throw new Error('首次创建账户需要联网');
  const normalizedAccount = normalizeAccountName(accountName);
  const scopedHash = await deriveKeyHash(password, normalizedAccount, 'scoped');
  if ((await loadCloudRecord(scopedHash)).exists || await offline.get(scopedHash)) {
    throw new Error('该账户名和密码已存在，请直接登录');
  }
  if (normalizedAccount === DEFAULT_ACCOUNT) {
    for (const mode of ['legacy-v2', 'legacy-v1']) {
      const legacyHash = await deriveKeyHash(password, normalizedAccount, mode);
      if ((await loadCloudRecord(legacyHash)).exists) throw new Error('检测到兼容账户，请直接登录');
    }
  }
  state.accountName = normalizedAccount;
  state.keyHash = scopedHash;
  state.salt = generateSalt();
  state.masterKey = await deriveKey(password, state.salt, PBKDF2_ITERATIONS.CURRENT);
  state.keyIterations = PBKDF2_ITERATIONS.CURRENT;
  state.keys = [];
  state.deletedItems = [];
  const saved = await saveVault({ silent: true });
  if (!saved) throw new Error('无法将新账户保存到云端');
  await rememberCurrentSession();
}

async function restoreSession(accountName) {
  const session = getSession(accountName);
  if (!session) return false;
  try {
    state.masterKey = await importAesKey(session.keyStr);
    state.keyHash = session.keyHash;
    state.salt = session.salt;
    state.accountName = normalizeAccountName(session.accountName);
    state.keyIterations = Number(session.keyIterations || PBKDF2_ITERATIONS.CURRENT);
    let record = null;
    if (offline.isOnline) {
      try {
        const cloud = await loadCloudRecord(state.keyHash);
        if (cloud.exists) record = cloud;
      } catch (error) {
        console.warn('Session cloud load failed:', error);
      }
    }
    if (!record) record = await offline.get(state.keyHash);
    if (!record) throw new Error('会话数据不存在');
    useVaultData(await decryptJson(record.encryptedData, state.masterKey));
    setActiveAccount(state.accountName);
    showMainApp();
    return true;
  } catch (error) {
    console.warn('Session restore failed:', error);
    removeSession(accountName);
    clearSensitiveState();
    return false;
  }
}

function showAuthScreen(accountName = '') {
  setHidden('#main-app', true);
  setHidden('#unlock-screen', false);
  $('#login-account').value = accountName || '';
  $('#login-password').value = '';
  switchAuthView('login');
  renderKnownAccounts();
  renderSessionResume();
  requestAnimationFrame(() => $('#login-account').focus());
}

function showMainApp() {
  setHidden('#unlock-screen', true);
  setHidden('#main-app', false);
  $('#search-input').value = state.search;
  renderAccountSwitch();
  pruneTrash();
  renderAll();
  startUpdateTimer();
  resetAutoLockTimer();
}

function lockCurrent() {
  const account = state.accountName;
  removeSession(account);
  clearSensitiveState();
  showAuthScreen(account);
}

function lockAll(message = '') {
  clearAllSessions();
  clearSensitiveState();
  showAuthScreen();
  if (message) showToast(message);
}

function switchAuthView(view) {
  const setup = view === 'setup';
  setHidden('#login-form', setup);
  setHidden('#setup-form', !setup);
  for (const button of $$('[data-auth-view]')) {
    const active = button.dataset.authView === view;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  }
  requestAnimationFrame(() => $(setup ? '#setup-account' : '#login-account').focus());
}

function renderKnownAccounts() {
  $('#known-accounts').innerHTML = getKnownAccounts().map((account) => `<option value="${escapeHtml(account)}"></option>`).join('');
}

function renderSessionResume() {
  const sessions = Object.values(getSessions());
  setHidden('#session-resume', sessions.length === 0);
  $('#session-buttons').innerHTML = sessions.map((session) => `<button class="btn btn-secondary" type="button" data-resume-account="${escapeHtml(session.accountName)}">${escapeHtml(session.accountName)}</button>`).join('');
}

function renderAccountSwitch() {
  const sessions = Object.values(getSessions());
  const select = $('#account-switch');
  select.innerHTML = sessions.map((session) => `<option value="${escapeHtml(session.accountName)}">${escapeHtml(session.accountName)}</option>`).join('')
    + '<option value="__other">＋ 登录其他账户</option>';
  select.value = state.accountName;
}

function resetAutoLockTimer() {
  clearTimeout(state.autoLockTimer);
  if (!state.masterKey || Number(state.settings.autoLockMinutes) <= 0) return;
  state.autoLockTimer = setTimeout(() => lockAll('由于长时间无操作，保险库已自动锁定'), Number(state.settings.autoLockMinutes) * 60_000);
}

function getGroups() {
  return [...new Set(state.keys.map((key) => key.group || '').filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
}

function updateGroupOptions() {
  $('#group-options').innerHTML = getGroups().map((group) => `<option value="${escapeHtml(group)}"></option>`).join('');
}

function renderGroupFilters() {
  const ungroupedCount = state.keys.filter((key) => !key.group).length;
  const filters = [
    { value: '__all', label: '全部', count: state.keys.length },
    ...getGroups().map((group) => ({ value: group, label: group, count: state.keys.filter((key) => key.group === group).length })),
    { value: '__ungrouped', label: '未分组', count: ungroupedCount },
  ];
  $('#group-filters').innerHTML = filters.map((filter) => {
    const active = state.groupFilter === filter.value;
    return `<button class="filter-btn${active ? ' active' : ''}" type="button" data-group-filter="${escapeHtml(filter.value)}" aria-pressed="${active}"><span>${escapeHtml(filter.label)}</span><span class="filter-count">${filter.count}</span></button>`;
  }).join('');
}

function getVisibleKeys() {
  const query = state.search.toLocaleLowerCase();
  const filtered = state.keys.filter((key) => {
    const groupMatches = state.groupFilter === '__all'
      || (state.groupFilter === '__ungrouped' ? !key.group : key.group === state.groupFilter);
    const textMatches = !query || `${key.name} ${key.issuer} ${key.account} ${key.group} ${key.note}`.toLocaleLowerCase().includes(query);
    return groupMatches && textMatches;
  });
  const now = Date.now();
  return filtered.sort((left, right) => {
    if (state.settings.sortMode === 'smart') return compareSmartKeys(left, right, now);
    if (state.settings.sortMode === 'stale') return compareStaleKeys(left, right);
    if (left.favorite !== right.favorite) return left.favorite ? -1 : 1;
    if (state.settings.sortMode === 'name') return left.name.localeCompare(right.name, 'zh-CN');
    if (state.settings.sortMode === 'recent') return Number(right.lastUsed || 0) - Number(left.lastUsed || 0) || left.name.localeCompare(right.name, 'zh-CN');
    return Number(left.order || 0) - Number(right.order || 0);
  });
}

function renderListMeta(visibleCount) {
  const total = state.keys.length;
  const filtered = Boolean(state.search) || state.groupFilter !== '__all';
  $('#list-summary').textContent = filtered ? `显示 ${visibleCount} / ${total} 个验证码` : `${total} 个验证码`;
  const hints = {
    smart: '智能排序会根据使用频次和最近使用自动调整',
    recent: '最近复制的验证码排在前面',
    stale: '从未使用和最久未使用的验证码排在前面',
    name: '按名称顺序排列，收藏仍会置顶',
    custom: '按住卡片拖拽即可调整顺序',
  };
  $('#sort-hint').textContent = hints[state.settings.sortMode] || hints.smart;
  $('#sort-quick').value = state.settings.sortMode;
  applyColumnsPerRow();
}

function applyColumnsPerRow(announce = false) {
  const grid = $('#token-list');
  const value = ['auto', '1', '2', '3', '4'].includes(String(state.settings.columnsPerRow))
    ? String(state.settings.columnsPerRow)
    : 'auto';
  if (value === 'auto') grid.removeAttribute('data-columns');
  else grid.dataset.columns = value;
  $('#columns-quick').value = value;
  if (announce) showToast(value === 'auto' ? '已启用自动列数' : `每行显示 ${value} 个`);
}

function selectedKeys() {
  const availableIds = new Set(state.keys.map((key) => key.id));
  for (const id of state.selectedKeyIds) {
    if (!availableIds.has(id)) state.selectedKeyIds.delete(id);
  }
  return state.keys.filter((key) => state.selectedKeyIds.has(key.id));
}

function renderMultiSelectUi(visible = getVisibleKeys()) {
  const enabled = state.multiSelectMode;
  const selected = selectedKeys();
  const visibleIds = visible.map((key) => key.id);
  const selectedVisibleCount = visibleIds.filter((id) => state.selectedKeyIds.has(id)).length;
  const selectVisible = $('#select-visible');
  const hasVisible = visibleIds.length > 0;

  document.body.classList.toggle('bulk-mode', enabled);
  $('#main-app').classList.toggle('multi-select-mode', enabled);
  $('#multi-select-toggle').classList.toggle('active', enabled);
  $('#multi-select-toggle').setAttribute('aria-pressed', String(enabled));
  $('#multi-select-toggle').textContent = enabled ? '退出多选' : '多选';
  $('#multi-select-toggle').disabled = state.keys.length === 0;
  setHidden('#multi-select-tools', !enabled);
  setHidden('#standard-actions', enabled);
  setHidden('#bulk-actions', !enabled);

  selectVisible.disabled = !hasVisible;
  selectVisible.checked = hasVisible && selectedVisibleCount === visibleIds.length;
  selectVisible.indeterminate = selectedVisibleCount > 0 && selectedVisibleCount < visibleIds.length;
  $('#select-visible-label').textContent = `全选当前筛选结果（${visibleIds.length}）`;
  $('#bulk-selected-count').textContent = `已选 ${selected.length} 项`;

  const disabled = selected.length === 0;
  for (const id of ['bulk-favorite', 'bulk-unfavorite', 'bulk-export', 'bulk-delete']) $(`#${id}`).disabled = disabled;
  $('#bulk-move').disabled = disabled || $('#bulk-group-select').value === '__choose';

  const groupSelect = $('#bulk-group-select');
  const previousGroup = groupSelect.value;
  groupSelect.innerHTML = '<option value="__choose" disabled>移动到分组…</option><option value="__ungrouped">未分组</option>'
    + getGroups().map((group) => `<option value="${escapeHtml(group)}">${escapeHtml(group)}</option>`).join('');
  groupSelect.value = [...groupSelect.options].some((option) => option.value === previousGroup) ? previousGroup : '__choose';
  $('#bulk-move').disabled = disabled || groupSelect.value === '__choose';
}

function setMultiSelectMode(enabled) {
  state.multiSelectMode = Boolean(enabled);
  state.selectedKeyIds.clear();
  state.draggedId = '';
  renderKeys();
}

function updateSelectionCards() {
  for (const card of $$('.token-item')) {
    const selected = state.selectedKeyIds.has(card.dataset.keyId);
    card.classList.toggle('selected', selected);
    const checkbox = $('.token-select-input', card);
    if (checkbox) checkbox.checked = selected;
  }
}

function toggleKeySelection(id) {
  if (state.selectedKeyIds.has(id)) state.selectedKeyIds.delete(id);
  else state.selectedKeyIds.add(id);
  updateSelectionCards();
  renderMultiSelectUi();
}

async function finishBulkMutation(message) {
  await saveVault();
  state.multiSelectMode = false;
  state.selectedKeyIds.clear();
  renderAll();
  showToast(message);
}

async function bulkSetFavorite(favorite) {
  const keys = selectedKeys();
  if (keys.length === 0) return;
  const button = $(favorite ? '#bulk-favorite' : '#bulk-unfavorite');
  setBusy(button, true, '正在处理…');
  try {
    for (const key of keys) key.favorite = favorite;
    await finishBulkMutation(favorite ? `已收藏 ${keys.length} 个密钥` : `已取消收藏 ${keys.length} 个密钥`);
  } finally {
    setBusy(button, false);
  }
}

async function bulkMoveToGroup() {
  const keys = selectedKeys();
  if (keys.length === 0) return;
  const selectedGroup = $('#bulk-group-select').value;
  if (selectedGroup === '__choose') return;
  const group = selectedGroup === '__ungrouped' ? '' : selectedGroup;
  if (group && !getGroups().includes(group)) return;
  const button = $('#bulk-move');
  setBusy(button, true, '正在移动…');
  try {
    for (const key of keys) key.group = group;
    await finishBulkMutation(group ? `已将 ${keys.length} 个密钥移到“${group}”` : `已将 ${keys.length} 个密钥移到未分组`);
  } finally {
    setBusy(button, false);
  }
}

async function bulkDeleteSelected() {
  const keys = selectedKeys();
  if (keys.length === 0) return;
  const ok = await askConfirm({
    title: '批量移入回收站',
    message: `确定将已选择的 ${keys.length} 个密钥移入回收站？之后仍可恢复。`,
    confirmText: '移入回收站',
  });
  if (!ok) return;
  const button = $('#bulk-delete');
  setBusy(button, true, '正在移动…');
  try {
    const ids = new Set(keys.map((key) => key.id));
    const deletedAt = Date.now();
    state.keys = state.keys.filter((key) => !ids.has(key.id));
    state.deletedItems.unshift(...keys.map((key) => ({ ...key, deletedAt })));
    await saveVault();
    state.multiSelectMode = false;
    state.selectedKeyIds.clear();
    renderAll();
    showToast(`已将 ${keys.length} 个密钥移入回收站`, {
      actionLabel: '撤销',
      duration: 6_000,
      onAction: async () => {
        const trashIds = new Set(keys.map((key) => key.id));
        state.deletedItems = state.deletedItems.filter((item) => !trashIds.has(item.id));
        state.keys.push(...keys);
        await saveVault();
        renderAll();
        showToast(`已恢复 ${keys.length} 个密钥`);
      },
    });
  } finally {
    setBusy(button, false);
  }
}

function ringValues(key, now = Date.now()) {
  const period = getTotpOptions(key).period;
  const remaining = getRemainingSeconds(key, now);
  const circumference = 2 * Math.PI * 15;
  const offset = circumference * (1 - remaining / period);
  const status = remaining <= Math.min(5, period / 6) ? 'critical' : (remaining <= Math.min(10, period / 3) ? 'warning' : '');
  return { remaining, circumference, offset, status };
}

async function renderKeys() {
  const version = ++state.renderVersion;
  const visible = getVisibleKeys();
  renderListMeta(visible.length);
  setHidden('#empty-state', state.keys.length !== 0);
  setHidden('#no-results', state.keys.length === 0 || visible.length !== 0);
  renderMultiSelectUi(visible);
  if (visible.length === 0) {
    $('#token-list').replaceChildren();
    return;
  }
  const rankNow = Date.now();
  const frequentIds = new Set(state.settings.sortMode === 'smart'
    ? [...state.keys]
      .filter((key) => Number(key.useCount || 0) >= 2)
      .sort((left, right) => compareSmartKeys(left, right, rankNow))
      .slice(0, 3)
      .map((key) => key.id)
    : []);
  const cards = await Promise.all(visible.map(async (key) => {
    let code = '——————';
    try { code = await generateTOTP(key.secret, Date.now(), key); } catch { /* invalid legacy item */ }
    const ring = ringValues(key);
    const icon = getKeyIcon(key);
    const subtitle = [key.issuer && key.issuer !== key.name ? key.issuer : '', key.account].filter(Boolean).join(' · ') || 'TOTP';
    const lastUsed = Number(key.lastUsed || 0) > 0 ? formatDateTime(key.lastUsed) : '从未使用';
    const note = key.note ? `<p class="token-note" title="${escapeHtml(key.note)}">${escapeHtml(key.note)}</p>` : '';
    const draggable = state.settings.sortMode === 'custom' && !state.multiSelectMode ? 'true' : 'false';
    const frequent = frequentIds.has(key.id);
    const customPeers = state.settings.sortMode === 'custom' ? visible.filter((item) => item.favorite === key.favorite) : [];
    const customIndex = customPeers.findIndex((item) => item.id === key.id);
    const reorderControls = state.settings.sortMode === 'custom' ? `
      <button class="small-btn reorder-btn" type="button" data-action="move-up" aria-label="上移 ${escapeHtml(key.name)}" title="上移"${customIndex <= 0 ? ' disabled' : ''}><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 15 6-6 6 6"></path></svg></button>
      <button class="small-btn reorder-btn" type="button" data-action="move-down" aria-label="下移 ${escapeHtml(key.name)}" title="下移"${customIndex < 0 || customIndex >= customPeers.length - 1 ? ' disabled' : ''}><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"></path></svg></button>` : '';
    const selected = state.selectedKeyIds.has(key.id);
    const selectControl = state.multiSelectMode ? `<label class="token-select"><input class="token-select-input" type="checkbox" aria-label="选择 ${escapeHtml(key.name)}"${selected ? ' checked' : ''}><span aria-hidden="true"></span></label>` : '';
    return `
      <article class="token-item${frequent ? ' frequent' : ''}${state.multiSelectMode ? ' selectable' : ''}${selected ? ' selected' : ''}" draggable="${draggable}" data-key-id="${escapeHtml(key.id)}" data-counter="${getCounter(key)}">
        <div class="token-top">
          ${selectControl}
          <div class="token-icon${icon.matched ? '' : ' initial'}" aria-hidden="true">${escapeHtml(icon.value)}</div>
          <div class="token-meta"><div class="token-title-line"><div class="token-name">${escapeHtml(key.name)}</div>${frequent ? `<span class="usage-badge" title="已复制 ${Number(key.useCount || 0)} 次">常用</span>` : ''}</div><div class="token-subtitle">${escapeHtml(subtitle)}</div><div class="token-last-used" title="最近使用时间：${escapeHtml(lastUsed)}">最近使用：${escapeHtml(lastUsed)}</div></div>
          <button class="favorite-btn${key.favorite ? ' active' : ''}" type="button" data-action="favorite" aria-label="${key.favorite ? '取消收藏' : '收藏'}" aria-pressed="${key.favorite}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-2.9-5.6 2.9 1.1-6.2L3 9.6l6.2-.9L12 3Z"></path></svg></button>
        </div>
        ${note}
        <div class="token-code-row">
          <button class="token-code" type="button" data-action="copy-code" aria-label="${state.multiSelectMode ? `选择 ${escapeHtml(key.name)}` : `复制 ${escapeHtml(key.name)} 的验证码`}"${state.multiSelectMode ? ' aria-disabled="true" tabindex="-1"' : ''}><span class="token-code-value">${escapeHtml(formatCode(code))}</span>${state.multiSelectMode ? '' : '<span class="copy-affordance" aria-hidden="true">点击复制</span>'}</button>
          <svg class="progress-ring ${ring.status}" viewBox="0 0 36 36" aria-label="剩余 ${ring.remaining} 秒" role="img">
            <circle class="ring-bg" cx="18" cy="18" r="15"></circle>
            <circle class="ring-value" cx="18" cy="18" r="15" stroke-dasharray="${ring.circumference}" stroke-dashoffset="${ring.offset}"></circle>
            <text x="18" y="18">${ring.remaining}</text>
          </svg>
        </div>
        <div class="token-footer">
          <button class="group-label${key.group ? '' : ' empty'}" type="button" data-action="quick-group" aria-label="${key.group ? `更改 ${escapeHtml(key.name)} 的分组` : `为 ${escapeHtml(key.name)} 添加分组`}" title="${key.group ? '点击更改分组' : '点击添加分组'}">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6.5h6l2 2h10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-11Z"></path><path d="M12 11v5M9.5 13.5h5"></path></svg>
            <span class="group-label-text">${escapeHtml(key.group || '未分组')}</span>${key.group ? '' : '<span class="group-label-add">设置</span>'}
          </button>
          <div class="token-actions">${reorderControls}<button class="small-btn" type="button" data-action="edit">编辑</button><button class="small-btn delete" type="button" data-action="delete">移入回收站</button></div>
        </div>
      </article>`;
  }));
  if (version !== state.renderVersion) return;
  $('#token-list').innerHTML = cards.join('');
}

function renderAll() {
  renderGroupFilters();
  updateGroupOptions();
  $('#trash-count').textContent = String(state.deletedItems.length);
  renderKeys();
}

async function updateDisplay() {
  if (!state.masterKey) return;
  const now = Date.now();
  for (const card of $$('.token-item')) {
    const key = state.keys.find((item) => item.id === card.dataset.keyId);
    if (!key) continue;
    const counter = getCounter(key, now);
    if (String(counter) !== card.dataset.counter) {
      try {
        const code = await generateTOTP(key.secret, now, key);
        $('.token-code-value', card).textContent = formatCode(code);
        card.dataset.counter = String(counter);
      } catch {
        $('.token-code-value', card).textContent = '——————';
      }
    }
    const ring = ringValues(key, now);
    const svg = $('.progress-ring', card);
    svg.classList.toggle('warning', ring.status === 'warning');
    svg.classList.toggle('critical', ring.status === 'critical');
    svg.setAttribute('aria-label', `剩余 ${ring.remaining} 秒`);
    $('.ring-value', svg).setAttribute('stroke-dashoffset', String(ring.offset));
    $('text', svg).textContent = String(ring.remaining);
  }
}

function startUpdateTimer() {
  if (state.updateTimer) clearInterval(state.updateTimer);
  state.updateTimer = setInterval(updateDisplay, 1_000);
}

async function copyText(value, successMessage = '已复制') {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.append(textarea);
    textarea.select();
    const copied = document.execCommand('copy');
    textarea.remove();
    if (!copied) throw new Error('剪贴板不可用');
  }
  showToast(successMessage);
  clearTimeout(state.clipboardTimer);
  if (state.settings.clipboardAutoClear) {
    state.clipboardTimer = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
        showToast('剪贴板已自动清空');
      } catch { /* browser may revoke clipboard permission */ }
    }, 30_000);
  }
}

function waitForNextCodePeriod(key, startedAt) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      state.pendingCodeCopies.delete(timer);
      resolve(true);
    }, getNextPeriodDelay(key, startedAt));
    state.pendingCodeCopies.set(timer, resolve);
  });
}

async function copyKeyCode(key, card) {
  const button = card ? $('.token-code', card) : null;
  if (button?.disabled) return;
  const affordance = card ? $('.copy-affordance', card) : null;
  const originalLabel = button?.getAttribute('aria-label') || '';
  const startedAt = Date.now();
  const remaining = getRemainingSeconds(key, startedAt);

  if (remaining <= 1) {
    card?.classList.add('waiting-next-code');
    if (button) {
      button.disabled = true;
      button.setAttribute('aria-label', '等待新验证码');
    }
    if (affordance) affordance.textContent = '等待新码…';
    showToast('验证码即将过期，正在复制新码');
    try {
      if (!await waitForNextCodePeriod(key, startedAt)) return;
      const code = await generateTOTP(key.secret, Date.now(), key);
      await copyText(code, '新验证码已复制');
    } finally {
      card?.classList.remove('waiting-next-code');
      if (button) {
        button.disabled = false;
        button.setAttribute('aria-label', originalLabel);
      }
      if (affordance) affordance.textContent = '点击复制';
    }
  } else {
    const code = await generateTOTP(key.secret, startedAt, key);
    await copyText(code, remaining <= 3 ? '验证码即将过期，注意尽快粘贴' : '验证码已复制');
  }
  key.lastUsed = Date.now();
  key.useCount = Math.max(0, Number(key.useCount || 0)) + 1;
  card?.classList.add('copied');
  setTimeout(() => card?.classList.remove('copied'), 520);
  card?.animate?.([{ transform: 'scale(1)' }, { transform: 'scale(.98)' }, { transform: 'scale(1)' }], { duration: 180 });
  scheduleSave();
  if (['smart', 'recent', 'stale'].includes(state.settings.sortMode)) setTimeout(() => renderKeys(), 650);
}

async function moveKeyInCustomOrder(id, direction) {
  if (state.settings.sortMode !== 'custom') return;
  const key = state.keys.find((item) => item.id === id);
  if (!key) return;
  const peers = getVisibleKeys().filter((item) => item.favorite === key.favorite);
  const index = peers.findIndex((item) => item.id === id);
  const target = peers[index + direction];
  if (!target) return;
  [key.order, target.order] = [target.order, key.order];
  await saveVault({ silent: true });
  renderKeys();
  showToast(direction < 0 ? '已上移' : '已下移');
}

function readKeyForm(prefix) {
  const name = $(`#${prefix}-name`).value.trim();
  const secret = $(`#${prefix}-secret`).value.trim().toUpperCase();
  const options = getTotpOptions({
    period: $(`#${prefix}-period`).value,
    digits: $(`#${prefix}-digits`).value,
    algorithm: $(`#${prefix}-algorithm`).value,
  });
  const key = normalizeKey({
    id: prefix === 'edit' ? $('#edit-id').value : generateId(),
    name,
    issuer: $(`#${prefix}-issuer`).value.trim(),
    account: $(`#${prefix}-account`).value.trim(),
    group: $(`#${prefix}-group`).value.trim(),
    note: $(`#${prefix}-note`).value.trim(),
    secret,
    icon: $(`#${prefix}-icon`).value.trim(),
    ...options,
  });
  key.name = name;
  key.secret = secret;
  return key;
}

async function validateKeyInput(key, existingId = '') {
  if (!key.name) throw new Error('名称不能为空');
  if (!key.secret) throw new Error('密钥不能为空');
  if (/[^A-Z2-7\s=-]/i.test(key.secret)) throw new Error('密钥只能包含 Base32 字符、空格或连字符');
  if (state.keys.some((item) => item.id !== existingId && item.name.toLocaleLowerCase() === key.name.toLocaleLowerCase())) {
    throw new Error('该名称已存在');
  }
  try { await generateTOTP(key.secret, Date.now(), key); } catch { throw new Error('密钥格式或 TOTP 参数无效'); }
  key.secret = normalizeSecret(key.secret);
}

function resetAddForm() {
  $('#add-form').reset();
  $('#add-period').value = '30';
  $('#add-digits').value = '6';
  $('#add-algorithm').value = 'SHA-1';
  for (const id of ['add-error', 'qr-error', 'qr-image-error']) hideError(`#${id}`);
  switchAddTab('manual');
}

function switchAddTab(tab) {
  qrScanner?.stop();
  for (const button of $$('[data-add-tab]')) {
    const active = button.dataset.addTab === tab;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  }
  for (const panel of $$('[data-add-panel]')) setHidden(panel, panel.dataset.addPanel !== tab);
}

function fillAddFromOtpauth(parsed, message = '已识别二维码，请确认后添加') {
  $('#add-name').value = parsed.name;
  $('#add-issuer').value = parsed.issuer || '';
  $('#add-account').value = parsed.account || '';
  $('#add-secret').value = parsed.secret;
  $('#add-period').value = String(parsed.period || 30);
  $('#add-digits').value = String(parsed.digits || 6);
  $('#add-algorithm').value = parsed.algorithm || 'SHA-1';
  switchAddTab('manual');
  showToast(message);
}

function openOtpAuthValue(value, source = 'qr') {
  const text = String(value || '').trim()
    .replace(/^otpauth-migration:\/\//i, 'otpauth-migration://')
    .replace(/^otpauth:\/\//i, 'otpauth://');
  if (text.startsWith('otpauth-migration://')) {
    parseGoogleMigrationUri(text);
    if (!$('#add-modal').classList.contains('hidden')) closeModal('add-modal', false);
    resetImportPreview({ resetForm: true });
    $('#import-text').value = text;
    openModal('import-modal', '#import-strategy');
    showToast(source === 'paste' ? '已从剪贴板识别 Google Authenticator 迁移包' : '已识别 Google Authenticator 迁移包');
    return;
  }
  const parsed = parseOtpauthUri(text);
  if (!parsed) throw new Error('仅支持 TOTP 的 otpauth:// 链接');
  if (source === 'paste') resetAddForm();
  fillAddFromOtpauth(parsed, source === 'paste' ? '已从剪贴板识别 OTPAuth 链接，请确认后添加' : undefined);
  if (source === 'paste') openModal('add-modal', '#add-name');
}

function processQrResult(value) {
  try {
    openOtpAuthValue(value);
  } catch (error) {
    showError('#qr-error', error.message);
    showError('#qr-image-error', error.message);
  }
}

function processPastedOtpAuth(value) {
  try {
    openOtpAuthValue(value, 'paste');
  } catch {
    showToast('剪贴板中的 OTPAuth 链接无效');
  }
}

async function addKeyFromForm(event) {
  event.preventDefault();
  hideError('#add-error');
  const button = $('#add-submit');
  setBusy(button, true, '正在添加…');
  try {
    const key = readKeyForm('add');
    await validateKeyInput(key);
    key.order = Math.max(-1, ...state.keys.map((item) => Number(item.order || 0))) + 1;
    state.keys.push(key);
    await saveVault();
    closeModal('add-modal');
    resetAddForm();
    renderAll();
    showToast('密钥已添加');
  } catch (error) {
    showError('#add-error', error.message);
  } finally {
    setBusy(button, false);
  }
}

function openEditModal(id) {
  const key = state.keys.find((item) => item.id === id);
  if (!key) return;
  $('#edit-id').value = key.id;
  $('#edit-name').value = key.name;
  $('#edit-issuer').value = key.issuer;
  $('#edit-account').value = key.account;
  $('#edit-group').value = key.group;
  $('#edit-note').value = key.note;
  $('#edit-secret').value = key.secret;
  $('#edit-secret').type = 'password';
  $('#edit-icon').value = key.icon;
  $('#edit-period').value = String(key.period);
  $('#edit-digits').value = String(key.digits);
  $('#edit-algorithm').value = key.algorithm;
  hideError('#edit-error');
  openModal('edit-modal', '#edit-name');
}

function openQuickGroupModal(id) {
  const key = state.keys.find((item) => item.id === id);
  if (!key) return;
  updateGroupOptions();
  $('#quick-group-id').value = key.id;
  $('#quick-group').value = key.group;
  $('#quick-group-key-name').textContent = `为“${key.name}”设置分组`;
  hideError('#quick-group-error');
  openModal('quick-group-modal', '#quick-group');
}

async function saveQuickGroup(event) {
  event.preventDefault();
  hideError('#quick-group-error');
  const button = $('#quick-group-submit');
  setBusy(button, true, '正在保存…');
  try {
    const key = state.keys.find((item) => item.id === $('#quick-group-id').value);
    if (!key) throw new Error('密钥不存在');
    const group = $('#quick-group').value.trim();
    if (group.length > 50) throw new Error('分组名称不能超过 50 个字符');
    if (group === key.group) {
      closeModal('quick-group-modal');
      return;
    }
    key.group = group;
    await saveVault();
    closeModal('quick-group-modal');
    renderAll();
    showToast(group ? `已归入“${group}”` : '已移到未分组');
  } catch (error) {
    showError('#quick-group-error', error.message || '分组保存失败');
  } finally {
    setBusy(button, false);
  }
}

async function saveEditedKey(event) {
  event.preventDefault();
  hideError('#edit-error');
  const button = $('#edit-submit');
  setBusy(button, true, '正在保存…');
  try {
    const edited = readKeyForm('edit');
    const index = state.keys.findIndex((item) => item.id === edited.id);
    if (index < 0) throw new Error('密钥不存在');
    await validateKeyInput(edited, edited.id);
    const previous = state.keys[index];
    state.keys[index] = { ...previous, ...edited, favorite: previous.favorite, order: previous.order, lastUsed: previous.lastUsed, useCount: previous.useCount };
    await saveVault();
    closeModal('edit-modal');
    renderAll();
    showToast('已保存');
  } catch (error) {
    showError('#edit-error', error.message);
  } finally {
    setBusy(button, false);
  }
}

async function deleteKey(id) {
  const index = state.keys.findIndex((item) => item.id === id);
  if (index < 0) return;
  const [removed] = state.keys.splice(index, 1);
  state.deletedItems.unshift({ ...removed, deletedAt: Date.now() });
  await saveVault();
  renderAll();
  showToast('密钥已移入回收站', {
    actionLabel: '撤销',
    duration: 6_000,
    onAction: async () => {
      const trashIndex = state.deletedItems.findIndex((item) => item.id === removed.id);
      if (trashIndex >= 0) state.deletedItems.splice(trashIndex, 1);
      state.keys.push(removed);
      await saveVault();
      renderAll();
      showToast('已撤销删除');
    },
  });
}

function pruneTrash() {
  const cutoff = Date.now() - Number(state.settings.trashRetentionDays) * 86_400_000;
  const before = state.deletedItems.length;
  state.deletedItems = state.deletedItems.filter((item) => item.deletedAt >= cutoff);
  if (state.deletedItems.length !== before) scheduleSave();
}

function renderTrash() {
  const list = $('#trash-list');
  if (state.deletedItems.length === 0) {
    list.innerHTML = '<p class="field-hint center">回收站是空的</p>';
    return;
  }
  list.innerHTML = state.deletedItems.map((item) => `
    <div class="manage-row" data-trash-id="${escapeHtml(item.id)}">
      <div class="manage-row-main"><strong>${escapeHtml(item.name)}</strong><span>删除于 ${escapeHtml(formatDateTime(item.deletedAt))}</span></div>
      <div class="manage-actions"><button class="small-btn" type="button" data-trash-action="restore">恢复</button><button class="small-btn delete" type="button" data-trash-action="purge">彻底删除</button></div>
    </div>`).join('');
}

async function restoreTrashItem(id) {
  const index = state.deletedItems.findIndex((item) => item.id === id);
  if (index < 0) return;
  const [item] = state.deletedItems.splice(index, 1);
  const existing = new Set(state.keys.map((key) => key.name.toLocaleLowerCase()));
  item.name = uniqueName(item.name, existing);
  state.keys.push(normalizeKey(item, state.keys.length));
  await saveVault();
  renderTrash();
  renderAll();
  showToast('密钥已恢复');
}

async function purgeTrashItem(id) {
  const item = state.deletedItems.find((entry) => entry.id === id);
  if (!item) return;
  const confirmed = await askConfirm({
    title: '彻底删除',
    message: `彻底删除“${item.name}”？此操作无法撤销。`,
    confirmText: '彻底删除',
  });
  if (!confirmed) {
    renderTrash();
    openModal('trash-modal');
    return;
  }
  state.deletedItems = state.deletedItems.filter((entry) => entry.id !== id);
  await saveVault();
  renderTrash();
  renderAll();
  openModal('trash-modal');
  showToast('已彻底删除');
}

function renderGroups() {
  const groups = getGroups();
  $('#groups-list').innerHTML = groups.length === 0
    ? '<p class="field-hint center">尚未创建分组</p>'
    : groups.map((group) => {
      const count = state.keys.filter((key) => key.group === group).length;
      return `<div class="manage-row" data-group-name="${escapeHtml(group)}"><div class="manage-row-main"><strong>${escapeHtml(group)}</strong><span>${count} 个密钥</span></div><div class="manage-actions"><button class="small-btn" type="button" data-group-action="rename">重命名</button><button class="small-btn delete" type="button" data-group-action="delete">删除</button></div></div>`;
    }).join('');
}

async function renameGroup(group) {
  const next = await askText({
    title: '重命名分组',
    label: '新分组名称',
    defaultValue: group,
    validate: (value) => {
      if (!value) return '分组名不能为空';
      if (value.length > 50) return '分组名不能超过 50 个字符';
      if (value.toLocaleLowerCase() !== group.toLocaleLowerCase()
        && getGroups().some((item) => item.toLocaleLowerCase() === value.toLocaleLowerCase())) return '该分组已存在';
      return null;
    },
  });
  if (next === null || next === group) {
    renderGroups();
    openModal('groups-modal');
    return;
  }
  state.keys.forEach((key) => { if (key.group === group) key.group = next; });
  if (state.groupFilter === group) state.groupFilter = next;
  await saveVault();
  renderGroups();
  renderAll();
  openModal('groups-modal');
  showToast('分组已重命名');
}

async function deleteGroup(group) {
  const confirmed = await askConfirm({
    title: '删除分组',
    message: `删除分组“${group}”后，其中的密钥将移到“未分组”。`,
    confirmText: '删除分组',
  });
  if (!confirmed) {
    renderGroups();
    openModal('groups-modal');
    return;
  }
  state.keys.forEach((key) => { if (key.group === group) key.group = ''; });
  if (state.groupFilter === group) state.groupFilter = '__all';
  await saveVault();
  renderGroups();
  renderAll();
  openModal('groups-modal');
  showToast('分组已删除，密钥已移到未分组');
}

function updateImportSubmitState() {
  const button = $('#import-submit');
  if (button.getAttribute('aria-busy') === 'true') return;
  if (!state.importPreview) {
    button.textContent = '预览导入';
    button.disabled = false;
    return;
  }
  const count = state.importPreview.plan.stats.actionable;
  button.textContent = count > 0 ? `确认导入 ${count} 条` : '没有可导入条目';
  button.disabled = count === 0;
}

function resetImportPreview({ resetForm = false, clearError = true } = {}) {
  state.importPreview = null;
  state.importRevision += 1;
  if (resetForm) $('#import-form').reset();
  if (clearError) hideError('#import-error');
  const preview = $('#import-preview');
  preview.replaceChildren();
  setHidden(preview, true);
  updateImportSubmitState();
}

function importSecretHint(secret) {
  const normalized = normalizeSecret(secret);
  if (!normalized) return '密钥不可识别';
  return normalized.length > 4 ? `密钥尾号 ${normalized.slice(-4)}` : '密钥已隐藏';
}

function renderImportPreview(source, plan) {
  const actionMeta = {
    add: { label: '新增', detail: '将新增到保险库' },
    overwrite: { label: '覆盖', detail: '将覆盖同名条目' },
    skip: { label: '跳过', detail: '同名条目不会导入' },
    invalid: { label: '无效', detail: '密钥无法生成验证码' },
  };
  const rows = plan.items.map((item) => {
    const meta = actionMeta[item.action];
    const candidate = item.candidate;
    const identity = [candidate.issuer && candidate.issuer !== candidate.name ? candidate.issuer : '', candidate.account].filter(Boolean).join(' · ');
    const otp = `${candidate.algorithm} · ${candidate.digits} 位 · ${candidate.period} 秒`;
    let detail = meta.detail;
    if (item.action === 'overwrite') detail = item.target.kind === 'planned' ? '覆盖本批同名条目' : `将覆盖“${item.target.name}”`;
    if (item.action === 'skip') detail = `与“${item.target.name}”同名`;
    if (item.action === 'add' && item.originalName) detail = `原名“${item.originalName}”，已自动重命名`;
    if (item.action === 'invalid') detail = item.reason;
    return `
      <li class="import-preview-row" data-import-action="${item.action}">
        <div class="import-preview-main">
          <strong>${escapeHtml(candidate.name)}</strong>
          ${identity ? `<span>${escapeHtml(identity)}</span>` : ''}
          <span>${escapeHtml(otp)} · ${escapeHtml(importSecretHint(candidate.secret))}</span>
          <small>${escapeHtml(detail)}</small>
        </div>
        <span class="import-action-badge ${item.action}">${meta.label}</span>
      </li>`;
  }).join('');
  const skipped = plan.stats.skip + plan.stats.invalid;
  const preview = $('#import-preview');
  preview.innerHTML = `
    <div class="import-preview-header">
      <div><p>${escapeHtml(source)} · 解析完成</p><strong>确认导入内容</strong></div>
      <span>确认前保险库不会改变</span>
    </div>
    <div class="import-preview-stats" aria-label="导入统计">
      <span class="add"><strong>${plan.stats.add}</strong> 新增</span>
      <span class="overwrite"><strong>${plan.stats.overwrite}</strong> 覆盖</span>
      <span class="skip"><strong>${skipped}</strong> 跳过</span>
    </div>
    <ul class="import-preview-list" aria-label="导入条目预览">${rows}</ul>`;
  setHidden(preview, false);
  updateImportSubmitState();
}

async function importKeysFromForm(event) {
  event.preventDefault();
  hideError('#import-error');
  const button = $('#import-submit');

  if (!state.importPreview) {
    const revision = state.importRevision;
    setBusy(button, true, '正在解析…');
    try {
      const file = $('#import-file').files[0];
      let content = $('#import-text').value.trim();
      if (file) {
        if (file.size > 5 * 1024 * 1024) throw new Error('导入文件不能超过 5 MB');
        content = await file.text();
      }
      if (!content) throw new Error('请选择文件或粘贴导入链接');
      const parsed = await parseImportContent(content, $('#import-password').value);
      const { valid, invalid } = await validateImportedItems(parsed.items, generateTOTP);
      if (revision !== state.importRevision) return;
      if (valid.length === 0) throw new Error(`没有有效的可导入条目，已跳过 ${invalid.length} 个`);
      const plan = createImportPlan(valid, state.keys, $('#import-strategy').value, invalid);
      state.importPreview = { source: parsed.source, plan };
      renderImportPreview(parsed.source, plan);
    } catch (error) {
      showError('#import-error', error.code === 'PASSWORD_REQUIRED' ? `${error.message}，然后重试` : error.message);
    } finally {
      setBusy(button, false);
      updateImportSubmitState();
    }
    return;
  }

  const pending = state.importPreview;
  let completed = false;
  setBusy(button, true, '正在导入…');
  try {
    const result = applyImportPlan(pending.plan, state.keys, generateId);
    if (result.stats.actionable === 0) throw new Error('没有可导入的条目，请更改同名处理方式');
    state.keys = result.keys;
    await saveVault();
    renderAll();
    const skipped = result.stats.skip + result.stats.invalid;
    showToast(`导入完成：新增 ${result.stats.add}，覆盖 ${result.stats.overwrite}，跳过 ${skipped}`);
    completed = true;
  } catch (error) {
    if (error.code === 'STALE_IMPORT') resetImportPreview({ clearError: false });
    showError('#import-error', error.message);
  } finally {
    setBusy(button, false);
    if (completed) closeModal('import-modal');
    else updateImportSubmitState();
  }
}

function exportKeys() {
  if (!(state.exportKeyIds instanceof Set)) return state.keys;
  return state.keys.filter((key) => state.exportKeyIds.has(key.id));
}

function exportedVault(keys = exportKeys()) {
  return {
    format: '2fa-authenticator-backup',
    version: VAULT_VERSION,
    account: state.accountName,
    exportedAt: new Date().toISOString(),
    keys,
    deletedItems: state.exportKeyIds instanceof Set ? [] : state.deletedItems,
  };
}

function openExportDialog(keyIds = null) {
  state.exportKeyIds = keyIds ? new Set(keyIds) : null;
  const count = exportKeys().length;
  $('#export-title').textContent = state.exportKeyIds ? '导出所选密钥' : '导出备份';
  $('#export-scope').textContent = state.exportKeyIds ? `将导出已选择的 ${count} 个密钥。` : '将导出当前保险库中的全部数据。';
  $('#export-form').reset();
  hideError('#export-error');
  setHidden('#export-warning', true);
  setHidden('#export-password-group', false);
  openModal('export-modal', '#export-format');
}

async function exportKeysFromForm(event) {
  event.preventDefault();
  hideError('#export-error');
  const button = $('#export-submit');
  setBusy(button, true, '正在导出…');
  try {
    const keys = exportKeys();
    if (keys.length === 0) throw new Error('没有可导出的密钥');
    const selectedExport = state.exportKeyIds instanceof Set;
    const format = $('#export-format').value;
    const date = new Date().toISOString().slice(0, 10);
    const accountSlug = state.accountName.replace(/[^a-zA-Z0-9\u4e00-\u9fa5_-]+/g, '-');
    if (format === 'encrypted') {
      const password = $('#export-password').value;
      const validation = validatePassword(password);
      if (!validation.valid) throw new Error(validation.error);
      const encrypted = await encryptBackup(exportedVault(), password);
      downloadText(`2fa-${accountSlug}-${date}${selectedExport ? '-selected' : ''}.encrypted.json`, JSON.stringify(encrypted, null, 2), 'application/json');
    } else if (format === 'plain') {
      downloadText(`2fa-${accountSlug}-${date}${selectedExport ? '-selected' : ''}.json`, JSON.stringify(exportedVault(), null, 2), 'application/json');
    } else {
      downloadText(`2fa-${accountSlug}-${date}${selectedExport ? '-selected' : ''}.otpauth.txt`, keys.map(buildOtpauthUri).join('\n'));
    }
    closeModal('export-modal');
    $('#export-form').reset();
    if (selectedExport) {
      state.multiSelectMode = false;
      state.selectedKeyIds.clear();
      renderKeys();
    }
    showToast(selectedExport ? `已导出 ${keys.length} 个密钥` : '备份已导出');
  } catch (error) {
    showError('#export-error', error.message);
  } finally {
    setBusy(button, false);
  }
}

function fillSettingsForm() {
  $('#theme-select').value = state.settings.theme;
  $('#sort-select').value = state.settings.sortMode;
  $('#auto-lock-minutes').value = String(state.settings.autoLockMinutes);
  $('#lock-on-hidden').checked = state.settings.lockOnHidden;
  $('#clipboard-clear').checked = state.settings.clipboardAutoClear;
}

function applySortMode(sortMode, announce = false) {
  state.settings = saveSettings({ ...state.settings, sortMode });
  $('#sort-quick').value = state.settings.sortMode;
  $('#sort-select').value = state.settings.sortMode;
  renderKeys();
  if (announce) {
    const labels = { smart: '已启用智能排序', recent: '已按最近使用排序', stale: '已按最久未使用排序', name: '已按名称排序', custom: '已启用自定义拖拽排序' };
    showToast(labels[state.settings.sortMode] || '排序已更新');
  }
}

function saveSettingsFromForm(event) {
  event.preventDefault();
  state.settings = saveSettings({
    ...state.settings,
    theme: $('#theme-select').value,
    sortMode: $('#sort-select').value,
    autoLockMinutes: $('#auto-lock-minutes').value,
    lockOnHidden: $('#lock-on-hidden').checked,
    clipboardAutoClear: $('#clipboard-clear').checked,
  });
  applyTheme(state.settings.theme);
  resetAutoLockTimer();
  renderKeys();
  closeModal('settings-modal');
  showToast('设置已保存');
}

async function changeMasterPassword(event) {
  event.preventDefault();
  hideError('#change-password-error');
  const button = $('#change-password-submit');
  setBusy(button, true, '正在重新加密…');
  try {
    if (!offline.isOnline) throw new Error('修改主密码需要联网');
    const currentPassword = $('#current-password').value;
    const nextPassword = $('#changed-password').value;
    const confirmation = $('#changed-password-confirm').value;
    const validation = validatePassword(nextPassword);
    if (!validation.valid) throw new Error(validation.error);
    if (nextPassword !== confirmation) throw new Error('两次输入的新密码不一致');
    if (nextPassword === currentPassword) throw new Error('新密码不能与当前密码相同');
    const currentDerived = await deriveKey(currentPassword, state.salt, state.keyIterations);
    if (!await aesKeysEqual(currentDerived, state.masterKey)) throw new Error('当前密码错误');

    const oldHash = state.keyHash;
    const nextHash = await deriveKeyHash(nextPassword, state.accountName, 'scoped');
    if ((await loadCloudRecord(nextHash)).exists) throw new Error('新密码对应的保险库已存在');
    const nextSalt = generateSalt();
    const nextKey = await deriveKey(nextPassword, nextSalt, PBKDF2_ITERATIONS.CURRENT);
    const encrypted = await encryptJson(vaultPayload(), nextKey);
    const result = await apiSave(nextHash, encrypted, nextSalt, VAULT_VERSION);
    const verification = await loadCloudRecord(nextHash);
    if (!verification.exists) throw new Error('新密码数据验证失败，旧数据已保留');
    await decryptJson(verification.encryptedData, nextKey);

    state.keyHash = nextHash;
    state.salt = nextSalt;
    state.masterKey = nextKey;
    state.keyIterations = PBKDF2_ITERATIONS.CURRENT;
    await offline.save(nextHash, encrypted, nextSalt, VAULT_VERSION, Number(result.updatedAt || Date.now()));
    await rememberCurrentSession();
    try {
      await apiDelete(oldHash);
      await offline.delete(oldHash);
    } catch (cleanupError) {
      console.warn('Old password data cleanup deferred:', cleanupError);
    }
    closeModal('change-password-modal');
    $('#change-password-form').reset();
    showToast('主密码已修改');
  } catch (error) {
    showError('#change-password-error', error.message);
  } finally {
    setBusy(button, false);
  }
}

async function triggerSyncCheck() {
  if (!state.masterKey || !state.keyHash || !offline.isOnline) return;
  try {
    const cloud = await loadCloudRecord(state.keyHash);
    const local = await offline.get(state.keyHash);
    if (!cloud.exists) {
      await saveVault();
      return;
    }
    if (local && offline.detectConflict(local, cloud.updatedAt)) {
      state.conflict = { local, cloud };
      const localVault = normalizeVaultData(await decryptJson(local.encryptedData, state.masterKey));
      const cloudVault = normalizeVaultData(await decryptJson(cloud.encryptedData, state.masterKey));
      $('#local-conflict-info').textContent = `${localVault.keys.length} 个密钥 · ${formatDateTime(local.updatedAt)}`;
      $('#cloud-conflict-info').textContent = `${cloudVault.keys.length} 个密钥 · ${formatDateTime(cloud.updatedAt)}`;
      openModal('conflict-modal', '[data-conflict="local"]');
      return;
    }
    if (local?.locallyModified) {
      useVaultData(await decryptJson(local.encryptedData, state.masterKey));
      const result = await apiSave(state.keyHash, local.encryptedData, local.salt, local.version || VAULT_VERSION);
      await offline.save(state.keyHash, local.encryptedData, local.salt, local.version || VAULT_VERSION, Number(result.updatedAt || Date.now()));
      renderAll();
      showToast('本地修改已同步到云端');
      return;
    }
    useVaultData(await decryptJson(cloud.encryptedData, state.masterKey));
    await offline.save(state.keyHash, cloud.encryptedData, state.salt, VAULT_VERSION, cloud.updatedAt);
    renderAll();
  } catch (error) {
    console.error('Sync check failed:', error);
    showToast('云端同步检查失败');
  }
}

async function resolveConflict(choice) {
  if (!state.conflict) return;
  try {
    if (choice === 'local') {
      useVaultData(await decryptJson(state.conflict.local.encryptedData, state.masterKey));
      const result = await apiSave(state.keyHash, state.conflict.local.encryptedData, state.salt, VAULT_VERSION);
      await offline.save(state.keyHash, state.conflict.local.encryptedData, state.salt, VAULT_VERSION, Number(result.updatedAt || Date.now()));
      showToast('已使用本地数据并同步到云端');
    } else {
      useVaultData(await decryptJson(state.conflict.cloud.encryptedData, state.masterKey));
      await offline.save(state.keyHash, state.conflict.cloud.encryptedData, state.salt, VAULT_VERSION, state.conflict.cloud.updatedAt);
      showToast('已使用云端数据');
    }
    state.conflict = null;
    closeModal('conflict-modal');
    renderAll();
  } catch (error) {
    showToast(`冲突处理失败：${error.message}`);
  }
}

function setupEvents() {
  setupModalAccessibility();

  document.addEventListener('click', (event) => {
    const closeButton = event.target.closest('[data-close-modal]');
    if (closeButton) {
      if (closeButton.dataset.closeModal === 'add-modal') qrScanner?.stop();
      closeModal(closeButton.dataset.closeModal);
      return;
    }
    const toggle = event.target.closest('[data-toggle-password]');
    if (toggle) {
      const input = document.getElementById(toggle.dataset.togglePassword);
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      toggle.textContent = reveal ? '隐藏' : '显示';
      toggle.setAttribute('aria-label', reveal ? '隐藏密码' : '显示密码');
    }
  });

  for (const button of $$('[data-auth-view]')) button.addEventListener('click', () => switchAuthView(button.dataset.authView));
  $('#new-password').addEventListener('input', () => updatePasswordStrength($('#new-password'), $('#setup-strength'), $('#setup-strength-label'), getPasswordStrength));
  $('#changed-password').addEventListener('input', () => updatePasswordStrength($('#changed-password'), $('#change-strength'), $('#change-strength-label'), getPasswordStrength));

  $('#login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    hideError('#login-error');
    const button = $('#login-submit');
    setBusy(button, true, '正在解锁…');
    try {
      const password = $('#login-password').value;
      if (!password) throw new Error('请输入主密码');
      await unlockWithPassword(password, $('#login-account').value);
      $('#login-password').value = '';
      showMainApp();
    } catch (error) {
      clearSensitiveState();
      showError('#login-error', error.message || '解锁失败');
    } finally {
      setBusy(button, false);
    }
  });

  $('#setup-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    hideError('#setup-error');
    const button = $('#setup-submit');
    setBusy(button, true, '正在创建…');
    try {
      const password = $('#new-password').value;
      const validation = validatePassword(password);
      if (!validation.valid) throw new Error(validation.error);
      if (password !== $('#confirm-password').value) throw new Error('两次输入的密码不一致');
      await setupAccount(password, $('#setup-account').value);
      $('#setup-form').reset();
      showMainApp();
      showToast('加密保险库已创建');
    } catch (error) {
      clearSensitiveState();
      showError('#setup-error', error.message || '创建失败');
    } finally {
      setBusy(button, false);
    }
  });

  $('#session-buttons').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-resume-account]');
    if (!button) return;
    clearSensitiveState();
    if (!await restoreSession(button.dataset.resumeAccount)) showError('#login-error', '会话已失效，请重新输入密码');
  });

  $('#account-switch').addEventListener('change', async (event) => {
    const target = event.target.value;
    if (target === '__other') {
      clearSensitiveState();
      showAuthScreen();
      return;
    }
    if (target === state.accountName) return;
    clearSensitiveState();
    if (!await restoreSession(target)) showAuthScreen(target);
  });

  $('#theme-quick').addEventListener('click', () => {
    state.settings.theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    state.settings = saveSettings(state.settings);
    applyTheme(state.settings.theme);
  });
  $('#settings-open').addEventListener('click', () => { fillSettingsForm(); openModal('settings-modal', '#theme-select'); });
  $('#settings-form').addEventListener('submit', saveSettingsFromForm);
  $('#sort-quick').addEventListener('change', (event) => applySortMode(event.target.value, true));
  $('#columns-quick').addEventListener('change', (event) => {
    state.settings = saveSettings({ ...state.settings, columnsPerRow: event.target.value });
    applyColumnsPerRow(true);
  });
  $('#lock-current').addEventListener('click', () => { closeModal('settings-modal'); lockCurrent(); });
  $('#lock-all').addEventListener('click', () => { closeModal('settings-modal'); lockAll('全部会话已锁定'); });
  $('#login-other').addEventListener('click', () => { closeModal('settings-modal'); clearSensitiveState(); showAuthScreen(); });

  $('#add-open').addEventListener('click', () => { resetAddForm(); openModal('add-modal', '#add-name'); });
  $('[data-action="open-add"]').addEventListener('click', () => { resetAddForm(); openModal('add-modal', '#add-name'); });
  for (const button of $$('[data-add-tab]')) button.addEventListener('click', () => switchAddTab(button.dataset.addTab));
  $('#add-form').addEventListener('submit', addKeyFromForm);
  $('#edit-form').addEventListener('submit', saveEditedKey);
  $('#quick-group-form').addEventListener('submit', saveQuickGroup);
  $('#copy-secret').addEventListener('click', () => copyText(normalizeSecret($('#edit-secret').value), '原始密钥已复制'));
  $('#copy-uri').addEventListener('click', async () => {
    try {
      const key = readKeyForm('edit');
      await validateKeyInput(key, key.id);
      hideError('#edit-error');
      await copyText(buildOtpauthUri(key), 'OTPAuth URI 已复制');
    } catch (error) {
      showError('#edit-error', error.message);
    }
  });

  $('#token-list').addEventListener('click', async (event) => {
    const card = event.target.closest('.token-item');
    if (!card) return;
    const key = state.keys.find((item) => item.id === card.dataset.keyId);
    if (!key) return;
    if (state.multiSelectMode) {
      event.preventDefault();
      toggleKeySelection(key.id);
      return;
    }
    if (event.target.closest('[data-action="favorite"]')) {
      key.favorite = !key.favorite;
      await saveVault({ silent: true });
      renderKeys();
    } else if (event.target.closest('[data-action="move-up"]')) await moveKeyInCustomOrder(key.id, -1);
    else if (event.target.closest('[data-action="move-down"]')) await moveKeyInCustomOrder(key.id, 1);
    else if (event.target.closest('[data-action="quick-group"]')) openQuickGroupModal(key.id);
    else if (event.target.closest('[data-action="edit"]')) openEditModal(key.id);
    else if (event.target.closest('[data-action="delete"]')) await deleteKey(key.id);
    else if (event.target.closest('[data-action="copy-code"]')) await copyKeyCode(key, card);
  });

  $('#token-list').addEventListener('dragstart', (event) => {
    const card = event.target.closest('.token-item');
    if (!card || state.multiSelectMode || state.settings.sortMode !== 'custom') return;
    state.draggedId = card.dataset.keyId;
    card.classList.add('dragging');
    event.dataTransfer.effectAllowed = 'move';
  });
  $('#token-list').addEventListener('dragover', (event) => {
    if (!state.draggedId) return;
    const card = event.target.closest('.token-item');
    if (!card || card.dataset.keyId === state.draggedId) return;
    event.preventDefault();
    $$('.token-item.drag-over').forEach((item) => item.classList.remove('drag-over'));
    card.classList.add('drag-over');
  });
  $('#token-list').addEventListener('drop', async (event) => {
    event.preventDefault();
    const target = event.target.closest('.token-item');
    const source = state.keys.find((key) => key.id === state.draggedId);
    const destination = state.keys.find((key) => key.id === target?.dataset.keyId);
    if (source && destination && source !== destination) {
      [source.order, destination.order] = [destination.order, source.order];
      await saveVault({ silent: true });
      renderKeys();
    }
    state.draggedId = '';
  });
  $('#token-list').addEventListener('dragend', () => {
    state.draggedId = '';
    $$('.token-item').forEach((item) => item.classList.remove('dragging', 'drag-over'));
  });

  $('#search-input').addEventListener('input', (event) => { state.search = event.target.value.trim(); renderKeys(); });
  $('#multi-select-toggle').addEventListener('click', () => setMultiSelectMode(!state.multiSelectMode));
  $('#select-visible').addEventListener('change', (event) => {
    const visibleIds = getVisibleKeys().map((key) => key.id);
    for (const id of visibleIds) {
      if (event.target.checked) state.selectedKeyIds.add(id);
      else state.selectedKeyIds.delete(id);
    }
    updateSelectionCards();
    renderMultiSelectUi();
  });
  $('#bulk-favorite').addEventListener('click', () => bulkSetFavorite(true));
  $('#bulk-unfavorite').addEventListener('click', () => bulkSetFavorite(false));
  $('#bulk-group-select').addEventListener('change', () => { $('#bulk-move').disabled = selectedKeys().length === 0 || $('#bulk-group-select').value === '__choose'; });
  $('#bulk-move').addEventListener('click', bulkMoveToGroup);
  $('#bulk-export').addEventListener('click', () => openExportDialog([...state.selectedKeyIds]));
  $('#bulk-delete').addEventListener('click', bulkDeleteSelected);
  $('#bulk-cancel').addEventListener('click', () => setMultiSelectMode(false));
  document.addEventListener('keydown', (event) => {
    if (event.defaultPrevented || event.key !== 'Escape' || !state.multiSelectMode || document.querySelector('.modal-overlay:not(.hidden)')) return;
    event.preventDefault();
    setMultiSelectMode(false);
  });
  $('#clear-filters').addEventListener('click', () => {
    state.search = '';
    state.groupFilter = '__all';
    $('#search-input').value = '';
    renderGroupFilters();
    renderKeys();
    $('#search-input').focus();
  });
  $('#group-filters').addEventListener('click', (event) => {
    const button = event.target.closest('[data-group-filter]');
    if (!button) return;
    state.groupFilter = button.dataset.groupFilter;
    renderGroupFilters();
    renderKeys();
  });

  $('#groups-open').addEventListener('click', () => { closeModal('settings-modal', false); renderGroups(); openModal('groups-modal'); });
  $('#groups-list').addEventListener('click', (event) => {
    const row = event.target.closest('[data-group-name]');
    const action = event.target.closest('[data-group-action]')?.dataset.groupAction;
    if (!row || !action) return;
    if (action === 'rename') renameGroup(row.dataset.groupName);
    else deleteGroup(row.dataset.groupName);
  });

  $('#trash-open').addEventListener('click', () => { renderTrash(); openModal('trash-modal'); });
  $('#trash-list').addEventListener('click', (event) => {
    const row = event.target.closest('[data-trash-id]');
    const action = event.target.closest('[data-trash-action]')?.dataset.trashAction;
    if (!row || !action) return;
    if (action === 'restore') restoreTrashItem(row.dataset.trashId);
    else purgeTrashItem(row.dataset.trashId);
  });

  $('#import-open').addEventListener('click', () => { resetImportPreview({ resetForm: true }); openModal('import-modal', '#import-file'); });
  $('#import-form').addEventListener('submit', importKeysFromForm);
  for (const input of $$('#import-file, #import-text, #import-password, #import-strategy')) {
    input.addEventListener(input.matches('select, input[type="file"]') ? 'change' : 'input', () => resetImportPreview());
  }
  $('#import-modal').addEventListener('modal:close', () => resetImportPreview({ resetForm: true }));
  $('#export-open').addEventListener('click', () => openExportDialog());
  $('#export-modal').addEventListener('modal:close', () => { state.exportKeyIds = null; });
  $('#export-format').addEventListener('change', (event) => {
    const encrypted = event.target.value === 'encrypted';
    setHidden('#export-password-group', !encrypted);
    setHidden('#export-warning', encrypted);
  });
  $('#export-form').addEventListener('submit', exportKeysFromForm);

  $('#change-password-open').addEventListener('click', () => {
    closeModal('settings-modal', false);
    $('#change-password-form').reset();
    hideError('#change-password-error');
    openModal('change-password-modal', '#current-password');
  });
  $('#change-password-form').addEventListener('submit', changeMasterPassword);
  for (const button of $$('[data-conflict]')) button.addEventListener('click', () => resolveConflict(button.dataset.conflict));

  $('#qr-start').addEventListener('click', () => { hideError('#qr-error'); qrScanner.start(); });
  const dropZone = $('#qr-drop-zone');
  $('#qr-image-input').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    hideError('#qr-image-error');
    try { processQrResult(await scanQrImage(file)); } catch (error) { showError('#qr-image-error', error.message); }
    event.target.value = '';
  });
  for (const type of ['dragenter', 'dragover']) dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.classList.add('dragover'); });
  for (const type of ['dragleave', 'drop']) dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.classList.remove('dragover'); });
  dropZone.addEventListener('drop', async (event) => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    try { processQrResult(await scanQrImage(file)); } catch (error) { showError('#qr-image-error', error.message); }
  });
  dropZone.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); $('#qr-image-input').click(); } });
  document.addEventListener('paste', async (event) => {
    const clipboardText = String(event.clipboardData?.getData('text/plain') || event.clipboardData?.getData('text') || '').trim();
    if (/^otpauth(?:-migration)?:\/\//i.test(clipboardText)) {
      event.preventDefault();
      if (!state.masterKey) {
        showToast('请先解锁保险库');
        return;
      }
      processPastedOtpAuth(clipboardText);
      return;
    }
    const imagePanel = $('[data-add-panel="image"]');
    if ($('#add-modal').classList.contains('hidden') || imagePanel.classList.contains('hidden')) return;
    const imageItem = [...(event.clipboardData?.items || [])].find((item) => item.type.startsWith('image/'));
    if (!imageItem) return;
    try { processQrResult(await scanQrImage(imageItem.getAsFile())); } catch (error) { showError('#qr-image-error', error.message); }
  });

  const activityEvents = ['pointerdown', 'keydown', 'touchstart'];
  activityEvents.forEach((name) => document.addEventListener(name, resetAutoLockTimer, { passive: true }));
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) return;
    qrScanner?.stop();
    if (state.masterKey && state.settings.lockOnHidden) lockAll('页面进入后台，保险库已锁定');
  });
  window.addEventListener('beforeunload', () => qrScanner?.stop());
}

function setupQrScanner() {
  qrScanner = new QrScanner({
    video: $('#qr-video'),
    canvas: $('#qr-canvas'),
    onResult: processQrResult,
    onError: (message) => showError('#qr-error', message),
    onStatus: (message) => { $('#qr-status').textContent = message; },
  });
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.register('/service-worker.js');
      registration.addEventListener('updatefound', () => {
        registration.installing?.addEventListener('statechange', (event) => {
          if (event.target.state === 'installed' && navigator.serviceWorker.controller) showToast('发现新版本，重新打开页面后生效');
        });
      });
    } catch (error) {
      console.warn('Service worker registration failed:', error);
    }
  });
}

async function init() {
  applyTheme(state.settings.theme);
  watchSystemTheme(() => state.settings.theme);
  setupQrScanner();
  setupEvents();
  registerServiceWorker();
  try { await offline.init(); } catch (error) { console.warn('Offline cache unavailable:', error); }
  offline.setupNetworkListeners(
    () => {
      setNetworkStatus(true);
      setHidden('#offline-banner', true);
      showToast('网络已恢复');
      triggerSyncCheck();
    },
    () => {
      setNetworkStatus(false);
      setHidden('#offline-banner', false);
    },
  );
  setNetworkStatus(offline.isOnline);
  setHidden('#offline-banner', offline.isOnline);
  renderKnownAccounts();
  renderSessionResume();

  const active = getActiveAccount();
  const sessionAccounts = Object.values(getSessions()).map((session) => session.accountName);
  if (active && await restoreSession(active)) return;
  if (sessionAccounts.length > 0 && await restoreSession(sessionAccounts[0])) return;
  showAuthScreen(active);
}

init().catch((error) => {
  console.error('Application initialization failed:', error);
  showAuthScreen();
  showError('#login-error', '应用初始化失败，请刷新页面');
});
