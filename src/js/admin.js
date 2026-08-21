import { enhanceSearchableSelects } from './searchable-select.js';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  token: '',
  adminName: '',
  activePanel: 'users-panel',
  users: [],
  userOffset: 0,
  userLimit: 50,
  userTotal: 0,
  selectedUser: null,
  usersRequest: 0,
  logsLoaded: false,
  logsRequest: 0,
  historyRequest: 0,
};

const statusLabels = {
  active: '正常',
  disabled: '已停用',
  reset_required: '等待重建',
};

const actionLabels = {
  'admin.login': '管理员登录',
  'admin.logout': '管理员退出',
  'admin.user.update': '更新用户',
  'admin.vault.reset': '重置保险库',
  'admin.vault.restore': '恢复保险库',
  'admin.vault.history_restore': '恢复历史版本',
  'vault.read': '读取保险库',
  'vault.save': '保存保险库',
  'vault.delete': '删除旧保险库',
  'vault.access_blocked': '阻止访问',
  'vault.save_blocked': '阻止同步',
};

const resultLabels = { success: '成功', failure: '失败', blocked: '已阻止' };
const BACKDROP_DRAG_TOLERANCE = 6;
let userDialogBackdropPointer = null;

function setHidden(target, hidden) {
  const element = typeof target === 'string' ? $(target) : target;
  element?.classList.toggle('hidden', hidden);
}

function createElement(tagName, options = {}) {
  const element = document.createElement(tagName);
  if (options.className) element.className = options.className;
  if (options.text !== undefined) element.textContent = options.text;
  if (options.title) element.title = options.title;
  if (options.type) element.type = options.type;
  return element;
}

function setBusy(button, busy, label) {
  if (!button) return;
  if (busy) {
    button.dataset.originalLabel = button.textContent;
    button.textContent = label;
  } else if (button.dataset.originalLabel) {
    button.textContent = button.dataset.originalLabel;
    delete button.dataset.originalLabel;
  }
  button.disabled = busy;
}

function showError(target, message = '') {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  element.textContent = message;
  setHidden(element, !message);
}

let toastTimer = null;
function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  setHidden(toast, false);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => setHidden(toast, true), 3200);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
  let body = options.body;
  if (body && typeof body !== 'string') {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, { ...options, headers, body, cache: 'no-store' });
  } catch {
    throw new Error('无法连接服务器，请检查网络后重试');
  }
  let data = {};
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) {
    if (response.status === 401 && state.token) showLogin('管理会话已失效，请重新登录');
    const error = new Error(response.status === 429 ? '请求过于频繁，请稍后再试' : (data.error || `请求失败 (${response.status})`));
    error.status = response.status;
    error.code = data.code || '';
    throw error;
  }
  return data;
}

function showLogin(message = '') {
  state.token = '';
  state.adminName = '';
  state.selectedUser = null;
  if ($('#user-dialog').open) $('#user-dialog').close();
  setHidden('#admin-app', true);
  setHidden('#login-view', false);
  $('#admin-password').value = '';
  showError('#login-error', message);
  requestAnimationFrame(() => $('#admin-password').focus());
}

function showDashboard(session) {
  state.token = session.token;
  state.adminName = session.adminName;
  $('#admin-name').textContent = session.adminName;
  setHidden('#login-view', true);
  setHidden('#admin-app', false);
  showError('#login-error');
}

function formatDateTime(value) {
  const timestamp = Number(value || 0);
  if (!timestamp) return '暂无记录';
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(timestamp));
}

function shortKey(value) {
  const key = String(value || '');
  return key.length > 16 ? `${key.slice(0, 8)}…${key.slice(-8)}` : key || '—';
}

function createBadge(label, className) {
  return createElement('span', { className: `badge ${className}`, text: label });
}

function renderSummary(summary = {}) {
  $('#summary-total').textContent = String(summary.total ?? 0);
  $('#summary-active').textContent = String(summary.active ?? 0);
  $('#summary-disabled').textContent = String(summary.disabled ?? 0);
  $('#summary-reset').textContent = String(summary.resetRequired ?? 0);
  $('#summary-anonymous').textContent = String(summary.anonymous ?? 0);
}

function userPrimaryName(user) {
  return user.displayName || user.accountName || '待识别用户';
}

function renderUsers(payload) {
  state.users = payload.users || [];
  state.userTotal = Number(payload.total || 0);
  renderSummary(payload.summary);
  const body = $('#users-table-body');
  const rows = state.users.map((user) => {
    const row = createElement('tr');

    const identityCell = createElement('td', { className: 'user-cell' });
    identityCell.dataset.label = '用户';
    identityCell.append(
      createElement('span', { className: 'user-name', text: userPrimaryName(user), title: userPrimaryName(user) }),
      createElement('span', {
        className: 'user-subtitle',
        text: user.displayName && user.accountName ? user.accountName : shortKey(user.keyHash),
        title: user.accountName || user.keyHash,
      }),
    );
    row.append(identityCell);

    const statusCell = createElement('td');
    statusCell.dataset.label = '状态';
    statusCell.append(createBadge(statusLabels[user.status] || user.status, `badge-${user.status}`));
    row.append(statusCell);

    const activityCell = createElement('td', { className: 'muted', text: formatDateTime(user.lastSeenAt || user.updatedAt) });
    activityCell.dataset.label = '最近在线';
    row.append(activityCell);

    const vaultCell = createElement('td');
    vaultCell.dataset.label = '保险库';
    vaultCell.append(createBadge(user.hasVault ? '已同步' : '无当前数据', user.hasVault ? 'badge-vault' : 'badge-empty'));
    row.append(vaultCell);

    const noteCell = createElement('td', {
      className: 'note-preview',
      text: user.adminNote || '—',
      title: user.adminNote || '',
    });
    noteCell.dataset.label = '管理备注';
    row.append(noteCell);

    const actionCell = createElement('td');
    actionCell.dataset.label = '操作';
    const manageButton = createElement('button', { className: 'button button-secondary compact', text: '管理', type: 'button' });
    manageButton.addEventListener('click', () => openUserDialog(user));
    actionCell.append(manageButton);
    row.append(actionCell);
    return row;
  });
  body.replaceChildren(...rows);
  setHidden('#users-empty', rows.length > 0);
  const start = state.userTotal ? state.userOffset + 1 : 0;
  const end = Math.min(state.userOffset + state.userLimit, state.userTotal);
  $('#users-result-summary').textContent = `共 ${state.userTotal} 个匹配用户，当前显示 ${start}–${end}`;
  $('#users-page').textContent = `第 ${Math.floor(state.userOffset / state.userLimit) + 1} 页`;
  $('#users-prev').disabled = state.userOffset === 0;
  $('#users-next').disabled = !payload.hasMore;
}

async function loadUsers({ resetOffset = false } = {}) {
  if (!state.token) return;
  if (resetOffset) state.userOffset = 0;
  const requestId = ++state.usersRequest;
  const params = new URLSearchParams({
    query: $('#user-query').value.trim(),
    status: $('#user-status').value,
    limit: String(state.userLimit),
    offset: String(state.userOffset),
  });
  setHidden('#users-loading', false);
  try {
    const payload = await api(`/api/admin/users?${params.toString()}`);
    if (requestId === state.usersRequest) renderUsers(payload);
  } catch (error) {
    if (error.status !== 401) showToast(error.message);
  } finally {
    if (requestId === state.usersRequest) setHidden('#users-loading', true);
  }
}

function openUserDialog(user) {
  state.selectedUser = { ...user };
  $('#dialog-account').textContent = user.accountName || '尚未识别（用户下次在线登录后自动补全）';
  $('#dialog-access-email').textContent = user.accessEmail || '尚未绑定（首次成功访问旧保险库后自动绑定）';
  $('#dialog-key').textContent = shortKey(user.keyHash);
  $('#dialog-key').title = user.keyHash;
  $('#dialog-created').textContent = `创建：${formatDateTime(user.createdAt)}`;
  $('#dialog-last-seen').textContent = `最近在线：${formatDateTime(user.lastSeenAt || user.updatedAt)}`;
  $('#dialog-display-name').value = user.displayName || '';
  $('#dialog-status').value = user.status || 'active';
  $('#dialog-note').value = user.adminNote || '';
  $('#reset-confirmation').value = '';
  $('#restore-confirmation').value = '';
  showError('#user-form-error');
  setHidden('#vault-history-loading', false);
  setHidden('#vault-history-empty', true);
  setHidden('#vault-history-list', true);
  $('#vault-history-list').replaceChildren();
  renderDangerControls();
  const dialog = $('#user-dialog');
  if (!dialog.open) dialog.showModal();
  loadVaultHistory(user.keyHash);
}

function renderVaultHistory(payload) {
  const versions = Array.isArray(payload?.versions) ? payload.versions : [];
  const rows = versions.map((version) => {
    const row = createElement('div', { className: 'vault-history-row' });
    const meta = createElement('div', { className: 'vault-history-meta' });
    meta.append(
      createElement('strong', { text: formatDateTime(version.updatedAt) }),
      createElement('span', { text: `保险库格式 v${Number(version.version || 1)} · 加密密文` }),
    );
    const restore = createElement('button', { className: 'button button-warning compact', text: '恢复此版本', type: 'button' });
    restore.dataset.historyUpdatedAt = String(version.updatedAt);
    row.append(meta, restore);
    return row;
  });
  $('#vault-history-list').replaceChildren(...rows);
  setHidden('#vault-history-loading', true);
  setHidden('#vault-history-empty', rows.length > 0);
  setHidden('#vault-history-list', rows.length === 0);
}

async function loadVaultHistory(keyHash = state.selectedUser?.keyHash) {
  if (!keyHash || !state.token) return;
  const requestId = ++state.historyRequest;
  setHidden('#vault-history-loading', false);
  try {
    const payload = await api(`/api/admin/users/${keyHash}/history`);
    if (requestId === state.historyRequest && state.selectedUser?.keyHash === keyHash) renderVaultHistory(payload);
  } catch (error) {
    if (requestId === state.historyRequest && error.status !== 401) {
      setHidden('#vault-history-loading', true);
      showError('#user-form-error', error.message);
    }
  }
}

async function restoreVaultHistoryVersion(updatedAt, button) {
  if (!state.selectedUser || !Number.isSafeInteger(updatedAt) || updatedAt <= 0) return;
  if (!window.confirm(`确定恢复 ${formatDateTime(updatedAt)} 的加密保险库版本？当前版本也会自动保留，可再次恢复。`)) return;
  setBusy(button, true, '正在恢复…');
  showError('#user-form-error');
  try {
    const payload = await api(`/api/admin/users/${state.selectedUser.keyHash}/history/${updatedAt}/restore`, {
      method: 'POST', body: { confirmation: '恢复历史版本' },
    });
    state.selectedUser = payload.user;
    $('#dialog-status').value = payload.user.status;
    showToast('历史版本已恢复，恢复前版本仍在历史中');
    await loadVaultHistory();
    await loadUsers();
    if (state.logsLoaded) await loadLogs();
  } catch (error) {
    if (error.status !== 401) showError('#user-form-error', error.message);
  } finally {
    setBusy(button, false);
  }
}

function renderDangerControls() {
  const user = state.selectedUser;
  const canReset = Boolean(user?.hasVault);
  const canRestore = Boolean(user?.archiveKey && !user?.hasVault);
  setHidden('#reset-controls', !canReset);
  setHidden('#restore-controls', !canRestore);
  $('#reset-vault').disabled = !canReset || $('#reset-confirmation').value !== '重置保险库';
  $('#restore-vault').disabled = !canRestore || $('#restore-confirmation').value !== '恢复保险库';
  $('#archive-expiry').textContent = canRestore
    ? `重置前的旧密文保留至 ${formatDateTime(user.archivedUntil)}，恢复不会绕过原主密码。`
    : '';
}

async function saveSelectedUser(event) {
  event.preventDefault();
  if (!state.selectedUser) return;
  const button = $('#user-save');
  showError('#user-form-error');
  setBusy(button, true, '正在保存…');
  try {
    const payload = await api(`/api/admin/users/${state.selectedUser.keyHash}`, {
      method: 'PATCH',
      body: {
        displayName: $('#dialog-display-name').value.trim(),
        status: $('#dialog-status').value,
        adminNote: $('#dialog-note').value.trim(),
      },
    });
    state.selectedUser = payload.user;
    $('#user-dialog').close();
    showToast('用户信息已更新');
    await loadUsers();
    if (state.logsLoaded) await loadLogs();
  } catch (error) {
    if (error.status !== 401) showError('#user-form-error', error.message);
  } finally {
    setBusy(button, false);
  }
}

async function resetSelectedVault() {
  if (!state.selectedUser || $('#reset-confirmation').value !== '重置保险库') return;
  const button = $('#reset-vault');
  setBusy(button, true, '正在重置…');
  showError('#user-form-error');
  try {
    const payload = await api(`/api/admin/users/${state.selectedUser.keyHash}/reset`, {
      method: 'POST', body: { confirmation: '重置保险库' },
    });
    state.selectedUser = payload.user;
    $('#dialog-status').value = payload.user.status;
    $('#reset-confirmation').value = '';
    renderDangerControls();
    showToast('保险库已重置，旧密文将保留 30 天');
    await loadUsers();
    if (state.logsLoaded) await loadLogs();
  } catch (error) {
    if (error.status !== 401) showError('#user-form-error', error.message);
  } finally {
    setBusy(button, false);
    renderDangerControls();
  }
}

async function restoreSelectedVault() {
  if (!state.selectedUser || $('#restore-confirmation').value !== '恢复保险库') return;
  const button = $('#restore-vault');
  setBusy(button, true, '正在恢复…');
  showError('#user-form-error');
  try {
    const payload = await api(`/api/admin/users/${state.selectedUser.keyHash}/restore`, {
      method: 'POST', body: { confirmation: '恢复保险库' },
    });
    state.selectedUser = payload.user;
    $('#dialog-status').value = payload.user.status;
    $('#restore-confirmation').value = '';
    renderDangerControls();
    showToast('旧保险库已恢复');
    await loadUsers();
    if (state.logsLoaded) await loadLogs();
  } catch (error) {
    if (error.status !== 401) showError('#user-form-error', error.message);
  } finally {
    setBusy(button, false);
    renderDangerControls();
  }
}

function isUserDialogBackdropPointer(event) {
  const rect = $('#user-dialog').getBoundingClientRect();
  return event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
}

function renderLogs(payload) {
  const body = $('#logs-table-body');
  const rows = (payload.logs || []).map((entry) => {
    const row = createElement('tr');
    const timeCell = createElement('td', { className: 'muted', text: formatDateTime(entry.timestamp) });
    timeCell.dataset.label = '时间';
    row.append(timeCell);
    const actionCell = createElement('td', { text: actionLabels[entry.action] || entry.action });
    actionCell.dataset.label = '操作';
    row.append(actionCell);

    const targetCell = createElement('td');
    targetCell.dataset.label = '用户 / 对象';
    targetCell.append(
      createElement('span', { className: 'user-name', text: entry.targetLabel || '—', title: entry.targetLabel || '' }),
      createElement('span', { className: 'user-subtitle', text: entry.targetKey ? shortKey(entry.targetKey) : '无目标对象' }),
    );
    row.append(targetCell);
    const actorCell = createElement('td', { text: entry.actor || 'system' });
    actorCell.dataset.label = '执行者';
    row.append(actorCell);

    const ipCell = createElement('td', { className: 'audit-ip muted', text: entry.ipAddress || '—', title: entry.ipAddress || '' });
    ipCell.dataset.label = 'IP 地址';
    row.append(ipCell);

    const resultCell = createElement('td');
    resultCell.dataset.label = '结果';
    resultCell.append(createBadge(resultLabels[entry.result] || entry.result, `badge-${entry.result}`));
    row.append(resultCell);
    const detailCell = createElement('td', { className: 'muted', text: entry.details || '—', title: entry.details || '' });
    detailCell.dataset.label = '详情';
    row.append(detailCell);
    return row;
  });
  body.replaceChildren(...rows);
  setHidden('#logs-empty', rows.length > 0);
  $('#logs-result-summary').textContent = `共匹配 ${payload.total || 0} 条，显示最近 ${rows.length} 条；已扫描 ${payload.scanned || 0} 条日志。`;
}

async function loadLogs() {
  if (!state.token) return;
  const requestId = ++state.logsRequest;
  const params = new URLSearchParams({
    query: $('#log-query').value.trim(),
    action: $('#log-action').value,
    result: $('#log-result').value,
    limit: '100',
  });
  setHidden('#logs-loading', false);
  try {
    const payload = await api(`/api/admin/logs?${params.toString()}`);
    if (requestId === state.logsRequest) {
      state.logsLoaded = true;
      renderLogs(payload);
    }
  } catch (error) {
    if (error.status !== 401) showToast(error.message);
  } finally {
    if (requestId === state.logsRequest) setHidden('#logs-loading', true);
  }
}

function switchPanel(panelId) {
  state.activePanel = panelId;
  for (const tab of $$('.section-tab')) {
    const active = tab.dataset.panel === panelId;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
    setHidden(`#${tab.dataset.panel}`, !active);
  }
  if (panelId === 'logs-panel' && !state.logsLoaded) loadLogs();
}

let userSearchTimer;
let logSearchTimer;

enhanceSearchableSelects();

$('#admin-login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#admin-login-submit');
  showError('#login-error');
  setBusy(button, true, '正在验证…');
  try {
    const session = await api('/api/admin/login', {
      method: 'POST',
      body: { username: $('#admin-username').value.trim(), password: $('#admin-password').value },
    });
    showDashboard(session);
    $('#admin-password').value = '';
    await loadUsers({ resetOffset: true });
  } catch (error) {
    const message = error.code === 'ADMIN_NOT_CONFIGURED'
      ? '后台尚未启用：请先在服务器中配置 ADMIN_PASSWORD。'
      : error.message;
    showError('#login-error', message);
  } finally {
    setBusy(button, false);
  }
});

$('#toggle-admin-password').addEventListener('click', () => {
  const input = $('#admin-password');
  const reveal = input.type === 'password';
  input.type = reveal ? 'text' : 'password';
  $('#toggle-admin-password').textContent = reveal ? '隐藏' : '显示';
  $('#toggle-admin-password').setAttribute('aria-pressed', String(reveal));
});

$('#admin-logout').addEventListener('click', async () => {
  try { await api('/api/admin/logout', { method: 'POST' }); } catch { /* local logout still completes */ }
  showLogin('已安全退出管理后台');
});

for (const tab of $$('.section-tab')) tab.addEventListener('click', () => switchPanel(tab.dataset.panel));

$('#refresh-current').addEventListener('click', async () => {
  const button = $('#refresh-current');
  setBusy(button, true, '正在刷新…');
  try {
    if (state.activePanel === 'users-panel') await loadUsers();
    else await loadLogs();
    showToast('数据已刷新');
  } finally {
    setBusy(button, false);
  }
});

$('#user-filters').addEventListener('submit', (event) => event.preventDefault());
$('#user-query').addEventListener('input', () => {
  clearTimeout(userSearchTimer);
  userSearchTimer = setTimeout(() => loadUsers({ resetOffset: true }), 280);
});
$('#user-status').addEventListener('change', () => loadUsers({ resetOffset: true }));
$('#users-prev').addEventListener('click', () => {
  state.userOffset = Math.max(0, state.userOffset - state.userLimit);
  loadUsers();
});
$('#users-next').addEventListener('click', () => {
  state.userOffset += state.userLimit;
  loadUsers();
});

$('#log-filters').addEventListener('submit', (event) => event.preventDefault());
$('#log-query').addEventListener('input', () => {
  clearTimeout(logSearchTimer);
  logSearchTimer = setTimeout(loadLogs, 280);
});
$('#log-action').addEventListener('change', loadLogs);
$('#log-result').addEventListener('change', loadLogs);

$('#user-form').addEventListener('submit', saveSelectedUser);
$('#user-dialog-close').addEventListener('click', () => $('#user-dialog').close());
for (const button of $$('[data-close-user]')) button.addEventListener('click', () => $('#user-dialog').close());
$('#user-dialog').addEventListener('pointerdown', (event) => {
  const startedOnBackdrop = event.button === 0 && event.isPrimary !== false && isUserDialogBackdropPointer(event);
  userDialogBackdropPointer = startedOnBackdrop
    ? { pointerId: event.pointerId, x: event.clientX, y: event.clientY }
    : null;
});
$('#user-dialog').addEventListener('pointerup', (event) => {
  const started = userDialogBackdropPointer;
  userDialogBackdropPointer = null;
  if (!started || event.pointerId !== started.pointerId || !isUserDialogBackdropPointer(event)) return;
  const distance = Math.hypot(event.clientX - started.x, event.clientY - started.y);
  if (distance <= BACKDROP_DRAG_TOLERANCE) $('#user-dialog').close();
});
$('#user-dialog').addEventListener('pointercancel', () => { userDialogBackdropPointer = null; });

$('#reset-confirmation').addEventListener('input', renderDangerControls);
$('#restore-confirmation').addEventListener('input', renderDangerControls);
$('#reset-vault').addEventListener('click', resetSelectedVault);
$('#restore-vault').addEventListener('click', restoreSelectedVault);
$('#vault-history-refresh').addEventListener('click', () => loadVaultHistory());
$('#vault-history-list').addEventListener('click', (event) => {
  const button = event.target.closest('[data-history-updated-at]');
  if (!button) return;
  restoreVaultHistoryVersion(Number(button.dataset.historyUpdatedAt), button);
});
