export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

let activeModal = null;
let modalTrigger = null;
let toastTimer = null;
let offlineBannerObserver = null;
let backdropPointer = null;
const BACKDROP_DRAG_TOLERANCE = 6;

function updateModalWindowControls(modal) {
  const minimized = modal.classList.contains('modal-minimized');
  const fullscreen = modal.classList.contains('modal-fullscreen');
  const minimizeButton = $('[data-modal-window-action="minimize"]', modal);
  const fullscreenButton = $('[data-modal-window-action="fullscreen"]', modal);
  if (minimizeButton) {
    minimizeButton.setAttribute('aria-pressed', String(minimized));
    minimizeButton.setAttribute('aria-label', minimized ? '还原窗口' : '最小化窗口');
    minimizeButton.title = minimized ? '还原窗口' : '最小化窗口';
  }
  if (fullscreenButton) {
    fullscreenButton.setAttribute('aria-pressed', String(fullscreen));
    fullscreenButton.setAttribute('aria-label', fullscreen ? '退出全屏' : '全屏显示');
    fullscreenButton.title = fullscreen ? '退出全屏' : '全屏显示';
  }
}

function resetModalWindowState(modal) {
  modal.classList.remove('modal-minimized', 'modal-fullscreen');
  modal.setAttribute('aria-modal', 'true');
  updateModalWindowControls(modal);
}

function setModalMinimized(modal, minimized) {
  modal.classList.toggle('modal-minimized', minimized);
  modal.setAttribute('aria-modal', minimized ? 'false' : 'true');
  document.body.classList.toggle('modal-open', !minimized);
  updateModalWindowControls(modal);
  requestAnimationFrame(() => $('[data-modal-window-action="minimize"]', modal)?.focus());
}

function toggleModalFullscreen(modal) {
  if (modal.classList.contains('modal-minimized')) {
    setModalMinimized(modal, false);
    modal.classList.add('modal-fullscreen');
  } else modal.classList.toggle('modal-fullscreen');
  updateModalWindowControls(modal);
  requestAnimationFrame(() => $('[data-modal-window-action="fullscreen"]', modal)?.focus());
}

function createModalWindowButton(action, label, markup) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'icon-btn modal-window-button';
  button.dataset.modalWindowAction = action;
  button.setAttribute('aria-label', label);
  button.setAttribute('aria-pressed', 'false');
  button.title = label;
  button.innerHTML = markup;
  return button;
}

function setupModalWindowControls() {
  for (const modal of $$('.modal-overlay')) {
    const dialog = $('.modal-wide', modal);
    const header = dialog && $('.modal-header', dialog);
    const closeButton = header && $('[data-close-modal]', header);
    if (!dialog || !header || !closeButton || modal.dataset.dismissible === 'false' || modal.dataset.windowControlsReady === 'true') continue;
    const controls = document.createElement('div');
    controls.className = 'modal-window-controls';
    controls.setAttribute('role', 'group');
    controls.setAttribute('aria-label', '窗口控制');
    const minimizeButton = createModalWindowButton('minimize', '最小化窗口', `
      <svg class="modal-minimize-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 17h14"></path></svg>
      <svg class="modal-restore-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m7 14 5-5 5 5"></path></svg>`);
    const fullscreenButton = createModalWindowButton('fullscreen', '全屏显示', `
      <svg class="modal-expand-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3H3v5M16 3h5v5M21 16v5h-5M3 16v5h5"></path></svg>
      <svg class="modal-contract-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3v5H3M16 3v5h5M21 16h-5v5M3 16h5v5"></path></svg>`);
    controls.append(minimizeButton, fullscreenButton, closeButton);
    header.append(controls);
    controls.addEventListener('click', (event) => {
      const button = event.target.closest('[data-modal-window-action]');
      if (!button) return;
      event.preventDefault();
      event.stopPropagation();
      if (button.dataset.modalWindowAction === 'minimize') {
        setModalMinimized(modal, !modal.classList.contains('modal-minimized'));
      } else toggleModalFullscreen(modal);
    });
    header.addEventListener('click', (event) => {
      if (!modal.classList.contains('modal-minimized') || event.target.closest('button')) return;
      setModalMinimized(modal, false);
    });
    modal.dataset.windowControlsReady = 'true';
    updateModalWindowControls(modal);
  }
}

export function setHidden(target, hidden) {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  element.classList.toggle('hidden', hidden);
}

export function showError(target, message) {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  element.textContent = message;
  element.classList.remove('hidden');
}

export function hideError(target) {
  const element = typeof target === 'string' ? $(target) : target;
  if (!element) return;
  element.textContent = '';
  element.classList.add('hidden');
}

export function openModal(id, focusSelector = 'input:not([type="hidden"]), button, select, textarea') {
  const modal = typeof id === 'string' ? document.getElementById(id) : id;
  if (!modal) return;
  if (activeModal) closeModal(activeModal, false);
  resetModalWindowState(modal);
  modalTrigger = document.activeElement;
  activeModal = modal;
  modal.inert = false;
  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  document.body.classList.add('modal-open');
  const focusTarget = $(focusSelector, modal);
  requestAnimationFrame(() => focusTarget?.focus());
}

export function closeModal(id, restoreFocus = true) {
  const modal = typeof id === 'string' ? document.getElementById(id) : id;
  if (!modal) return;
  const restoreTarget = restoreFocus
    && modalTrigger instanceof HTMLElement
    && modalTrigger.isConnected
    && !modal.contains(modalTrigger)
    ? modalTrigger
    : null;
  if (modal.contains(document.activeElement)) {
    if (restoreTarget) restoreTarget.focus({ preventScroll: true });
    else document.activeElement.blur();
  }
  modal.inert = true;
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  resetModalWindowState(modal);
  if (activeModal === modal) activeModal = null;
  if (!activeModal) document.body.classList.remove('modal-open');
  if (restoreTarget && document.activeElement !== restoreTarget) restoreTarget.focus({ preventScroll: true });
  modal.dispatchEvent(new CustomEvent('modal:close'));
}

export function askConfirm({ title, message, confirmText = '删除' }) {
  const modal = $('#confirm-modal');
  const confirmButton = $('#confirm-ok', modal);
  $('#confirm-title', modal).textContent = title;
  $('#confirm-message', modal).textContent = message;
  confirmButton.textContent = confirmText;

  return new Promise((resolve) => {
    let settled = false;
    const cleanup = () => {
      confirmButton.removeEventListener('click', onConfirm);
      modal.removeEventListener('modal:close', onClose);
    };
    const finish = (value, close = true) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (close) closeModal(modal);
      resolve(value);
    };
    const onConfirm = () => finish(true);
    const onClose = () => finish(false, false);

    openModal(modal, '#confirm-ok');
    confirmButton.addEventListener('click', onConfirm);
    modal.addEventListener('modal:close', onClose);
  });
}

export function askText({ title, label, defaultValue = '', validate = () => null }) {
  const modal = $('#rename-group-modal');
  const form = $('#rename-group-form', modal);
  const input = $('#rename-group-input', modal);
  const error = $('#rename-group-error', modal);
  $('#rename-group-title', modal).textContent = title;
  $('#rename-group-label', modal).textContent = label;
  input.value = defaultValue;
  hideError(error);

  return new Promise((resolve) => {
    let settled = false;
    const cleanup = () => {
      form.removeEventListener('submit', onSubmit);
      input.removeEventListener('input', onInput);
      modal.removeEventListener('modal:close', onClose);
    };
    const finish = (value, close = true) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (close) closeModal(modal);
      resolve(value);
    };
    const onSubmit = (event) => {
      event.preventDefault();
      const value = input.value.trim();
      let validationError = null;
      try { validationError = validate(value); } catch (caught) { validationError = caught.message || '输入无效'; }
      if (validationError) {
        showError(error, validationError);
        input.focus();
        return;
      }
      finish(value);
    };
    const onInput = () => hideError(error);
    const onClose = () => finish(null, false);

    openModal(modal, '#rename-group-input');
    form.addEventListener('submit', onSubmit);
    input.addEventListener('input', onInput);
    modal.addEventListener('modal:close', onClose);
    requestAnimationFrame(() => input.select());
  });
}

export function setupModalAccessibility() {
  setupModalWindowControls();
  for (const modal of $$('.modal-overlay')) modal.inert = modal.classList.contains('hidden');
  document.addEventListener('keydown', (event) => {
    if (!activeModal || activeModal.classList.contains('hidden')) return;
    if (event.key === 'Escape' && activeModal.dataset.dismissible !== 'false') {
      event.preventDefault();
      closeModal(activeModal);
      return;
    }
    if (activeModal.classList.contains('modal-minimized')) return;
    if (event.key !== 'Tab') return;
    const focusable = $$('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])', activeModal)
      .filter((element) => element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  document.addEventListener('pointerdown', (event) => {
    const overlay = event.target.closest?.('.modal-overlay');
    const startedOnBackdrop = overlay && event.target === overlay && event.button === 0 && event.isPrimary !== false;
    backdropPointer = startedOnBackdrop
      ? { overlay, pointerId: event.pointerId, x: event.clientX, y: event.clientY }
      : null;
  });

  document.addEventListener('pointerup', (event) => {
    const started = backdropPointer;
    backdropPointer = null;
    if (!started || event.pointerId !== started.pointerId || event.target !== started.overlay) return;
    const distance = Math.hypot(event.clientX - started.x, event.clientY - started.y);
    if (distance <= BACKDROP_DRAG_TOLERANCE && started.overlay.dataset.dismissible !== 'false') closeModal(started.overlay);
  });

  document.addEventListener('pointercancel', () => { backdropPointer = null; });
}

export function showToast(message, options = {}) {
  const toast = $('#app-toast');
  if (!toast) return;
  clearTimeout(toastTimer);
  toast.replaceChildren();
  const text = document.createElement('span');
  text.textContent = message;
  toast.append(text);
  if (options.actionLabel && options.onAction) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'toast-action';
    button.textContent = options.actionLabel;
    button.addEventListener('click', () => {
      options.onAction();
      toast.classList.remove('show');
    }, { once: true });
    toast.append(button);
  }
  toast.classList.add('show');
  toastTimer = setTimeout(() => toast.classList.remove('show'), options.duration || 2_500);
}

export function applyTheme(preference) {
  const resolved = preference === 'system'
    ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : preference;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;
  const meta = $('meta[name="theme-color"]');
  if (meta) meta.content = resolved === 'dark' ? '#070b14' : '#2563eb';
  return resolved;
}

export function watchSystemTheme(getPreference) {
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (getPreference() === 'system') applyTheme('system');
  });
}

function updateOfflineBannerOffset(banner) {
  const offset = banner.classList.contains('hidden') ? 0 : banner.offsetHeight;
  document.documentElement.style.setProperty('--offline-banner-offset', `${offset}px`);
}

function watchOfflineBannerSize(banner) {
  if (offlineBannerObserver || typeof ResizeObserver !== 'function') return;
  offlineBannerObserver = new ResizeObserver(() => updateOfflineBannerOffset(banner));
  offlineBannerObserver.observe(banner);
}

export function updatePasswordStrength(input, meter, label, getStrength) {
  const strength = getStrength(input.value);
  meter.style.setProperty('--strength', `${strength.percent}%`);
  meter.dataset.score = String(strength.score);
  label.textContent = input.value ? `密码强度：${strength.label}` : '密码强度';
}

export function setNetworkStatus(isOnline, detail = '') {
  const indicator = $('#network-status');
  if (!indicator) return;
  indicator.classList.toggle('online', isOnline);
  indicator.classList.toggle('offline', !isOnline);
  $('.status-text', indicator).textContent = detail || (isOnline ? '在线' : '离线');
  indicator.setAttribute('aria-label', detail || (isOnline ? '当前在线' : '当前离线'));
  const banner = $('#offline-banner');
  if (!banner) return;
  setHidden(banner, isOnline);
  watchOfflineBannerSize(banner);
  updateOfflineBannerOffset(banner);
}

export function setBusy(button, busy, busyText = '处理中…') {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
}

const ICON_MAP = [
  [/github/i, '🐙'],
  [/google|gmail/i, '🌐'],
  [/microsoft|outlook|azure/i, '🪟'],
  [/amazon|aws/i, '📦'],
  [/cloudflare/i, '☁️'],
  [/discord/i, '🎮'],
  [/facebook|meta/i, '👥'],
  [/apple|icloud/i, '🍎'],
  [/stripe|paypal|bank|finance/i, '💳'],
  [/gitlab|bitbucket/i, '🦊'],
  [/docker/i, '🐳'],
];

export function getKeyIcon(key) {
  if (key.icon) return { value: key.icon, matched: true };
  const haystack = `${key.issuer || ''} ${key.name || ''}`;
  const match = ICON_MAP.find(([pattern]) => pattern.test(haystack));
  if (match) return { value: match[1], matched: true };
  const name = String(key.name || '?').trim() || '?';
  let hash = 2166136261;
  for (const character of name) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return { value: name.charAt(0).toUpperCase() || '?', matched: false, tone: Math.abs(hash) % 8 };
}
