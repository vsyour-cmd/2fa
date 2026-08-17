export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

let activeModal = null;
let modalTrigger = null;
let toastTimer = null;

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
  if (activeModal && activeModal !== modal) closeModal(activeModal, false);
  modalTrigger = document.activeElement;
  activeModal = modal;
  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  document.body.classList.add('modal-open');
  const focusTarget = $(focusSelector, modal);
  requestAnimationFrame(() => focusTarget?.focus());
}

export function closeModal(id, restoreFocus = true) {
  const modal = typeof id === 'string' ? document.getElementById(id) : id;
  if (!modal) return;
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  if (activeModal === modal) activeModal = null;
  if (!activeModal) document.body.classList.remove('modal-open');
  if (restoreFocus && modalTrigger instanceof HTMLElement) modalTrigger.focus();
}

export function setupModalAccessibility() {
  document.addEventListener('keydown', (event) => {
    if (!activeModal || activeModal.classList.contains('hidden')) return;
    if (event.key === 'Escape' && activeModal.dataset.dismissible !== 'false') {
      event.preventDefault();
      closeModal(activeModal);
      return;
    }
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

  document.addEventListener('click', (event) => {
    const overlay = event.target.closest('.modal-overlay');
    if (overlay && event.target === overlay && overlay.dataset.dismissible !== 'false') closeModal(overlay);
  });
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
  return { value: String(key.name || '?').trim().charAt(0).toUpperCase() || '?', matched: false };
}
