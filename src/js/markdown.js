import DOMPurify from 'dompurify';
import { marked } from 'marked';

const ALLOWED_TAGS = [
  'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'strong', 'em', 'del', 'span',
  'a', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'input',
];

const ALLOWED_ATTR = ['href', 'title', 'class', 'type', 'checked', 'disabled', 'align', 'target', 'rel'];
const SECRET_PATTERN = /\{\{\s*(?:secret|pwd)\s*:\s*([^\r\n{}]+?)\s*\}\}/gi;
// The mask token must survive the GFM parse as literal text. It is plain
// alphanumerics on purpose: the previous "__...__" token was interpreted as
// strong emphasis, which broke the post-parse replacement and leaked the token.
const SECRET_MASK_TOKEN_PREFIX = 'WFSECRETTOKEN';

function normalizeSecretValue(value) {
  // Passwords may intentionally contain repeated spaces or tabs. Only trim
  // the optional padding around the marker value; never rewrite its content.
  return String(value || '').trim();
}

function secretMask(length = 0) {
  const visibleLength = Math.max(Math.min(Number(length) || 4, 32), 6);
  return '*'.repeat(visibleLength);
}

function embedSecretTokens(source) {
  const values = [];
  let tokenPrefix = SECRET_MASK_TOKEN_PREFIX;
  while (source.includes(tokenPrefix)) tokenPrefix += 'X';
  const replaced = source.replace(SECRET_PATTERN, (marker, password) => {
    const raw = normalizeSecretValue(password);
    if (!raw) return marker;
    const index = values.length;
    values.push(raw);
    return `${tokenPrefix}${index}`;
  });
  return { replaced, values, tokenPrefix };
}

function secretReference() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return [...crypto.getRandomValues(new Uint8Array(16))]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function injectSecretRevealMarkup(html, values, tokenPrefix, secretStore) {
  if (!values.length) return html;
  let rendered = html;
  for (let index = 0; index < values.length; index += 1) {
    const token = `${tokenPrefix}${index}`;
    const raw = values[index];
    const masked = secretMask(raw.length);
    const reference = secretStore instanceof Map ? secretReference() : '';
    if (reference) secretStore.set(reference, raw);
    const copyAction = reference
      ? `<a href="#" class="markdown-secret-copy" data-secret-ref="${reference}" title="复制密码">复制</a>`
      : '';
    const replacement = `<span class="markdown-secret"><span class="markdown-secret-mask" aria-hidden="true">${masked}</span>${copyAction}</span>`;
    rendered = rendered.replace(token, replacement);
  }
  return rendered;
}

DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A' && node.hasAttribute('href')) {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  }
  if (node.tagName === 'INPUT') {
    node.setAttribute('type', 'checkbox');
    node.setAttribute('disabled', '');
  }
});

export function renderMarkdown(value, secretStore = null) {
  const source = String(value || '');
  if (!source.trim()) return '';
  const { replaced, values, tokenPrefix } = embedSecretTokens(source);
  const parsed = marked.parse(replaced, { async: false, breaks: true, gfm: true });
  const sanitized = DOMPurify.sanitize(parsed, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_ARIA_ATTR: false,
    ALLOW_DATA_ATTR: false,
    SANITIZE_NAMED_PROPS: true,
  });
  return injectSecretRevealMarkup(sanitized, values, tokenPrefix, secretStore);
}
