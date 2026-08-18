import DOMPurify from 'dompurify';
import { marked } from 'marked';

const ALLOWED_TAGS = [
  'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'strong', 'em', 'del',
  'a', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'input',
];

const ALLOWED_ATTR = ['href', 'title', 'class', 'type', 'checked', 'disabled', 'align', 'target', 'rel'];

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

export function renderMarkdown(value) {
  const source = String(value || '');
  if (!source.trim()) return '';
  const parsed = marked.parse(source, { async: false, breaks: true, gfm: true });
  return DOMPurify.sanitize(parsed, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_ARIA_ATTR: false,
    ALLOW_DATA_ATTR: false,
    SANITIZE_NAMED_PROPS: true,
  });
}
