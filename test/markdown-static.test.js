import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { marked } from 'marked';

const markdown = await readFile(new URL('../src/js/markdown.js', import.meta.url), 'utf8');

describe('safe Markdown rendering', () => {
  it('parses GitHub-flavored Markdown with preserved line breaks', () => {
    expect(markdown).toContain("import { marked } from 'marked'");
    expect(markdown).toContain('breaks: true');
    expect(markdown).toContain('gfm: true');
  });

  it('sanitizes output with a narrow allow-list', () => {
    expect(markdown).toContain("import DOMPurify from 'dompurify'");
    expect(markdown).toContain('ALLOWED_TAGS');
    expect(markdown).toContain('ALLOWED_ATTR');
    expect(markdown).toContain('ALLOW_DATA_ATTR: false');
    expect(markdown).toContain('SANITIZE_NAMED_PROPS: true');
    expect(markdown).not.toContain("'img'");
    expect(markdown).not.toContain("'script'");
  });

  it('opens sanitized links without access to the original page', () => {
    expect(markdown).toContain("node.setAttribute('target', '_blank')");
    expect(markdown).toContain("node.setAttribute('rel', 'noopener noreferrer')");
  });

  it('forces any allowed input to remain a disabled checklist item', () => {
    expect(markdown).toContain("node.tagName === 'INPUT'");
    expect(markdown).toContain("node.setAttribute('type', 'checkbox')");
    expect(markdown).toContain("node.setAttribute('disabled', '')");
  });

  it('keeps secret mask tokens inert through the GFM parse so masked values and copy buttons are injected', () => {
    const prefix = markdown.match(/SECRET_MASK_TOKEN_PREFIX\s*=\s*'([^']+)'/)?.[1];
    expect(prefix).toBeTruthy();
    const token = `${prefix}0`;
    for (const context of [`- 密码：${token}`, `密码：${token} 结束`, `密码 ${token}`, `(${token})`]) {
      const rendered = marked.parse(context, { async: false, breaks: true, gfm: true });
      expect(rendered).toContain(token);
      expect(rendered).not.toContain('<strong>');
    }
  });

  it('preserves password whitespace and avoids collisions with literal mask-token text', () => {
    expect(markdown).toContain("import { replaceWorkflowSecretMarkers } from './workflow-secrets.js'");
    expect(markdown).toContain("while (source.includes(tokenPrefix)) tokenPrefix += 'X'");
    expect(markdown).toContain('replaceWorkflowSecretMarkers(source, (raw) =>');
  });

  it('keeps plaintext secrets out of rendered HTML attributes', () => {
    expect(markdown).toContain('secretStore.set(reference, raw)');
    expect(markdown).toContain('data-secret-ref="${reference}"');
    expect(markdown).toContain('secretStore instanceof Map');
    expect(markdown).not.toContain('data-secret-copy');
    expect(markdown).not.toContain('encodeURIComponent(raw)');
  });

  it('adds an accessible copy action to every sanitized code block', () => {
    expect(markdown).toContain('function injectCodeCopyMarkup(html)');
    expect(markdown).toContain('class="markdown-code-copy"');
    expect(markdown).toContain('aria-label="复制代码块"');
    expect(markdown).toContain('return injectCodeCopyMarkup(withSecrets)');
  });
});
