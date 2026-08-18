import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

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
});
