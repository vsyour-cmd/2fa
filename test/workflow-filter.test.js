import { describe, expect, it } from 'vitest';
import { matchesKeyFilter, matchesWorkflowNoteFilter } from '../src/js/utils.js';

const key = {
  name: 'GitHub Admin',
  account: 'owner@example.com',
  issuer: 'GitHub',
  group: '工作账户',
  note: '发布前使用',
  secret: 'SHOULD-NOT-BE-SEARCHABLE',
};

describe('workflow 2FA association filter', () => {
  it('matches each visible descriptive field without case sensitivity', () => {
    for (const query of ['github', 'OWNER@EXAMPLE.COM', '工作账户', '发布前']) {
      expect(matchesKeyFilter(key, query)).toBe(true);
    }
  });

  it('supports multiple terms across different fields', () => {
    expect(matchesKeyFilter(key, 'github 工作')).toBe(true);
    expect(matchesKeyFilter(key, 'github 私人')).toBe(false);
  });

  it('does not search secret values and treats a blank filter as all items', () => {
    expect(matchesKeyFilter(key, 'SHOULD-NOT-BE-SEARCHABLE')).toBe(false);
    expect(matchesKeyFilter(key, '   ')).toBe(true);
  });
});

describe('workflow note list filter', () => {
  const note = {
    title: '发布网站',
    content: '登录控制台并执行部署检查',
    linkedKeys: [{ name: 'Cloudflare Admin', issuer: 'Cloudflare', account: 'ops@example.com' }],
  };

  it('matches titles, Markdown content, and linked 2FA metadata', () => {
    for (const query of ['发布', '部署检查', 'cloudflare', 'OPS@EXAMPLE.COM']) {
      expect(matchesWorkflowNoteFilter(note, query)).toBe(true);
    }
  });

  it('supports multiple terms and treats blank input as all notes', () => {
    expect(matchesWorkflowNoteFilter(note, '发布 cloudflare')).toBe(true);
    expect(matchesWorkflowNoteFilter(note, '发布 github')).toBe(false);
    expect(matchesWorkflowNoteFilter(note, '   ')).toBe(true);
  });
});
