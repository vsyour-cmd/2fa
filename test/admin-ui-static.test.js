import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const html = await readFile(new URL('../admin.html', import.meta.url), 'utf8');
const script = await readFile(new URL('../src/js/admin.js', import.meta.url), 'utf8');
const styles = await readFile(new URL('../src/admin.css', import.meta.url), 'utf8');
const searchableSelect = await readFile(new URL('../src/js/searchable-select.js', import.meta.url), 'utf8');

describe('admin console static shell', () => {
  it('provides separate login, user management, recoverable reset, and audit-log views', () => {
    expect(html).toContain('id="admin-login-form"');
    expect(html).toContain('id="users-panel"');
    expect(html).toContain('id="logs-panel"');
    expect(html).toContain('id="user-dialog"');
    expect(html).toContain('id="dialog-access-email"');
    expect(script).toContain("user.accessEmail || '尚未绑定");
    expect(html).toContain('输入“重置保险库”确认');
    expect(html).toContain('输入“恢复保险库”确认');
    expect(html).toContain('输入“删除用户”确认');
    expect(html).toContain('id="delete-user"');
    expect(html).toContain('option value="admin.user.delete"');
    expect(html).toContain('<th>IP 地址</th>');
    expect(html).toContain('日志保留 90 天并记录来源 IP');
    expect(html).toContain('管理员无法查看主密码、验证码密钥或解密保险库');
    expect(script).toContain("method: 'DELETE', body: { confirmation: '删除用户' }");
    expect(script).toContain("'admin.user.delete': '删除用户'");
    expect(script).toContain("text: entry.ipAddress || '—'");
    expect(script).toContain("addEventListener('pointerdown'");
    expect(script).toContain("addEventListener('pointerup'");
    expect(script).not.toContain("$('#user-dialog').addEventListener('click'");
  });

  it('keeps the bearer token in memory and builds user content without innerHTML', () => {
    expect(script).toContain("token: ''");
    expect(script).toContain("headers.set('Authorization', `Bearer ${state.token}`)");
    expect(script).not.toContain('localStorage');
    expect(script).not.toContain('sessionStorage');
    expect(script).not.toContain('.innerHTML');
    expect(script).toContain('textContent');
  });

  it('has responsive, keyboard-focus, dark-mode, and reduced-motion styles', () => {
    expect(styles).toContain(':focus-visible');
    expect(styles).toContain('@media (max-width: 680px)');
    expect(styles).toContain('@media (prefers-color-scheme: dark)');
    expect(styles).toContain('@media (prefers-reduced-motion: reduce)');
  });

  it('uses the shared 3D gradient language without adding runtime assets', () => {
    expect(styles).toContain('body::before, body::after');
    expect(styles).toContain('@keyframes admin-ambient-orbit');
    expect(styles).toContain('@keyframes admin-perspective-grid-drift');
    expect(styles).toContain('transform: perspective(620px) rotateX(66deg)');
    expect(styles).toContain('body::before, body::after { animation: none !important; }');
  });

  it('uses searchable dropdown panels for every categorical filter', () => {
    expect(html.match(/data-searchable-filter/g)).toHaveLength(3);
    expect(html).toContain('data-search-placeholder="筛选用户状态…"');
    expect(html).toContain('data-search-placeholder="筛选操作类型…"');
    expect(html).toContain('data-search-placeholder="筛选操作结果…"');
    expect(script).toContain('enhanceSearchableSelects()');
    expect(searchableSelect).toContain("select.dispatchEvent(new Event('change', { bubbles: true }))");
    expect(searchableSelect).toContain("list.setAttribute('role', 'listbox')");
  });
});
