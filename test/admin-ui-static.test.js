import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const html = await readFile(new URL('../admin.html', import.meta.url), 'utf8');
const script = await readFile(new URL('../src/js/admin.js', import.meta.url), 'utf8');
const styles = await readFile(new URL('../src/admin.css', import.meta.url), 'utf8');

describe('admin console static shell', () => {
  it('provides separate login, user management, recoverable reset, and audit-log views', () => {
    expect(html).toContain('id="admin-login-form"');
    expect(html).toContain('id="users-panel"');
    expect(html).toContain('id="logs-panel"');
    expect(html).toContain('id="user-dialog"');
    expect(html).toContain('输入“重置保险库”确认');
    expect(html).toContain('输入“恢复保险库”确认');
    expect(html).toContain('管理员无法查看主密码、验证码密钥或解密保险库');
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
});
