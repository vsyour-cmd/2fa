import { describe, expect, it, vi } from 'vitest';
import { encodeWorkflowSecretMarker, replaceWorkflowSecretMarkers } from '../src/js/workflow-secrets.js';

describe('workflow password markers', () => {
  it('keeps a legacy password containing a single closing brace hidden', () => {
    const replacer = vi.fn(() => 'MASKED');
    expect(replaceWorkflowSecretMarkers('密码：{{secret:ab}cd}}', replacer)).toBe('密码：MASKED');
    expect(replacer).toHaveBeenCalledWith('ab}cd', '{{secret:ab}cd}}');
  });

  it('keeps legacy passwords ending with or containing repeated closing braces hidden', () => {
    const values = [];
    const replace = (value) => {
      values.push(value);
      return 'MASKED';
    };
    expect(replaceWorkflowSecretMarkers('{{secret:ends}}}', replace)).toBe('MASKED');
    expect(replaceWorkflowSecretMarkers('密码：{{secret:a}}b}}', replace)).toBe('密码：MASKED');
    expect(values).toEqual(['ends}', 'a}}b']);
  });

  it('keeps separate legacy markers on the same line independent', () => {
    const values = [];
    const rendered = replaceWorkflowSecretMarkers('{{secret:first}} 和 {{pwd:second}}', (value) => {
      values.push(value);
      return 'MASKED';
    });
    expect(rendered).toBe('MASKED 和 MASKED');
    expect(values).toEqual(['first', 'second']);
  });

  it('round-trips arbitrary generated passwords through an encoded marker', () => {
    const password = 'A}b}} { 空格\t换行\n!@#';
    const marker = encodeWorkflowSecretMarker(password);
    const replacer = vi.fn(() => 'MASKED');
    expect(marker).toMatch(/^\{\{secret64:[A-Za-z0-9_-]+\}\}$/);
    expect(marker).not.toContain(password);
    expect(replaceWorkflowSecretMarkers(`密码：${marker}`, replacer)).toBe('密码：MASKED');
    expect(replacer).toHaveBeenCalledWith(password, marker);
  });

  it('leaves malformed encoded markers untouched', () => {
    const marker = '{{secret64:not+base64}}';
    expect(replaceWorkflowSecretMarkers(marker, () => 'MASKED')).toBe(marker);
  });
});
