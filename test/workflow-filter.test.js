import { describe, expect, it } from 'vitest';
import { matchesKeyFilter } from '../src/js/utils.js';

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
