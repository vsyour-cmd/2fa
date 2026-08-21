import { describe, expect, it } from 'vitest';
import { applyWorkflowImportPlan, createWorkflowImportPlan, parseImportContent } from '../src/js/importers.js';

const existing = [{
  id: 'scene-existing',
  title: '服务器登录',
  group: '运维',
  content: '旧流程',
  linkedKeys: [{ keyId: 'key-existing', name: 'GitHub', issuer: 'GitHub', account: 'owner' }],
  favorite: true,
  lastUsed: 200,
  useCount: 4,
  createdAt: 100,
  updatedAt: 200,
}];

const imported = [{
  id: 'scene-backup',
  title: '服务器登录',
  group: '运维',
  content: '备份流程',
  linkedKeys: [{ keyId: 'key-backup', name: 'GitHub', issuer: 'GitHub', account: 'owner' }],
  createdAt: 50,
  updatedAt: 150,
}];

describe('workflow backup import planning', () => {
  it('preserves recycle-bin data and workflow protection from a complete backup', async () => {
    const deletedAt = 1_700_000_000_000;
    const protection = { salt: 'backup-salt', hash: 'a'.repeat(64), iterations: 210_000 };
    const parsed = await parseImportContent(JSON.stringify({
      format: '2fa-authenticator-backup',
      keys: [],
      workflowNotes: [],
      deletedItems: [{ id: 'deleted-key', name: '旧验证码', secret: 'JBSWY3DPEHPK3PXP', deletedAt }],
      deletedWorkflowNotes: [{ id: 'deleted-scene', title: '旧场景', content: '旧流程', deletedAt }],
      workflowProtection: protection,
    }));

    expect(parsed.completeBackup).toMatchObject({
      hasWorkflowProtection: true,
      workflowProtection: protection,
    });
    expect(parsed.completeBackup.deletedItems).toEqual([expect.objectContaining({ id: 'deleted-key', deletedAt })]);
    expect(parsed.completeBackup.deletedWorkflowNotes).toEqual([expect.objectContaining({ id: 'deleted-scene', deletedAt })]);
  });

  it('skips a same-name scene when importing the same backup with the default strategy', () => {
    const plan = createWorkflowImportPlan(imported, existing, 'skip');
    expect(plan.stats).toEqual({ add: 0, overwrite: 0, skip: 1, actionable: 0 });
    expect(plan.items[0]).toMatchObject({ action: 'skip', target: { id: 'scene-existing' } });

    const result = applyWorkflowImportPlan(plan, existing);
    expect(result.workflowNotes).toHaveLength(1);
    expect(result.workflowNotes[0]).toMatchObject({ id: 'scene-existing', title: '服务器登录', content: '旧流程' });
  });

  it('treats the original scene id as the same scene even when its title changed', () => {
    const renamedBackup = [{ ...imported[0], id: 'scene-existing', title: '服务器新登录' }];
    const plan = createWorkflowImportPlan(renamedBackup, existing, 'skip');
    expect(plan.items[0].action).toBe('skip');
  });

  it('overwrites one scene in place and remaps its linked 2FA key', () => {
    const plan = createWorkflowImportPlan(imported, existing, 'overwrite');
    const result = applyWorkflowImportPlan(plan, existing, {
      keys: [{ id: 'key-new', name: 'GitHub', issuer: 'GitHub', account: 'owner' }],
      importedKeyIds: new Map([['key-backup', 'key-new']]),
    }, () => 'unused', 500);

    expect(result.workflowNotes).toHaveLength(1);
    expect(result.workflowNotes[0]).toMatchObject({
      id: 'scene-existing',
      title: '服务器登录',
      content: '备份流程',
      favorite: true,
      lastUsed: 200,
      useCount: 4,
      createdAt: 100,
      updatedAt: 500,
      linkedKeys: [{ keyId: 'key-new', name: 'GitHub' }],
    });
  });

  it('only creates a renamed copy when the user explicitly chooses to import all', () => {
    const plan = createWorkflowImportPlan(imported, existing, 'all');
    expect(plan.items[0]).toMatchObject({ action: 'add', originalTitle: '服务器登录' });
    expect(plan.items[0].candidate.title).toBe('服务器登录 (2)');

    const result = applyWorkflowImportPlan(plan, existing, {}, () => 'scene-copy', 500);
    expect(result.workflowNotes.map((note) => [note.id, note.title])).toEqual([
      ['scene-existing', '服务器登录'],
      ['scene-copy', '服务器登录 (2)'],
    ]);
  });

  it('deduplicates repeated scenes within one backup batch', () => {
    const repeated = [{ ...imported[0], title: '新场景' }, { ...imported[0], title: '新场景' }];
    const plan = createWorkflowImportPlan(repeated, [], 'skip');
    expect(plan.items.map((item) => item.action)).toEqual(['add', 'skip']);
  });
});
