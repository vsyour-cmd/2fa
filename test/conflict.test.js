import { describe, expect, it } from 'vitest';
import { createConflictPlan, mergeConflictPlan } from '../src/js/conflict.js';

function vault(overrides = {}) {
  return {
    version: 3,
    keys: [],
    deletedItems: [],
    workflowNotes: [],
    deletedWorkflowNotes: [],
    workflowProtection: null,
    ...overrides,
  };
}

describe('item-level vault conflict resolution', () => {
  it('names the exact token and fields that differ without including secret values in labels', () => {
    const local = vault({ keys: [{ id: 'token-1', name: 'GitHub', note: 'local', secret: 'LOCALSECRET' }] });
    const cloud = vault({ keys: [{ id: 'token-1', name: 'GitHub', note: 'cloud', secret: 'CLOUDSECRET' }] });

    const plan = createConflictPlan(local, cloud);

    expect(plan.rows).toHaveLength(1);
    expect(plan.rows[0]).toMatchObject({ kindLabel: '验证码', title: 'GitHub' });
    expect(plan.rows[0].differences).toEqual(expect.arrayContaining(['备注', '密钥内容']));
    expect(plan.rows[0].differences.join(' ')).not.toContain('LOCALSECRET');
    expect(plan.rows[0].differences.join(' ')).not.toContain('CLOUDSECRET');
  });

  it('keeps additions from both devices by default', () => {
    const local = vault({ keys: [{ id: 'local-token', name: '本地验证码' }] });
    const cloud = vault({ workflowNotes: [{ id: 'cloud-scene', title: '云端场景', updatedAt: 20 }] });
    const plan = createConflictPlan(local, cloud);

    const merged = mergeConflictPlan(local, cloud, plan);

    expect(merged.keys.map((item) => item.id)).toEqual(['local-token']);
    expect(merged.workflowNotes.map((item) => item.id)).toEqual(['cloud-scene']);
  });

  it('applies each selected version independently, including recycle-bin state', () => {
    const local = vault({
      keys: [{ id: 'token-1', name: '本地名称' }],
      workflowNotes: [{ id: 'scene-1', title: '本地场景', updatedAt: 10 }],
    });
    const cloud = vault({
      deletedItems: [{ id: 'token-1', name: '云端名称', deletedAt: 30 }],
      workflowNotes: [{ id: 'scene-1', title: '云端场景', updatedAt: 20 }],
    });
    const plan = createConflictPlan(local, cloud);

    const merged = mergeConflictPlan(local, cloud, plan, {
      'token:token-1': 'local',
      'workflow:scene-1': 'cloud',
    });

    expect(merged.keys[0].name).toBe('本地名称');
    expect(merged.deletedItems).toHaveLength(0);
    expect(merged.workflowNotes[0].title).toBe('云端场景');
  });
});
