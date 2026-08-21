import { describe, expect, it } from 'vitest';
import {
  parseWorkflowDraftCollection,
  removeWorkflowDraft,
  serializeWorkflowDraftCollection,
  upsertWorkflowDraft,
  workflowDraftHasContent,
  workflowDraftSourceChanged,
} from '../src/js/workflow-drafts.js';

describe('workflow draft collections', () => {
  it('migrates the legacy single workflow draft into a collection', () => {
    const drafts = parseWorkflowDraftCollection({ title: '旧草稿', content: '继续操作', linkedKeys: [] }, () => 'legacy-draft');
    expect(drafts).toHaveLength(1);
    expect(drafts[0]).toMatchObject({ id: 'legacy-draft', workflowId: '', title: '旧草稿', content: '继续操作' });
  });

  it('keeps independent new and edit drafts without overwriting either one', () => {
    let drafts = upsertWorkflowDraft([], {
      id: 'new-draft', workflowId: '', title: '新场景', content: '步骤 A', updatedAt: 10,
    });
    drafts = upsertWorkflowDraft(drafts, {
      id: 'edit-draft', workflowId: 'scene-1', title: '已有场景', content: '修改内容', updatedAt: 20,
    });
    expect(drafts.map((draft) => draft.id)).toEqual(['edit-draft', 'new-draft']);
  });

  it('updates and removes only the selected draft', () => {
    const original = [
      { id: 'a', workflowId: '', title: 'A', content: 'one', linkedKeys: [], createdAt: 1, updatedAt: 1 },
      { id: 'b', workflowId: '', title: 'B', content: 'two', linkedKeys: [], createdAt: 2, updatedAt: 2 },
    ];
    const updated = upsertWorkflowDraft(original, { ...original[0], content: 'changed', updatedAt: 3 });
    expect(updated.find((draft) => draft.id === 'a').content).toBe('changed');
    expect(removeWorkflowDraft(updated, 'a').map((draft) => draft.id)).toEqual(['b']);
  });

  it('does not retain empty drafts and serializes only encrypted-payload data', () => {
    expect(workflowDraftHasContent({ title: '', group: '', content: '', linkedKeys: [] })).toBe(false);
    const collection = serializeWorkflowDraftCollection([{ id: 'empty', title: '', content: '', linkedKeys: [] }]);
    expect(collection).toEqual({ version: 3, drafts: [] });
  });

  it('keeps version 2 collections when upgrading the draft format', () => {
    const drafts = parseWorkflowDraftCollection({
      version: 2,
      drafts: [{ id: 'old', workflowId: 'scene-1', title: '旧格式', content: '内容', updatedAt: 20 }],
    });
    expect(drafts).toHaveLength(1);
    expect(drafts[0]).toMatchObject({ id: 'old', workflowId: 'scene-1', baseUpdatedAt: 0 });
  });

  it('detects when an edited scene changed after the draft started', () => {
    const draft = { workflowId: 'scene-1', baseUpdatedAt: 100, updatedAt: 300 };
    expect(workflowDraftSourceChanged(draft, { id: 'scene-1', updatedAt: 101 })).toBe(true);
    expect(workflowDraftSourceChanged(draft, { id: 'scene-1', updatedAt: 100 })).toBe(false);
    expect(workflowDraftSourceChanged(draft, { id: 'scene-2', updatedAt: 999 })).toBe(false);
  });
});
