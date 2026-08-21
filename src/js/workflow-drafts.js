import { generateId, normalizeWorkflowNote } from './utils.js';

export const WORKFLOW_DRAFT_COLLECTION_VERSION = 3;
export const WORKFLOW_DRAFT_LIMIT = 50;

export function normalizeWorkflowDraft(raw = {}, createId = generateId) {
  const note = normalizeWorkflowNote({
    ...raw,
    id: raw.workflowId || raw.id || createId(),
  });
  const createdAt = Number.isFinite(Number(raw.createdAt)) ? Number(raw.createdAt) : Date.now();
  const updatedAt = Number.isFinite(Number(raw.updatedAt)) ? Number(raw.updatedAt) : createdAt;
  const baseUpdatedAt = Number.isFinite(Number(raw.baseUpdatedAt)) ? Number(raw.baseUpdatedAt) : 0;
  return {
    id: String(raw.id || createId()),
    workflowId: String(raw.workflowId || ''),
    title: note.title === '未命名场景' && !String(raw.title || '').trim() ? '' : note.title,
    group: note.group,
    content: note.content,
    linkedKeys: note.linkedKeys,
    baseUpdatedAt,
    createdAt,
    updatedAt,
  };
}

export function workflowDraftHasContent(draft) {
  return Boolean(
    String(draft?.title || '').trim()
    || String(draft?.group || '').trim()
    || String(draft?.content || '').trim()
    || draft?.linkedKeys?.length,
  );
}

export function parseWorkflowDraftCollection(payload, createId = generateId) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return [];
  const source = Number(payload.version) >= 2 && Array.isArray(payload.drafts)
    ? payload.drafts
    : (workflowDraftHasContent(payload) ? [{ ...payload, id: createId(), workflowId: '' }] : []);
  const byId = new Map();
  for (const raw of source) {
    const draft = normalizeWorkflowDraft(raw, createId);
    if (!workflowDraftHasContent(draft)) continue;
    const previous = byId.get(draft.id);
    if (!previous || draft.updatedAt >= previous.updatedAt) byId.set(draft.id, draft);
  }
  return [...byId.values()]
    .sort((left, right) => right.updatedAt - left.updatedAt)
    .slice(0, WORKFLOW_DRAFT_LIMIT);
}

export function serializeWorkflowDraftCollection(drafts) {
  return {
    version: WORKFLOW_DRAFT_COLLECTION_VERSION,
    drafts: parseWorkflowDraftCollection({ version: WORKFLOW_DRAFT_COLLECTION_VERSION, drafts }),
  };
}

export function upsertWorkflowDraft(drafts, rawDraft, createId = generateId) {
  const draft = normalizeWorkflowDraft(rawDraft, createId);
  const remaining = drafts.filter((item) => item.id !== draft.id);
  if (workflowDraftHasContent(draft)) remaining.push(draft);
  return parseWorkflowDraftCollection({
    version: WORKFLOW_DRAFT_COLLECTION_VERSION,
    drafts: remaining,
  }, createId);
}

export function removeWorkflowDraft(drafts, draftId) {
  return drafts.filter((draft) => draft.id !== draftId);
}

export function workflowDraftSourceChanged(draft, workflowNote) {
  if (!draft?.workflowId || !workflowNote || draft.workflowId !== workflowNote.id) return false;
  const sourceUpdatedAt = Number(workflowNote.updatedAt || 0);
  const baseline = Number(draft.baseUpdatedAt || 0);
  if (baseline > 0) return sourceUpdatedAt > baseline;
  return sourceUpdatedAt > Number(draft.updatedAt || 0);
}
