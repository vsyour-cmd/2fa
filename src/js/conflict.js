const COLLECTIONS = [
  {
    kind: 'token',
    label: '验证码',
    activeKey: 'keys',
    deletedKey: 'deletedItems',
    fields: {
      name: '名称', issuer: '发行方', account: '用户标识', note: '备注', secret: '密钥内容',
      group: '分组', period: '周期', digits: '位数', algorithm: '算法', favorite: '常用标记',
      order: '排序', lastUsed: '最近使用', useCount: '使用次数', icon: '图标', deletedAt: '删除时间',
    },
  },
  {
    kind: 'workflow',
    label: '使用场景',
    activeKey: 'workflowNotes',
    deletedKey: 'deletedWorkflowNotes',
    fields: {
      title: '标题', group: '分组', content: '操作内容', linkedKeys: '关联验证码', favorite: '常用标记',
      lastUsed: '最近使用', useCount: '使用次数', createdAt: '创建时间', updatedAt: '更新时间', deletedAt: '删除时间',
    },
  },
];

function sameValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function collectionStates(vault, definition) {
  const states = new Map();
  for (const item of vault[definition.deletedKey] || []) {
    states.set(String(item.id), { location: 'deleted', item });
  }
  for (const item of vault[definition.activeKey] || []) {
    states.set(String(item.id), { location: 'active', item });
  }
  return states;
}

function sameState(left, right) {
  if (!left || !right) return left === right;
  return left.location === right.location && sameValue(left.item, right.item);
}

function differenceLabels(left, right, fields) {
  if (!left) return ['仅云端存在'];
  if (!right) return ['仅本地存在'];
  const labels = [];
  if (left.location !== right.location) labels.push('当前/回收站状态');
  for (const [field, label] of Object.entries(fields)) {
    if (!sameValue(left.item[field], right.item[field])) labels.push(label);
  }
  return [...new Set(labels)];
}

function stateTimestamp(state) {
  if (!state) return 0;
  return Math.max(
    Number(state.item.updatedAt || 0),
    Number(state.item.deletedAt || 0),
    Number(state.item.lastUsed || 0),
  );
}

function defaultSide(local, cloud) {
  if (!local) return 'cloud';
  if (!cloud) return 'local';
  return stateTimestamp(cloud) > stateTimestamp(local) ? 'cloud' : 'local';
}

function itemTitle(definition, local, cloud) {
  const item = local?.item || cloud?.item || {};
  if (definition.kind === 'workflow') return item.title || '未命名场景';
  return item.name || item.issuer || item.account || '未命名验证码';
}

export function createConflictPlan(localVault, cloudVault) {
  const rows = [];
  for (const definition of COLLECTIONS) {
    const localStates = collectionStates(localVault, definition);
    const cloudStates = collectionStates(cloudVault, definition);
    const ids = new Set([...localStates.keys(), ...cloudStates.keys()]);
    for (const entityId of ids) {
      const local = localStates.get(entityId) || null;
      const cloud = cloudStates.get(entityId) || null;
      if (sameState(local, cloud)) continue;
      rows.push({
        id: `${definition.kind}:${entityId}`,
        kind: definition.kind,
        kindLabel: definition.label,
        entityId,
        title: itemTitle(definition, local, cloud),
        differences: differenceLabels(local, cloud, definition.fields),
        local,
        cloud,
        defaultSide: defaultSide(local, cloud),
      });
    }
  }

  if (!sameValue(localVault.workflowProtection, cloudVault.workflowProtection)) {
    rows.push({
      id: 'protection:workflow',
      kind: 'protection',
      kindLabel: '安全设置',
      entityId: 'workflow',
      title: '使用场景二次密码',
      differences: ['启用状态或密码设置'],
      local: { location: 'setting', item: localVault.workflowProtection },
      cloud: { location: 'setting', item: cloudVault.workflowProtection },
      defaultSide: 'local',
    });
  }
  return { rows };
}

function selectedSide(choices, row) {
  const selected = choices instanceof Map ? choices.get(row.id) : choices?.[row.id];
  return selected === 'local' || selected === 'cloud' ? selected : row.defaultSide;
}

export function mergeConflictPlan(localVault, cloudVault, plan, choices = {}) {
  const result = {
    version: 3,
    keys: [],
    deletedItems: [],
    workflowNotes: [],
    deletedWorkflowNotes: [],
    workflowProtection: localVault.workflowProtection,
  };
  const rows = new Map(plan.rows.map((row) => [row.id, row]));

  for (const definition of COLLECTIONS) {
    const localStates = collectionStates(localVault, definition);
    const cloudStates = collectionStates(cloudVault, definition);
    const ids = new Set([...localStates.keys(), ...cloudStates.keys()]);
    for (const entityId of ids) {
      const local = localStates.get(entityId) || null;
      const cloud = cloudStates.get(entityId) || null;
      const row = rows.get(`${definition.kind}:${entityId}`);
      const selected = row
        ? (selectedSide(choices, row) === 'cloud' ? cloud : local)
        : (local || cloud);
      if (!selected) continue;
      result[selected.location === 'deleted' ? definition.deletedKey : definition.activeKey].push(selected.item);
    }
  }

  const protectionRow = rows.get('protection:workflow');
  if (protectionRow) {
    result.workflowProtection = selectedSide(choices, protectionRow) === 'cloud'
      ? cloudVault.workflowProtection
      : localVault.workflowProtection;
  }
  return result;
}
