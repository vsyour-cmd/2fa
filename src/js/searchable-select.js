const controllers = new WeakMap();
let activeController = null;
let selectSequence = 0;

function createElement(tagName, className = '', text = '') {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  if (text) element.textContent = text;
  return element;
}

function searchableText(option) {
  return [option.textContent, option.dataset.description, option.dataset.search]
    .filter(Boolean)
    .join(' ')
    .toLocaleLowerCase();
}

function optionButton(option, selectedValue) {
  const button = createElement('button', 'searchable-select-option');
  button.type = 'button';
  button.dataset.value = option.value;
  button.setAttribute('role', 'option');
  button.setAttribute('aria-selected', String(option.value === selectedValue));
  if (option.value === selectedValue) button.classList.add('selected');

  const marker = createElement('span', 'searchable-select-marker', '✓');
  marker.setAttribute('aria-hidden', 'true');
  const copy = createElement('span', 'searchable-select-option-copy');
  copy.append(createElement('strong', '', option.textContent));
  if (option.dataset.description) copy.append(createElement('small', '', option.dataset.description));
  button.append(marker, copy);
  if (option.dataset.count) button.append(createElement('span', 'searchable-select-count', option.dataset.count));
  return button;
}

export function enhanceSearchableSelect(select) {
  if (!select || controllers.has(select)) return controllers.get(select) || null;

  const sequence = ++selectSequence;
  const root = createElement('div', 'searchable-select');
  for (const className of (select.dataset.searchableClass || '').split(/\s+/).filter(Boolean)) root.classList.add(className);

  const trigger = createElement('button', 'searchable-select-trigger');
  trigger.type = 'button';
  trigger.setAttribute('aria-haspopup', 'listbox');
  trigger.setAttribute('aria-expanded', 'false');

  const triggerIcon = createElement('span', 'searchable-select-trigger-icon');
  triggerIcon.setAttribute('aria-hidden', 'true');
  const triggerLabel = createElement('span', 'searchable-select-trigger-label');
  const chevron = createElement('span', 'searchable-select-chevron');
  chevron.setAttribute('aria-hidden', 'true');
  trigger.append(triggerIcon, triggerLabel, chevron);

  const panel = createElement('div', 'searchable-select-panel');
  panel.hidden = true;
  const panelId = `${select.id || 'searchable-select'}-panel-${sequence}`;
  const listId = `${select.id || 'searchable-select'}-options-${sequence}`;
  panel.id = panelId;
  trigger.setAttribute('aria-controls', panelId);

  const searchWrap = createElement('label', 'searchable-select-search');
  const searchLabel = createElement('span', 'sr-only', select.dataset.filterLabel || '筛选选项');
  const searchIcon = createElement('span', 'searchable-select-search-icon');
  searchIcon.setAttribute('aria-hidden', 'true');
  const search = createElement('input');
  search.type = 'search';
  search.autocomplete = 'off';
  search.placeholder = select.dataset.searchPlaceholder || '筛选选项…';
  search.setAttribute('aria-controls', listId);
  searchWrap.append(searchLabel, searchIcon, search);

  const optionsLabel = createElement('p', 'searchable-select-options-label', select.dataset.optionsLabel || '可选项');
  const list = createElement('div', 'searchable-select-options');
  list.id = listId;
  list.setAttribute('role', 'listbox');
  list.setAttribute('aria-label', select.dataset.optionsLabel || select.dataset.filterLabel || '可选项');
  const empty = createElement('p', 'searchable-select-empty', '没有匹配的选项');
  empty.hidden = true;
  panel.append(searchWrap, optionsLabel, list, empty);

  select.before(root);
  root.append(select, trigger, panel);
  select.classList.add('searchable-select-native');
  select.setAttribute('aria-hidden', 'true');
  select.tabIndex = -1;

  function render() {
    const options = [...select.options].filter((option) => !option.disabled);
    const selected = options.find((option) => option.value === select.value) || options[0];
    const label = selected?.dataset.triggerLabel || selected?.textContent || select.dataset.filterLabel || '选择筛选条件';
    triggerLabel.textContent = label;
    trigger.setAttribute('aria-label', `${select.dataset.filterLabel || '筛选'}：${label}`);
    root.classList.toggle('has-value', Boolean(selected && selected.value !== (select.dataset.searchableDefault || '')));

    const query = search.value.trim().toLocaleLowerCase();
    const visible = options.filter((option) => !query || searchableText(option).includes(query));
    list.replaceChildren(...visible.map((option) => optionButton(option, select.value)));
    empty.hidden = visible.length > 0;
    optionsLabel.textContent = query ? `匹配选项 · ${visible.length}` : (select.dataset.optionsLabel || '可选项');
  }

  function close({ restoreFocus = false } = {}) {
    panel.hidden = true;
    root.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
    if (activeController === controller) activeController = null;
    if (restoreFocus) trigger.focus();
  }

  function open() {
    if (select.disabled) return;
    if (activeController && activeController !== controller) activeController.close();
    activeController = controller;
    search.value = '';
    render();
    panel.hidden = false;
    root.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    requestAnimationFrame(() => search.focus());
  }

  function choose(value) {
    if (![...select.options].some((option) => !option.disabled && option.value === value)) return;
    const changed = select.value !== value;
    select.value = value;
    render();
    close({ restoreFocus: true });
    if (changed) select.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function focusRelativeOption(direction) {
    const options = [...list.querySelectorAll('.searchable-select-option')];
    if (!options.length) return;
    const index = Math.max(0, options.indexOf(document.activeElement));
    options[(index + direction + options.length) % options.length].focus();
  }

  const controller = { close, open, render };
  controllers.set(select, controller);

  trigger.addEventListener('click', () => (panel.hidden ? open() : close({ restoreFocus: true })));
  trigger.addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowDown') return;
    event.preventDefault();
    open();
  });
  search.addEventListener('input', render);
  search.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      close({ restoreFocus: true });
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      list.querySelector('.searchable-select-option')?.focus();
    } else if (event.key === 'Enter') {
      const first = list.querySelector('.searchable-select-option');
      if (first) {
        event.preventDefault();
        choose(first.dataset.value);
      }
    }
  });
  list.addEventListener('click', (event) => {
    const option = event.target.closest('.searchable-select-option');
    if (option) choose(option.dataset.value);
  });
  list.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      close({ restoreFocus: true });
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      focusRelativeOption(event.key === 'ArrowDown' ? 1 : -1);
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      const options = [...list.querySelectorAll('.searchable-select-option')];
      options[event.key === 'Home' ? 0 : options.length - 1]?.focus();
    }
  });
  select.addEventListener('change', render);
  document.addEventListener('pointerdown', (event) => {
    if (!panel.hidden && !root.contains(event.target)) close();
  });
  render();
  return controller;
}

export function refreshSearchableSelect(select) {
  enhanceSearchableSelect(select)?.render();
}

export function enhanceSearchableSelects(root = document) {
  return [...root.querySelectorAll('select[data-searchable-filter]')].map(enhanceSearchableSelect);
}
