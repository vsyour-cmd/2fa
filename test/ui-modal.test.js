import { afterAll, describe, expect, it, vi } from 'vitest';

class FakeClassList {
  constructor(initial = []) {
    this.values = new Set(initial);
  }

  add(value) { this.values.add(value); }
  remove(value) { this.values.delete(value); }
  contains(value) { return this.values.has(value); }
  toggle(value, force) {
    if (force ?? !this.values.has(value)) this.values.add(value);
    else this.values.delete(value);
  }
}

class FakeElement {
  constructor(name, log, classes = []) {
    this.name = name;
    this.log = log;
    this.classList = new FakeClassList(classes);
    this.isConnected = true;
    this.inert = false;
    this.focusTarget = null;
    this.descendants = new Set();
  }

  querySelector() { return this.focusTarget; }
  querySelectorAll() { return []; }
  contains(element) { return this.descendants.has(element); }
  setAttribute(name, value) { this.log.push(`attribute:${name}:${value}`); }
  dispatchEvent() {}
  focus() {
    this.log.push(`focus:${this.name}`);
    document.activeElement = this;
  }
  blur() {
    this.log.push(`blur:${this.name}`);
    document.activeElement = document.body;
  }
}

describe('modal focus management', () => {
  it('moves focus out before applying aria-hidden and inert', async () => {
    const log = [];
    const body = new FakeElement('body', log);
    const opener = new FakeElement('opener', log);
    const closeButton = new FakeElement('close', log);
    const modal = new FakeElement('modal', log, ['hidden']);
    modal.focusTarget = closeButton;
    modal.descendants.add(closeButton);

    vi.stubGlobal('HTMLElement', FakeElement);
    vi.stubGlobal('CustomEvent', class CustomEvent {});
    vi.stubGlobal('requestAnimationFrame', (callback) => callback());
    vi.stubGlobal('document', {
      activeElement: opener,
      body,
      getElementById: () => modal,
      querySelector: () => null,
      querySelectorAll: () => [],
    });

    const { closeModal, openModal } = await import('../src/js/ui.js');
    openModal(modal, 'button');
    expect(document.activeElement).toBe(closeButton);

    log.length = 0;
    closeModal(modal);

    expect(document.activeElement).toBe(opener);
    expect(modal.inert).toBe(true);
    expect(log.indexOf('focus:opener')).toBeGreaterThanOrEqual(0);
    expect(log.indexOf('attribute:aria-hidden:true')).toBeGreaterThan(log.indexOf('focus:opener'));
  });
});

describe('modal window state', () => {
  it('restores the current minimized modal instead of closing it', async () => {
    const log = [];
    const body = new FakeElement('body', log);
    const closeButton = new FakeElement('close', log);
    const modal = new FakeElement('modal', log, ['hidden']);
    modal.focusTarget = closeButton;
    modal.dispatchCount = 0;
    modal.dispatchEvent = () => { modal.dispatchCount += 1; };

    vi.stubGlobal('HTMLElement', FakeElement);
    vi.stubGlobal('CustomEvent', class CustomEvent {});
    vi.stubGlobal('requestAnimationFrame', (callback) => callback());
    vi.stubGlobal('document', {
      activeElement: body,
      body,
      getElementById: () => modal,
      querySelector: () => null,
      querySelectorAll: () => [],
    });

    const { openModal } = await import('../src/js/ui.js');
    openModal(modal, 'button');
    modal.classList.add('modal-minimized');
    openModal(modal, 'button');

    expect(modal.classList.contains('modal-minimized')).toBe(false);
    expect(modal.classList.contains('hidden')).toBe(false);
    expect(modal.dispatchCount).toBe(0);
  });
});

afterAll(() => vi.unstubAllGlobals());
