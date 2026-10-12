import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

const script = readFileSync(new URL('../../src/ui/static/select-controls.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../../src/ui/static/select-controls.css', import.meta.url), 'utf8');

// Small DOM/event harness, no database, runtime imports or additional packages.
function harness() {
  const observers: { callback: (records?: any[]) => void; target?: any }[] = [];
  class Event {
    defaultPrevented = false;
    constructor(public type: string, public init: any = {}) { Object.assign(this, init); }
    preventDefault() { this.defaultPrevented = true; }
    stopPropagation() {}
  }
  class Node {
    attrs = new Map<string, string>(); children: Node[] = []; parentElement: Node | null = null;
    listeners: Record<string, ((e: any) => void)[]> = {}; dataset: any = {}; className = ''; textContent = '';
    id = ''; hidden = false; tabIndex = 0; disabled = false; multiple = false; size = 0; required = false;
    autofocus = false; selectedIndex = 0; options: any[] = []; labels: Node[] = []; form: Node | null = null;
    validity = { valid: true }; scrollHeight = 180; scrollTop = 0; clientHeight = 160; offsetTop = 0; offsetHeight = 40;
    classList = { add: (_: string) => {}, remove: (_: string) => {} };
    constructor(public tagName = 'DIV') {}
    get isConnected(): boolean { return this === document || Boolean(this.parentElement?.isConnected); }
    setAttribute(key: string, value: any) { this.attrs.set(key, String(value)); }
    getAttribute(key: string) { return this.attrs.get(key) ?? null; }
    hasAttribute(key: string) { return this.attrs.has(key); }
    removeAttribute(key: string) { this.attrs.delete(key); }
    append(...nodes: Node[]) { for (const n of nodes) { n.remove(); n.parentElement = this; this.children.push(n); } }
    before(node: Node) { const p = this.parentElement; if (p) { node.remove(); node.parentElement = p; p.children.splice(p.children.indexOf(this), 0, node); } }
    remove() { const p = this.parentElement; if (p) p.children.splice(p.children.indexOf(this), 1); this.parentElement = null; }
    replaceChildren() { for (const child of [...this.children]) child.remove(); }
    contains(node: Node): boolean { return this === node || this.children.some(child => child.contains(node)); }
    matches(selector: string) { return selector === 'select' ? this.tagName === 'SELECT' : selector === ':disabled' ? this.disabled : false; }
    closest() { return null; }
    querySelectorAll(selector: string): Node[] { return this.children.flatMap(child => [
      ...(selector === 'select' ? child.tagName === 'SELECT' : child.getAttribute('role') === 'option') ? [child] : [],
      ...child.querySelectorAll(selector),
    ]); }
    addEventListener(type: string, listener: (e: any) => void) { (this.listeners[type] ??= []).push(listener); }
    removeEventListener(type: string, listener: (e: any) => void) { this.listeners[type] = this.listeners[type]?.filter(fn => fn !== listener) ?? []; }
    dispatchEvent(event: any) { event.target ??= this; this.listeners[event.type]?.forEach(fn => fn(event)); return !event.defaultPrevented; }
    fire(type: string, init: any = {}) { const event = new Event(type, init); this.dispatchEvent(event); return event; }
    focus() { document.activeElement = this; this.fire('focus'); }
    getBoundingClientRect() { return { left: 20, top: 40, bottom: 84, width: 240 }; }
    showPopover() { this.setAttribute('open-test', 'true'); }
    hidePopover() { this.removeAttribute('open-test'); }
  }
  const document: any = new Node('DOCUMENT');
  document.readyState = 'loading'; document.activeElement = null; document.body = new Node('BODY');
  document.documentElement = document.body; document.append(document.body);
  document.createElement = (tag: string) => new Node(tag.toUpperCase());
  document.createElementNS = (_: string, tag: string) => new Node(tag);
  const rules: any[] = [];
  document.styleSheets = [{ href: 'http://test/static/select-controls.css?v=1', cssRules: rules,
    insertRule: (_: string, index: number) => { rules.splice(index, 0, { style: { setProperty() {} } }); return index; },
    deleteRule: (index: number) => rules.splice(index, 1) }];
  const window = Object.assign(new Node(), { innerWidth: 320, innerHeight: 640 });
  class MutationObserver {
    entry: any;
    constructor(callback: any) { this.entry = { callback }; observers.push(this.entry); }
    observe(target: any) { this.entry.target = target; }
    disconnect() { this.entry.target = null; }
  }
  const context: any = { document, window, MutationObserver, Event, queueMicrotask, setTimeout };
  runInNewContext(script, context);
  const makeSelect = (labels = ['Alpha', 'Beta', 'Charlie']) => {
    const select = new Node('SELECT'); select.setAttribute('name', 'status'); select.setAttribute('id', 'status');
    select.options = labels.map((label, index) => ({ label, value: String(index), disabled: false, hidden: false, parentElement: select }));
    select.labels = [new Node('LABEL')]; select.labels[0]!.textContent = 'Status';
    document.body.append(select); return select;
  };
  const select = makeSelect(); document.fire('DOMContentLoaded');
  const trigger = () => select.parentElement!.children[1]!;
  const menu = () => document.body.children.find((node: Node) => node.getAttribute('role') === 'listbox')!;
  return { document, window, context, observers, select, trigger, menu, makeSelect, rules };
}

describe('global progressive Engine select controls', () => {
  it('preserves the native form source and forwards labels, required and error attributes', () => {
    const h = harness();
    expect(h.menu().id).toBe(h.trigger().getAttribute('aria-controls'));
    expect(h.select.getAttribute('name')).toBe('status');
    expect(h.select.getAttribute('id')).toBe('status');
    expect(h.select.tabIndex).toBe(-1);
    expect(h.trigger().getAttribute('role')).toBe('combobox');
    expect(h.trigger().getAttribute('aria-labelledby')).toBe(h.select.labels[0]!.id);
    h.select.required = true; h.select.setAttribute('aria-describedby', 'status-help'); h.select.setAttribute('aria-errormessage', 'status-error');
    h.context.EngineSelectControls.sync(h.select);
    expect(h.trigger().getAttribute('aria-required')).toBe('true');
    expect(h.trigger().getAttribute('aria-describedby')).toBe('status-help');
    expect(h.trigger().getAttribute('aria-errormessage')).toBe('status-error');
    h.select.validity.valid = false;
    expect(h.select.fire('invalid').defaultPrevented).toBe(true);
    expect(h.document.activeElement).toBe(h.trigger());
    expect(h.trigger().getAttribute('aria-invalid')).toBe('true');
  });
  it('supports keyboard navigation, commitment, duplicate values and exactly one input/change', () => {
    const h = harness(); const events: string[] = [];
    h.select.options.forEach(option => { option.value = 'same'; });
    for (const type of ['input', 'change']) h.select.addEventListener(type, () => events.push(type));
    h.trigger().fire('keydown', { key: 'ArrowDown' });
    expect(h.trigger().getAttribute('aria-expanded')).toBe('true');
    h.trigger().fire('keydown', { key: 'End' }); h.trigger().fire('keydown', { key: 'Enter' });
    expect(h.select.selectedIndex).toBe(2); expect(events).toEqual(['input', 'change']);
    h.trigger().fire('keydown', { key: 'Home' }); h.trigger().fire('keydown', { key: 'ArrowDown' });
    h.trigger().fire('keydown', { key: 'ArrowUp' }); h.trigger().fire('keydown', { key: ' ' });
    expect(h.select.selectedIndex).toBe(0);
    h.trigger().fire('click'); h.trigger().fire('keydown', { key: 'Escape' });
    expect(h.trigger().getAttribute('aria-expanded')).toBe('false');
    h.trigger().fire('click'); expect(h.trigger().fire('keydown', { key: 'Tab' }).defaultPrevented).toBe(false);
    expect(h.trigger().getAttribute('aria-expanded')).toBe('false');
  });
  it('does not resurrect removed controls and rebuilds controls reparented elsewhere', () => {
    const h = harness();
    const update = () => h.observers.find(item => item.target === h.document.body)!.callback([]);
    const wrapper = h.select.parentElement!;
    h.select.remove(); update();
    expect(h.select.isConnected).toBe(false);
    expect(wrapper.isConnected).toBe(false);
    const moved = h.makeSelect();
    h.context.EngineSelectControls.enhance(moved);
    const previous = moved.parentElement!;
    h.document.body.append(moved); update();
    expect(previous.isConnected).toBe(false);
    expect(moved.isConnected).toBe(true);
    expect(moved.parentElement!.className).toBe('ea-select-wrap');
    expect(moved.parentElement).not.toBe(previous);
  });
  it('filters hidden and disabled options and optgroups, supports typeahead and selected check', () => {
    const h = harness(); h.select.options[1].disabled = true;
    h.select.options[2].parentElement = { tagName: 'OPTGROUP', disabled: true, label: 'Group' };
    h.trigger().fire('click'); h.trigger().fire('keydown', { key: 'End' });
    expect(h.trigger().getAttribute('aria-activedescendant')).toContain('option-0');
    expect(h.menu().querySelectorAll('[role="option"]')).toHaveLength(3);
    h.select.options[2].parentElement.disabled = false;
    h.context.EngineSelectControls.sync(h.select); h.trigger().fire('keydown', { key: 'c' });
    h.trigger().fire('keydown', { key: 'Enter' }); expect(h.select.selectedIndex).toBe(2);
    h.trigger().fire('click');
    expect(h.menu().querySelectorAll('[role="option"]')[2]!.children[1]!.getAttribute('class')).toBe('ea-select-check');
    h.select.options[1].hidden = true; h.context.EngineSelectControls.sync(h.select);
    expect(h.menu().querySelectorAll('[role="option"]')).toHaveLength(2);
  });
  it('dismisses outside, retains reset state and enhances future single selects only', async () => {
    const h = harness(); h.trigger().fire('click');
    h.document.fire('pointerdown', { target: h.document.body });
    expect(h.trigger().getAttribute('aria-expanded')).toBe('false');
    h.trigger().fire('click'); h.document.fire('focusin', { target: h.document.body });
    expect(h.trigger().getAttribute('aria-expanded')).toBe('false');
    h.select.form = h.document.body; h.select.selectedIndex = 2; h.select.fire('change');
    h.document.fire('reset', { target: h.document.body });
    await Promise.resolve();
    expect(h.trigger().children[0]!.textContent).toBe('Charlie');
    h.select.selectedIndex = 0;
    await new Promise(resolve => setTimeout(resolve, 0)); expect(h.trigger().children[0]!.textContent).toBe('Alpha');
    h.select.selectedIndex = 2; h.select.fire('change');
    const cancelled = h.document.fire('reset', { target: h.document.body });
    cancelled.preventDefault();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(h.trigger().children[0]!.textContent).toBe('Charlie');
    const future = h.makeSelect(); h.observers.find(item => item.target === h.document.body)!.callback([{ addedNodes: [future] }]);
    expect(future.parentElement!.className).toBe('ea-select-wrap');
    const multiple = h.makeSelect(); multiple.multiple = true; h.context.EngineSelectControls.enhance(multiple);
    expect(multiple.parentElement).toBe(h.document.body);
    const expanded = h.makeSelect(); expanded.size = 5; h.context.EngineSelectControls.enhance(expanded);
    expect(expanded.parentElement).toBe(h.document.body);
  });
  it('clamps to a 320px viewport, flips above and uses stylesheet rules without inline styles', () => {
    const h = harness();
    const p = h.context.EngineSelectControls.position({ left: 290, top: 550, bottom: 594, width: 500 }, { width: 320, height: 640 }, 320);
    expect(p.width).toBe(304); expect(p.left).toBe(8); expect(p.top).toBe(224); expect(p.maxHeight).toBe(320);
    h.trigger().fire('click'); expect(h.rules).toHaveLength(1);
    expect(h.menu().hasAttribute('style')).toBe(false);
    expect(script).not.toMatch(/\.style\s*=|setAttribute\(['"]style/);
    expect(css).toContain('background-position:right 16px center');
    expect(css).toContain('padding:10px 48px 10px 14px');
    expect(css).toContain('width:18px; height:18px');
    expect(script).not.toMatch(/\bimport\b|StreamingEngine\//);
  });
  it('synchronizes external changes, refuses disabled selections and cleans up converted controls', () => {
    const h = harness();
    h.select.selectedIndex = 2; h.select.fire('input');
    expect(h.trigger().children[0]!.textContent).toBe('Charlie');
    h.select.disabled = true; h.context.EngineSelectControls.sync(h.select);
    expect(h.trigger().disabled).toBe(true);
    h.trigger().fire('keydown', { key: 'Home' });
    expect(h.trigger().getAttribute('aria-expanded')).toBe('false');
    h.select.disabled = false; h.context.EngineSelectControls.sync(h.select); h.trigger().fire('click');
    expect(h.rules).toHaveLength(1);
    h.select.multiple = true;
    h.observers.find(item => item.target === h.select)!.callback();
    expect(h.select.parentElement).toBe(h.document.body);
    expect(h.select.getAttribute('aria-hidden')).toBe(null);
    expect(h.select.getAttribute('tabindex')).toBe(null);
    expect(h.rules).toHaveLength(0);
    h.select.multiple = false; h.context.EngineSelectControls.enhance(h.select);
    expect(h.select.listeners.input).toHaveLength(1);
  });
  it('clears validation on reset and never treats option labels as HTML', async () => {
    const h = harness();
    h.select.options[0].label = '<img src=x onerror=alert(1)>';
    h.select.validity.valid = false; h.select.form = h.document.body;
    h.select.fire('invalid'); h.trigger().fire('click');
    expect(h.menu().querySelectorAll('[role="option"]')[0]!.children[0]!.textContent).toContain('<img');
    h.document.fire('reset', { target: h.document.body }); await new Promise(resolve => setTimeout(resolve, 0));
    expect(h.trigger().getAttribute('aria-invalid')).toBe(null);
    expect(script).not.toContain('innerHTML');
  });
});
