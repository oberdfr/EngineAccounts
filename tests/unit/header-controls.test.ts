import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { layout, nav } from '../../src/ui/layout.js';

const script = readFileSync(new URL('../../src/ui/static/header-controls.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../../src/ui/static/header-controls.css', import.meta.url), 'utf8');
const render = (options: Partial<Parameters<typeof layout>[0]> = {}) => layout({
  title: 'Profilo', width: 'wide', userEmail: 'user@example.test', csrf: 'csrf-header', body: '<h1>Profilo</h1>', ...options,
});

describe('header area navigation markup', () => {
  it('keeps global administration exclusively in the always-visible header selector', () => {
    const html = render({ admin: true });
    expect(html).toContain('class="desktop-nav header-controls"');
    expect(html).toContain('<nav class="area-navigation" aria-label="Area">');
    expect(html).toContain('<a href="/account" aria-current="page">Account</a>');
    expect(html).toContain('<a href="/admin">Admin</a>');
    expect(html).not.toContain('data-area-selector');
    expect(html.match(/href="\/admin"/g)).toHaveLength(1);
    expect(html.match(/<aside class="account-rail">[\s\S]*?<\/aside>/)?.[0]).not.toContain('/admin');
    expect(nav('user@example.test', 'csrf', true)).not.toContain('/admin');
    expect(html).not.toContain('role="listbox"');
    expect(html).not.toContain('<select');
    expect(css).toContain('.top .header-controls { display:flex;');
  });
  it('uses server-derived destinations, escapes labels, and rejects unsafe paths', () => {
    const html = render({ adminDestinations: [
      { href: '/admin/services/streaming', label: 'Streaming <Engine>' },
      { href: 'javascript:alert(1)', label: 'Unsafe' },
      { href: '//outside.test/admin', label: 'Outside' },
      { href: '/admin/\\outside.test', label: 'Backslash' },
    ] });
    expect(html).toContain('href="/admin/services/streaming"');
    expect(html).toContain('>Admin</a>');
    expect(html).not.toContain('href="/admin"');
    expect(html).not.toMatch(/javascript:|outside\.test/);
    expect(render()).not.toContain('href="/admin');
  });
  it('reflects the current area on the server, including deep administration routes', () => {
    expect(render({ admin: true, currentPath: '/admin/accounts/123' })).toContain('href="/admin" aria-current="page">Admin');
    expect(render({ admin: true, currentPath: '/account/security' })).toContain('href="/account" aria-current="page">Account');
    const html = render({ currentPath: '/admin/services/two?view=members', adminDestinations: [
      { href: '/admin/services/one', label: 'One' }, { href: '/admin/services/two', label: 'Two' },
    ] });
    expect(html).toContain('href="/admin/services/two" aria-current="page"');
    expect(render({ currentPath: '/admin/services/two/accounts/123', adminDestinations: [
      { href: '/admin/services/one', label: 'One' }, { href: '/admin/services/two', label: 'Two' },
    ] })).toContain('href="/admin/services/two" aria-current="page">Admin');
  });
  it('preserves native identity links and CSRF-protected POST logout, with versioned local assets', () => {
    const html = render({ userEmail: '<user>@example.test' });
    expect(html).toContain('data-identity-menu');
    expect(html).toContain('Menu profilo: &lt;user&gt;@example.test');
    expect(html).toContain('method="post" action="/account/logout"');
    expect(html).toContain('name="_csrf" value="csrf-header"');
    expect(html).toContain('/static/header-controls.js?v=20261012-ui4');
    expect(html).toContain('/static/header-controls.css?v=20261012-ui4');
    expect(html).toContain('/static/select-controls.js?v=20261012-ui4');
    expect(html).not.toMatch(/style="|<script>/);
    expect(render({ userEmail: undefined })).not.toContain('data-area-selector');
  });
});

// Minimal event/DOM harness keeps these tests database- and browser-dependency-free.
function harness() {
  type Event = { key?: string; target?: Element; prevented?: boolean; preventDefault(): void };
  class Element {
    attrs = new Map<string, string>();
    dataset: Record<string, string> = {};
    listeners: Record<string, ((event: Event) => void)[]> = {};
    children: Element[] = [];
    selectors: Record<string, Element> = {};
    open = false;
    hidden = true;
    tabIndex = 0;
    clicks = 0;
    setAttribute(key: string, value: string) { this.attrs.set(key, value); }
    hasAttribute(key: string) { return this.attrs.has(key); }
    querySelector(key: string) { return this.selectors[key] ?? null; }
    querySelectorAll() { return this.children; }
    addEventListener(type: string, callback: (event: Event) => void) { (this.listeners[type] ??= []).push(callback); }
    contains(target?: Element): boolean { return target === this || this.children.some(child => child.contains(target)); }
    closest(key: string) { return key === 'a' && items.includes(this) ? this : null; }
    focus() { document.activeElement = this; }
    fire(type: string, values: Partial<Event> = {}) {
      const event: Event = { target: this, preventDefault() { this.prevented = true; }, ...values };
      this.listeners[type]?.forEach(callback => callback(event));
      return event;
    }
    click() { this.clicks++; this.fire('click'); }
  }
  const area = new Element(), identity = new Element(), details = new Element();
  const trigger = new Element(), menu = new Element(), summary = new Element();
  const items = [new Element(), new Element()];
  items[0]!.setAttribute('aria-current', 'page');
  menu.children = items;
  details.children = [menu];
  area.children = [trigger, details];
  area.selectors = { details, button: trigger, nav: menu };
  identity.children = [summary]; identity.selectors = { summary };
  const document = Object.assign(new Element(), { activeElement: trigger });
  document.selectors = { '[data-area-selector]': area, '[data-identity-menu]': identity };
  runInNewContext(script, { document });
  return { area, identity, details, trigger, menu, summary, items, document, outside: new Element() };
}

describe('progressive header keyboard and dismissal', () => {
  it('does not turn area navigation into a scripted menu', () => {
    const h = harness();
    expect(h.menu.attrs.has('role')).toBe(false);
    expect(h.trigger.listeners).toEqual({});
  });
  it('closes the native identity menu on Escape and restores focus', () => {
    const h = harness();
    h.identity.open = true;
    h.document.fire('keydown', { key: 'Escape' });
    expect(h.identity.open).toBe(false);
    expect(h.document.activeElement).toBe(h.summary);
  });
  it('does not intercept Tab or native navigation', () => {
    const h = harness();
    expect(h.document.fire('keydown', { key: 'Tab' }).prevented).not.toBe(true);
    h.identity.open = true;
    expect(h.identity.fire('click', { target: h.items[0] }).prevented).not.toBe(true);
    expect(h.identity.open).toBe(false);
  });
  it('closes on outside pointer/focus without stealing focus and closes identity on Escape', () => {
    const h = harness();
    h.identity.open = true; h.document.activeElement = h.outside;
    h.document.fire('pointerdown', { target: h.outside });
    expect(h.identity.open).toBe(false);
    expect(h.document.activeElement).toBe(h.outside);
    h.identity.open = true; h.document.fire('focusin', { target: h.outside });
    expect(h.identity.open).toBe(false);
    h.identity.open = true;
    h.document.fire('keydown', { key: 'Escape' });
    expect(h.identity.open).toBe(false);
    expect(h.document.activeElement).toBe(h.summary);
    h.identity.open = true;
    h.document.fire('pointerdown', { target: h.outside });
    expect(h.identity.open).toBe(false);
  });
});
