import { readFileSync, existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { layout, field } from '../../src/ui/layout.js';
import { accountServicesPage, forcePasswordPage } from '../../src/ui/pages.js';

const css = readFileSync(new URL('../../src/ui/static/app.css', import.meta.url), 'utf8');
const colors = Object.fromEntries([...css.matchAll(/--color-([\w-]+):\s*(#[a-f0-9]{6})/g)].map(m => [m[1], m[2]]));
function luminance(hex: string): number {
  const c = hex.slice(1).match(/../g)!.map(v => parseInt(v, 16) / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
  return c[0]! * .2126 + c[1]! * .7152 + c[2]! * .0722;
}
function contrast(a: string, b: string): number { const x = luminance(a), y = luminance(b); return (Math.max(x, y) + .05) / (Math.min(x, y) + .05); }
describe('canonical design and safe HTML', () => {
  it('uses exact canonical tokens and readable opaque foregrounds', () => {
    const design = readFileSync(new URL('../../../StreamingEngine/DESIGN.md', import.meta.url), 'utf8');
    for (const [key, value] of Object.entries(colors)) expect(design).toContain(`${key}: "${value}"`);
    for (const fg of ['ink', 'body', 'ink-muted']) for (let i = 1; i <= 6; i++) expect(contrast(colors[fg]!, colors[`surface-${i}`]!)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(colors['on-primary']!, colors.primary!)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(colors['hairline-strong']!, colors['surface-1']!)).toBeGreaterThanOrEqual(3);
    expect(css).not.toMatch(/gradient\(|opacity\s*:|prefers-color-scheme:\s*light/);
  });
  it('has native no-JS menu, skip link, role-aware admin link and accessible hints', () => {
    const html = layout({ title: 'Account', body: '<h1>Account</h1>', userEmail: 'user@example.test', admin: true });
    expect(html).toContain('<details class="mobile-nav">'); expect(html).toContain('href="#main"'); expect(html).toContain('href="/admin"');
    expect(layout({ title: 'Account', body: '', userEmail: 'ordinary@example.test' })).not.toContain('href="/admin"');
    expect(field({ name: 'test', label: 'Test', hint: 'Hint' })).toContain('aria-describedby="f-test-hint"');
  });
  it('escapes service data and does not accept script navigation', () => {
    const html = accountServicesPage({ csrf: 'test', email: 'a@example.test', services: [{ id: 'one', name: '<script>', enabled: true, adminUrl: 'javascript:alert(1)' }] });
    expect(html).not.toContain('javascript:'); expect(html).toContain('&lt;script&gt;'); expect(html.match(/<h1>/g)).toHaveLength(1);
    expect(forcePasswordPage({ csrf: 'test', email: 'a@example.test' }).match(/<h1>/g)).toHaveLength(1);
  });
  it('references actual installed local variable fonts', () => {
    for (const font of ['geist', 'inter']) expect(existsSync(new URL(`../../node_modules/@fontsource-variable/${font}/files/${font}-latin-wght-normal.woff2`, import.meta.url))).toBe(true);
  });
});
