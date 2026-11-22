import { describe, expect, it } from 'vitest';
import {
  applySecurityHeaders,
  buildCsp,
  frameAncestorsSources,
  isSilentAuthorizationRequest,
  redirectOriginsOf,
} from '../../src/security/headers.js';

/**
 * Fix A dell'audit (`AUTH-AUDIT.md`): il silent renew del client web carica un
 * iframe su `/auth?prompt=none`, quindi quella sola risposta deve poter essere
 * incorniciata dalle origini dei client **registrati**. Le pagine UI restano
 * `DENY`. Qui si prova la regola pura (che cosa e' silenzioso, come si compone
 * `frame-ancestors`), senza database: l'integrazione e' in `exposure.test.ts`.
 */

const reply = () => {
  const headers = new Map<string, string>();
  return {
    headers,
    header(name: string, value: string) { headers.set(name.toLowerCase(), value); return this; },
    removeHeader(name: string) { headers.delete(name.toLowerCase()); },
    getHeaders() { return Object.fromEntries(headers); },
  };
};

const request = (url: string, method = 'GET') => ({
  method,
  protocol: 'http',
  raw: { url },
  headers: {},
}) as never;

describe('framing: che cosa e\' un authorization request silenzioso', () => {
  it("solo GET /auth con prompt=none", () => {
    expect(isSilentAuthorizationRequest('GET', '/auth?prompt=none&client_id=c')).toBe(true);
    // `prompt` puo' portare piu' valori.
    expect(isSilentAuthorizationRequest('GET', '/auth?prompt=login%20none')).toBe(true);
    // Senza prompt, o con un altro prompt, e' interattiva.
    expect(isSilentAuthorizationRequest('GET', '/auth?client_id=c')).toBe(false);
    expect(isSilentAuthorizationRequest('GET', '/auth?prompt=login&client_id=c')).toBe(false);
    // Altre rotte non sono mai incorniciabili.
    expect(isSilentAuthorizationRequest('GET', '/ui/interaction/x?prompt=none')).toBe(false);
    expect(isSilentAuthorizationRequest('GET', '/account?prompt=none')).toBe(false);
    // Solo GET/HEAD: il POST di consenso resta fuori.
    expect(isSilentAuthorizationRequest('POST', '/auth?prompt=none')).toBe(false);
    expect(isSilentAuthorizationRequest('HEAD', '/auth?prompt=none')).toBe(true);
  });
});

describe('framing: composizione di frame-ancestors', () => {
  it("default chiuso, e fail-closed su input malformato", () => {
    expect(frameAncestorsSources('none')).toEqual(["'none'"]);
    expect(frameAncestorsSources([])).toEqual(["'none'"]);
    expect(frameAncestorsSources(['*'])).toEqual(["'none'"]);
    expect(frameAncestorsSources(['https:'])).toEqual(["'none'"]);
    expect(frameAncestorsSources(['https://a.example/path'])).toEqual(["'none'"]);
    expect(frameAncestorsSources(['javascript:alert(1)'])).toEqual(["'none'"]);
    expect(buildCsp()).toContain("frame-ancestors 'none'");
  });

  it('solo origini esatte, deduplicate e stabili', () => {
    expect(frameAncestorsSources([
      'https://b.example', 'https://a.example', 'https://b.example', ' https://c.example ',
    ])).toEqual(['https://a.example', 'https://b.example', 'https://c.example']);
    // Stesso risultato a prescindere dall'ordine: l'header non deve ballare.
    expect(frameAncestorsSources(['https://c.example', 'https://a.example', 'https://b.example']))
      .toEqual(frameAncestorsSources(['https://b.example', 'https://c.example', 'https://a.example']));
    expect(buildCsp([], ['https://streaming.oberdfr.top']))
      .toContain('frame-ancestors https://streaming.oberdfr.top');
  });

  it("le origini vengono dai redirect_uri registrati, non dal richiedente", () => {
    const origini = redirectOriginsOf([
      { enabled: true, redirectUris: ['https://streaming.oberdfr.top/auth/callback'] },
      { enabled: true, redirectUris: ['http://localhost:5173/auth/callback'] },
      { enabled: false, redirectUris: ['https://spento.example/cb'] },
    ]);
    expect(frameAncestorsSources(origini)).toEqual([
      'http://localhost:5173',
      'https://streaming.oberdfr.top',
    ]);
  });
});

describe('framing: header emessi', () => {
  it('pagina normale: frame-ancestors none + X-Frame-Options DENY', () => {
    const res = reply();
    applySecurityHeaders(request('/ui/login'), res as never);
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(res.headers.get('x-frame-options')).toBe('DENY');
  });

  it('risposta silenziosa: solo frame-ancestors con le origini, niente XFO', () => {
    const res = reply();
    applySecurityHeaders(request('/auth?prompt=none'), res as never, {
      frameAncestors: ['https://streaming.oberdfr.top'],
    });
    const csp = res.headers.get('content-security-policy') ?? '';
    expect(csp).toContain('frame-ancestors https://streaming.oberdfr.top');
    expect(csp).not.toContain("frame-ancestors 'none'");
    expect(res.headers.has('x-frame-options')).toBe(false);
  });

  it('un elenco vuoto non apre niente: si torna a DENY', () => {
    const res = reply();
    applySecurityHeaders(request('/auth?prompt=none'), res as never, { frameAncestors: [] });
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(res.headers.get('x-frame-options')).toBe('DENY');
  });

  it('il resto della politica resta chiuso', () => {
    const res = reply();
    applySecurityHeaders(request('/auth?prompt=none'), res as never, {
      frameAncestors: ['https://streaming.oberdfr.top'],
    });
    const csp = res.headers.get('content-security-policy') ?? '';
    for (const direttiva of ["default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'"]) {
      expect(csp).toContain(direttiva);
    }
    expect(csp).not.toContain('unsafe-inline');
    expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    expect(res.headers.get('cross-origin-resource-policy')).toBe('same-origin');
  });

  it('CORP cross-origin solo per le origini opache delle app TV (file://, null)', () => {
    const withOrigin = (origin: string) => ({ method: 'POST', protocol: 'http', raw: { url: '/device/auth' }, headers: { origin } }) as never;
    for (const o of ['file://', 'null', 'file://top.oberdfr.streamingengine.tv-webos']) {
      const res = reply();
      applySecurityHeaders(withOrigin(o), res as never);
      expect(res.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
    }
    for (const o of ['https://evil.example', 'https://streaming.oberdfr.top']) {
      const res = reply();
      applySecurityHeaders(withOrigin(o), res as never);
      expect(res.headers.get('cross-origin-resource-policy')).toBe('same-origin');
    }
  });
});
