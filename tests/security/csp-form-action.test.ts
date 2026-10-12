import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HttpClient, TEST_CLIENT_ID, TEST_REDIRECT_URI, setupHarness, type Harness } from '../helpers/harness.js';
import { buildCsp, formActionSources, originOf, redirectOriginsOf } from '../../src/security/headers.js';

/**
 * `form-action` e il login da browser.
 *
 * Il difetto che questa suite copre e' invisibile a `curl` e alla intera suite
 * HTTP: un form che avvia una navigazione e' vincolato da `form-action` per
 * **tutta la catena di redirect**, e quella catena, per il flusso di
 * autorizzazione, termina dal lato del client. Con `form-action 'self'` il
 * browser **cancella** la navigazione dopo il consenso: la richiesta parte e il
 * server la lavora (il `code` arriva davvero al client), ma l'utente resta
 * fermo sulla pagina di consenso. Dal lato server non c'e' nessun errore, quindi
 * la verifica qui possibile e' sulla **direttiva**: deve contenere le origini dei
 * `redirect_uri` registrati, e nient'altro.
 */

let h: Harness;

beforeAll(async () => {
  h = await setupHarness();
}, 120_000);

afterAll(async () => {
  await h?.close();
});

describe('form-action: composizione della allowlist', () => {
  it("partendo da 'self' e basta quando non serve altro", () => {
    expect(formActionSources([])).toEqual(["'self'"]);
    expect(formActionSources()).toEqual(["'self'"]);
    expect(buildCsp()).toContain("form-action 'self'");
  });

  it('aggiunge le origini dei client, deduplicate e in ordine stabile', () => {
    const a = formActionSources(['http://b.example', 'http://a.example', 'http://b.example']);
    expect(a).toEqual(["'self'", 'http://a.example', 'http://b.example']);
    // Stabile: due chiamate con input diversi danno lo stesso header, altrimenti
    // la CSP cambierebbe a ogni richiesta e i test diventerebbero casuali.
    expect(formActionSources(['http://b.example', 'http://a.example'])).toEqual(a);
  });

  it("scarta il rumore invece di metterlo nell'header", () => {
    expect(formActionSources(['', "'self'", '  '])).toEqual(["'self'"]);
  });

  it("non allarga mai a '*'", () => {
    const csp = buildCsp(['http://a.example']);
    expect(csp).not.toContain('*');
    expect(csp).toContain("form-action 'self' http://a.example");
    // Le altre direttive restano chiuse: `form-action` non e' un invito al resto.
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
  });
});

describe('form-action: origine dei redirect_uri registrati', () => {
  it('estrae le origini e scarta i client disattivati', () => {
    const origini = redirectOriginsOf([
      { enabled: true, redirectUris: ['http://localhost:5173/auth/callback', 'http://localhost:5173/x'] },
      { enabled: false, redirectUris: ['https://disabilitato.example/cb'] },
      { enabled: true, redirectUris: ['https://streaming.oberdfr.top/callback'] },
    ]);
    expect(origini).toEqual(['http://localhost:5173', 'https://streaming.oberdfr.top']);
  });

  it('un redirect_uri non valido non fa fallire l\'avvio', () => {
    // Una allowlist incompleta blocca il login; una allowlist che impedisce
    // l'avvio blocca tutto. I dati corrotti si scartano.
    expect(redirectOriginsOf([{ enabled: true, redirectUris: ['non-e-una-url', 'http://ok.example/cb'] }])).toEqual([
      'http://ok.example',
    ]);
    expect(originOf('non-e-una-url')).toBeNull();
    expect(originOf('http://ok.example/cb')).toBe('http://ok.example');
  });
});

describe('form-action: la CSP delle pagine di interazione', () => {
  const formActionOf = (csp: string): string => /form-action ([^;]*)/.exec(csp)?.[1]?.trim() ?? '';

  it(" contiene l'origine del client registrato", async () => {
    // **Il test che copre il difetto.** Se la allowlist sparisce, questo fallisce;
    // il resto della suite HTTP continuerebbe a essere verde, perche' il problema
    // e' nel browser e non nel server.
    const client = new HttpClient(h.baseUrl);
    const res = await client.get('/ui/interaction/inesistente');
    const csp = res.headers.get('content-security-policy') ?? '';
    const origineClient = new URL(TEST_REDIRECT_URI).origin;
    expect(formActionOf(csp), `CSP senza l'origine del client: ${csp}`).toContain(origineClient);
    expect(formActionOf(csp)).toContain("'self'");
    // Nessun dominio estraneo, e nemmeno '*'.
    expect(formActionOf(csp)).not.toContain('*');
    expect(formActionOf(csp)).not.toContain('attaccante');
  });

  it("le pagine che non sono del flusso restano con 'self' e basta", async () => {
    // Allargare la CSP anche qui non serve a nulla e costerebbe una superficie
    // أكبر: su queste pagine nessuna navigazione esce dall'origine.
    const client = new HttpClient(h.baseUrl);
    for (const path of ['/ui/register', '/ui/login', '/', '/healthz', '/.well-known/openid-configuration']) {
      const res = await client.get(path);
      const csp = res.headers.get('content-security-policy') ?? '';
      expect(formActionOf(csp), `${path}: ${csp}`).toBe("'self'");
    }
  });

  it("l'origine e' quella del client registrato, non quella dichiarata a mano", async () => {
    // Se un giorno i domini cambiano, la allowlist li segue da sola: basta
    // registrare il client con i `redirect_uri` nuovi.
    const origini = redirectOriginsOf([
      { enabled: true, redirectUris: [TEST_REDIRECT_URI] },
    ]);
    expect(origini).toContain(new URL(TEST_REDIRECT_URI).origin);
    const client = new HttpClient(h.baseUrl);
    const res = await client.get('/ui/interaction/inesistente');
    const csp = res.headers.get('content-security-policy') ?? '';
    for (const origine of origini) expect(formActionOf(csp)).toContain(origine);
  });
});

describe('/userinfo: CORS per le SPA', () => {
  const registrata = () => new URL(TEST_REDIRECT_URI).origin;

  it('il preflight di un origine registrata riceve tutto quello che serve', async () => {
    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'OPTIONS',
      headers: {
        origin: registrata(),
        'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe(registrata());
    expect(res.headers.get('access-control-allow-headers') ?? '').toContain('authorization');
    expect(res.headers.get('access-control-allow-methods') ?? '').toContain('GET');
    expect(res.headers.get('vary') ?? '').toContain('Origin');
  });

  it("un'origine non registrata non ottiene nulla", async () => {
    const estranea = 'https://attaccante.example';
    const preflight = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'OPTIONS',
      headers: { origin: estranea, 'access-control-request-method': 'GET' },
    });
    expect(preflight.status).toBe(403);
    expect(preflight.headers.get('access-control-allow-origin')).toBeNull();

    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { origin: estranea, authorization: 'Bearer qualcosa' },
    });
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('la risposta all\'origine registrata non autorizza le credenziali', async () => {
    // `/userinfo` si autentica con il Bearer, non con i cookie: concedere le
    // credenziali ambientali non servirebbe e aprirebbe l'endpoint a qualunque
    // pagina su cui l'utente abbia un cookie.
    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { origin: registrata(), authorization: 'Bearer qualcosa' },
    });
    expect(res.headers.get('access-control-allow-origin')).toBe(registrata());
    expect(res.headers.get('access-control-allow-credentials')).toBeNull();
  });

  it('senza Origin la risposta resta quella di sempre (401 con WWW-Authenticate)', async () => {
    const res = await new HttpClient(h.baseUrl).get('/userinfo');
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate') ?? '').toContain('Bearer');
    expect(res.headers.get('vary') ?? '').toContain('Origin');
  });

  it("l'origine consentita segue il client registrato, quindi un client spento esce", async () => {
    // Il calcolo e' lo stesso di `form-action`: se il client non e' piu' valido,
    // l'origine non e' piu' tra le consentite.
    const spento = redirectOriginsOf([{ enabled: false, redirectUris: [TEST_REDIRECT_URI] }]);
    expect(spento).toEqual([]);
    const acceso = redirectOriginsOf([{ enabled: true, redirectUris: [TEST_REDIRECT_URI] }]);
    expect(acceso).toEqual([new URL(TEST_REDIRECT_URI).origin]);
    expect(acceso).not.toEqual(spento);
  });
});

describe('la correzione non ha rotto niente della CSP', () => {
  it('le direttive restano quelle di prima su una pagina di interazione', async () => {
    const res = await new HttpClient(h.baseUrl).get('/ui/interaction/inesistente');
    const csp = res.headers.get('content-security-policy') ?? '';
    for (const direttiva of [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "object-src 'none'",
    ]) {
      expect(csp, `manca ${direttiva}: ${csp}`).toContain(direttiva);
    }
    // `connect-src` resta chiuso: il frontend parla con noi via navigazione e via
    // `fetch` su `/token` e `/userinfo`, che sono endpoint nostri soggetti a CORS,
    // non un `connect-src` da allargare.
    expect(csp).toContain("connect-src 'self'");
  });

  it('il client di test e\' ancora quello registrato (nessun effetto collaterale)', async () => {
    const res = await new HttpClient(h.baseUrl).get(
      `/auth?response_type=code&client_id=${encodeURIComponent(TEST_CLIENT_ID)}` +
        `&redirect_uri=${encodeURIComponent(TEST_REDIRECT_URI)}&scope=openid&state=st-csp` +
        `&nonce=n-csp&code_challenge=${'a'.repeat(43)}&code_challenge_method=S256`,
    );
    // Se il client non esistesse la risposta sarebbe 400 `invalid_client`.
    expect(res.status).toBe(303);
    expect(res.headers.get('location') ?? '').toContain('/ui/interaction/');
  });
});