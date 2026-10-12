import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, jwtVerify, type JWK } from 'jose';
import {
  HttpClient,
  TEST_CLIENT_ID,
  TEST_REDIRECT_URI,
  createTestUser,
  pkce,
  setupHarness,
  testConfig,
  testEnv,
  type Harness,
} from '../helpers/harness.js';
import { loadConfig } from '../../src/config.js';
import { hstsHeader } from '../../src/security/headers.js';

/**
 * Predisposizione all'esposizione: cosa succede quando questo servizio smette
 * di stare su `localhost`.
 *
 * Il pericolo di fondo e' uno solo e vale per tutti i file di questa suite:
 * `OIDC_ISSUER` finisce nel claim `iss` di ogni token e i consumer lo
 * confrontano. Se l'issuer resta sbagliato, qui non si vede niente di rotto —
 * il login funziona, il token arriva — e il fallimento arriva **dall'altra
 * parte**, come 401 su ogni richiesta. Qui si verifica che l'issuer viaggi
 * davvero, che cambiandolo cambi l'emissione, e che un consumer con un issuer
 * diverso rifiuti il token.
 */

let h: Harness;
let user: { id: string; email: string; password: string };

/** Percorre il flusso e restituisce i token emessi. */
async function issueTokens(overrides: Record<string, string> = {}): Promise<{
  accessToken: string;
  idToken: string;
  jwks: { keys: JWK[] };
  issuer: string;
}> {
  const client = new HttpClient(h.baseUrl);
  const pair = pkce('S256');
  const first = await client.get(
    `/auth?response_type=code&client_id=${encodeURIComponent(TEST_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(overrides.redirectUri ?? TEST_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent('openid profile email')}` +
      `&state=st-${Date.now()}&nonce=n-${Date.now()}` +
      `&code_challenge=${encodeURIComponent(pair.challenge)}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(h.config.OIDC_AUDIENCE)}`,
  );
  const toUi = first.headers.get('location') ?? '';
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1] ?? '';
  const loginHtml = await (await client.get(toUi)).text();
  const login = await client.postForm(`/ui/interaction/${uid}/login`, {
    _csrf: /name="_csrf" value="([^"]+)"/.exec(loginHtml)?.[1] ?? '',
    email: user.email,
    password: user.password,
  });
  let cursor = login.headers.get('location') ?? '';
  let code = '';
  for (let hop = 0; hop < 8 && !code; hop++) {
    const res = await client.get(cursor);
    const location = res.headers.get('location');
    if (!location) break;
    cursor = client.resolve(location);
    const parsed = new URL(cursor);
    if (parsed.origin + parsed.pathname === (overrides.redirectUri ?? TEST_REDIRECT_URI)) {
      code = parsed.searchParams.get('code') ?? '';
      break;
    }
    if (parsed.pathname.startsWith('/ui/interaction/')) {
      const html = await (await client.get(cursor)).text();
      const cuid = /\/ui\/interaction\/([^/?#]+)/.exec(cursor)?.[1] ?? '';
      const submitted = await client.postForm(`/ui/interaction/${cuid}/consent`, {
        _csrf: /name="_csrf" value="([^"]+)"/.exec(html)?.[1] ?? '',
        decision: 'allow',
      });
      cursor = client.resolve(submitted.headers.get('location') ?? '/');
    }
  }
  const tokenRes = await client.postForm('/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: overrides.redirectUri ?? TEST_REDIRECT_URI,
    client_id: TEST_CLIENT_ID,
    code_verifier: pair.verifier,
  });
  expect(tokenRes.status, `token: ${await tokenRes.clone().text()}`).toBe(200);
  const tokens = (await tokenRes.json()) as { access_token: string; id_token: string };
  const jwks = (await (await client.get('/.well-known/jwks.json')).json()) as { keys: JWK[] };
  const discovery = (await (await client.get('/.well-known/openid-configuration')).json()) as {
    issuer: string;
  };
  return { accessToken: tokens.access_token, idToken: tokens.id_token, jwks, issuer: discovery.issuer };
}

beforeAll(async () => {
  h = await setupHarness();
  user = await createTestUser(h, { verified: true });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

describe('OIDC_ISSUER: e\' davvero dentro il token', () => {
  it('discovery e claim iss coincidono con la configurazione', async () => {
    const { accessToken, idToken, issuer } = await issueTokens();
    expect(issuer, 'la discovery annuncia l\'issuer configurato').toBe(h.config.issuer);

    const payload = JSON.parse(
      Buffer.from(accessToken.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    expect(payload.iss, 'l\'access token porta l\'issuer').toBe(h.config.issuer);

    const idPayload = JSON.parse(Buffer.from(idToken.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(idPayload.iss, 'anche l\'id token porta l\'issuer').toBe(h.config.issuer);
  });

  it('un consumer con un issuer diverso rifiuta il token (401)', async () => {
    const { accessToken, jwks, issuer } = await issueTokens();
    const keys = createLocalJWKSet(jwks);

    // Il consumer giusto accetta.
    await expect(
      jwtVerify(accessToken, keys, { issuer, audience: h.config.OIDC_AUDIENCE, algorithms: ['EdDSA', 'RS256'] }),
    ).resolves.toBeTruthy();

    // Un consumer con un issuer diverso (per esempio il proxy ancora
    // configurato su localhost mentre il provider e' gia' sul dominio) no.
    // E' esattamente il 401 silenzioso da cui bisogna guardarsi.
    await expect(
      jwtVerify(accessToken, keys, {
        issuer: 'https://account.oberdfr.top',
        audience: h.config.OIDC_AUDIENCE,
        algorithms: ['EdDSA', 'RS256'],
      }),
    ).rejects.toThrow();
  });

  it('cambiando l\'env cambia l\'issuer emesso', () => {
    // Non serve avviare un secondo servizio: la parte che decide e' la
    // configurazione, e la prova che l'issuer arrivi nei token e' sopra.
    const conDominio = loadConfig({
      ...testEnv(),
      OIDC_ISSUER: 'https://account.oberdfr.top',
      PUBLIC_BASE_URL: 'https://account.oberdfr.top',
    });
    expect(conDominio.issuer).toBe('https://account.oberdfr.top');
    expect(conDominio.baseUrl).toBe('https://account.oberdfr.top');
    // HTTPS abilita Secure; il prefisso è opt-in perché ea_res ha Path=/auth/<uid>.
    expect(conDominio.secureCookies).toBe(true);
    expect(conDominio.cookiePrefix).toBe('');
    expect(loadConfig({
      ...testEnv(), OIDC_ISSUER: 'https://account.oberdfr.top', COOKIE_HOST_PREFIX: 'true',
    }).cookiePrefix).toBe('__Host-');
  });

  it('issuer in chiaro: cookie senza Secure, nessun prefisso __Host-', () => {
    const config = testConfig();
    expect(config.issuer.startsWith('http://')).toBe(true);
    expect(config.secureCookies).toBe(false);
    expect(config.cookiePrefix).toBe('');
  });
});

describe('cookie e TLS', () => {
  it('con issuer https i cookie sono Secure, HttpOnly e host-only senza prefisso incompatibile', async () => {
    // La proprieta' e' di `config`, e la si verifica anche sul cookie vero
    // emesso dal provider in un harness con issuer https.
    const secure = await setupHarness({
      overrides: {
        OIDC_ISSUER: 'https://account.oberdfr.top',
        PUBLIC_BASE_URL: 'https://account.oberdfr.top',
        COOKIE_SECURE: 'true',
        TRUST_PROXY: 'true',
      },
    });
    try {
      expect(secure.config.cookiePrefix).toBe('');
      expect(secure.config.secureCookies).toBe(true);

      // Il provider usa un cookie resume con path limitato: __Host- lo renderebbe
      // invalido nei browser. Verificare le protezioni vere, non il solo nome.
      const client = new HttpClient(secure.baseUrl);
      const login = await client.get('/ui/login', { headers: { 'x-forwarded-proto': 'https' } });
      const interazione = await client.get(
        `/auth?response_type=code&client_id=${encodeURIComponent(TEST_CLIENT_ID)}` +
          `&redirect_uri=${encodeURIComponent(TEST_REDIRECT_URI)}` +
          `&scope=openid&state=st-${Date.now()}&nonce=n-${Date.now()}` +
          `&code_challenge=${encodeURIComponent(pkce('S256').challenge)}&code_challenge_method=S256` +
           `&resource=${encodeURIComponent(secure.config.OIDC_AUDIENCE)}`,
        { headers: { 'x-forwarded-proto': 'https' } },
      );
      expect(login.status).toBe(200);
      expect(interazione.status).toBe(303);

      const cookies = [...login.headers.getSetCookie(), ...interazione.headers.getSetCookie()];
      expect(cookies.length, 'nessun cookie emesso').toBeGreaterThan(0);
      for (const cookie of cookies) {
        expect(cookie).not.toContain('__Host-');
        expect(cookie, `cookie senza Secure: ${cookie}`).toMatch(/;\s*secure\b/i);
        expect(cookie).toMatch(/;\s*httponly\b/i);
        expect(cookie).toMatch(/;\s*samesite=lax\b/i);
        expect(cookie, `cookie con Domain esplicito: ${cookie}`).not.toMatch(/;\s*domain=/i);
      }
      const resume = cookies.find((cookie) => cookie.startsWith('ea_res='));
      expect(resume, 'manca il cookie resume scoped').toMatch(/;\s*path=\/auth\/[^;]+/i);
      const nomi = cookies.map((c) => c.split('=')[0]!.trim());
      expect(nomi.some((n) => n.includes('ea_csrf')), 'manca il cookie CSRF').toBe(true);
    } finally {
      await secure.close();
    }
  }, 60_000);

  it('dietro reverse proxy che termina il TLS, /auth regge (TRUST_PROXY)', async () => {
    /*
     * Il test che vale di piu' di tutti per il passaggio ai domini.
     *
     * Senza `TRUST_PROXY`, `oidc-provider` (che e' una app Koa) vede una
     * connessione http anche quando il proxy ha gia' terminato il TLS, e la
     * libreria dei cookie **rifiuta di impostare un cookie Secure**:
     * "Cannot send secure cookie over unencrypted connection", HTTP 500 su ogni
     * `/auth`. Il login si romperebbe esattamente nel giorno in cui si passa da
     * `localhost` a `https://account.oberdfr.top`.
     */
    const url =
      `/auth?response_type=code&client_id=${encodeURIComponent(TEST_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(TEST_REDIRECT_URI)}` +
      `&scope=openid&state=st-proxy&nonce=n-proxy` +
      `&code_challenge=${encodeURIComponent(pkce('S256').challenge)}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent('https://api.engine.local/streaming')}`;

    const senza = await setupHarness({
      overrides: {
        OIDC_ISSUER: 'https://account.oberdfr.top',
        PUBLIC_BASE_URL: 'https://account.oberdfr.top',
      },
    });
    try {
      const res = await new HttpClient(senza.baseUrl).get(url, {
        headers: { 'x-forwarded-proto': 'https' },
      });
      // Il difetto vero: 500, non un 303.
      expect(
        res.status,
        `senza TRUST_PROXY il proxy non viene ascoltato: ${(await res.clone().text()).slice(0, 200)}`,
      ).toBe(500);
    } finally {
      await senza.close();
    }

    const con = await setupHarness({
      overrides: {
        OIDC_ISSUER: 'https://account.oberdfr.top',
        PUBLIC_BASE_URL: 'https://account.oberdfr.top',
        TRUST_PROXY: 'true',
      },
    });
    try {
      const res = await new HttpClient(con.baseUrl).get(url, {
        headers: { 'x-forwarded-proto': 'https' },
      });
      expect(res.status, 'con TRUST_PROXY il flusso riparte').toBe(303);
      expect(res.headers.get('location') ?? '').toContain('/ui/interaction/');
      const cookies = res.headers.getSetCookie();
      expect(cookies.length, 'nessun cookie emesso').toBeGreaterThan(0);
      for (const cookie of cookies) {
        expect(cookie).not.toContain('__Host-');
        expect(cookie, `cookie senza Secure: ${cookie}`).toMatch(/;\s*secure\b/i);
        expect(cookie).toMatch(/;\s*httponly\b/i);
        expect(cookie).toMatch(/;\s*samesite=lax\b/i);
        expect(cookie).not.toMatch(/;\s*domain=/i);
      }
      expect(cookies.some((c) => c.includes('ea_int')), 'manca il cookie di interazione').toBe(true);
    } finally {
      await con.close();
    }
  }, 90_000);

  it('HSTS: spento per default, si accende dietro interruttore, solo su https', () => {
    const spento = loadConfig({ ...testEnv() } as NodeJS.ProcessEnv);
    expect(spento.hsts.enabled, 'HSTS non deve essere attivo di default').toBe(false);

    const acceso = loadConfig({ ...testEnv(), HSTS_ENABLED: 'true' } as NodeJS.ProcessEnv);
    expect(acceso.hsts.enabled).toBe(true);
    expect(acceso.hsts.maxAge).toBe(31_536_000);
    expect(acceso.hsts.includeSubDomains).toBe(false);

    // Su richiesta http l'header non esce: su http sarebbe ignorato.
    const suHttp = { protocol: 'http', headers: {} } as never;
    expect(hstsHeader(suHttp, acceso.hsts)).toBeNull();

    // Su richiesta https dietro proxy che inoltra x-forwarded-proto esce.
    const viaProxy = {
      protocol: 'http',
      headers: { 'x-forwarded-proto': 'https, http' },
    } as never;
    expect(hstsHeader(viaProxy, acceso.hsts)).toBe('max-age=31536000');
    expect(hstsHeader(viaProxy, spento.hsts)).toBeNull();

    // includeSubDomains e' disattivato di default: non si vincolano host altrui.
    const conSub = loadConfig({
      ...testEnv(),
      HSTS_ENABLED: 'true',
      HSTS_INCLUDE_SUBDOMAINS: 'true',
    } as NodeJS.ProcessEnv);
    expect(hstsHeader(viaProxy, conSub.hsts)).toContain('includeSubDomains');
  });
});

describe('header di sicurezza sulle risposte', () => {
  it('le rotte della UI e gli endpoint OIDC portano CSP, nosniff, referrer e frame-ancestors', async () => {
    const client = new HttpClient(h.baseUrl);
    for (const path of ['/', '/ui/login', '/.well-known/openid-configuration', '/healthz']) {
      const res = await client.get(path);
      const csp = res.headers.get('content-security-policy') ?? '';
      expect(csp, `${path} senza CSP`).toContain("default-src 'none'");
      expect(csp, `${path} senza frame-ancestors`).toContain("frame-ancestors 'none'");
      expect(res.headers.get('x-content-type-options'), `${path} senza nosniff`).toBe('nosniff');
      expect(res.headers.get('referrer-policy'), `${path} senza referrer-policy`).toBe('no-referrer');
      expect(res.headers.get('x-frame-options'), `${path} senza X-Frame-Options`).toBe('DENY');
      expect(res.headers.get('x-powered-by'), `${path} espone X-Powered-By`).toBeNull();
      // HSTS non deve comparire su una richiesta http.
      expect(res.headers.get('strict-transport-security'), `${path} con HSTS su http`).toBeNull();
    }
  });
});

describe('CORS', () => {
  it('/token risponde a una Origin registrata e non a una sconosciuta', async () => {
    const client = new HttpClient(h.baseUrl);
    // Origine del `redirect_uri` registrato del client di test: e' l'unica che
    // il provider deve accettare (SPA sul dominio del frontend).
    const registrata = new URL(TEST_REDIRECT_URI).origin;
    const estranea = 'https://attaccante.example';

    const conOrigin = await client.postForm(
      '/token',
      // Con `client_id`, cosi' la libreria puo' assegnare il client e applicare
      // l'allowlist: senza, la richiesta si ferma prima e il confronto non avviene.
      { grant_type: 'authorization_code', code: 'inesistente', client_id: TEST_CLIENT_ID },
      { headers: { origin: registrata } },
    );
    // La risposta d'errore e' prevista (il code non esiste): quello che conta
    // e' l'intestazione CORS.
    expect(conOrigin.headers.get('access-control-allow-origin')).toBe(registrata);
    expect(conOrigin.headers.get('access-control-allow-origin')).not.toBe('*');
    expect(conOrigin.headers.get('vary') ?? '').toContain('Origin');

    const conEstranea = await client.postForm(
      '/token',
      { grant_type: 'authorization_code', code: 'inesistente', client_id: TEST_CLIENT_ID },
      { headers: { origin: estranea } },
    );
    expect(
      conEstranea.headers.get('access-control-allow-origin'),
      'una Origin non registrata non deve ricevere CORS',
    ).toBeNull();
    // E la richiesta viene proprio rifiutata, non solo silenziata.
    expect(conEstranea.status).toBe(400);
    const corpo = (await conEstranea.json()) as { error_description?: string };
    expect(corpo.error_description ?? '').toContain('origin');
  }, 60_000);

  it('discovery e JWKS sono dati pubblici: rispecchiare l\'origine non concede nulla', async () => {
    // Su questi endpoint la libreria rispecchia l'Origin senza controlli: sono
    // documenti pubblici, senza credenziali e senza dati utente. Serve saperlo,
    // per non confonderlo con l'allowlist che vale per /token.
    for (const path of ['/.well-known/openid-configuration', '/jwks']) {
      const res = await new HttpClient(h.baseUrl).get(path, {
        headers: { origin: 'https://attaccante.example' },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('set-cookie'), `${path} non deve impostare cookie`).toBeNull();
      expect(res.headers.get('access-control-allow-credentials')).toBeNull();
    }
  });

  it('/userinfo e` leggibile solo dalle origini dei client registrati', async () => {
    // Prima non aveva CORS e il frontend non poteva arricchire il profilo: la
    // richiesta moriva con `Failed to fetch` prima di arrivare a noi. Ora e'
    // aperto, ma solo alle origini dei `redirect_uri` registrati e senza
    // `Allow-Credentials` (l'autenticazione e' il Bearer, non i cookie).
    // Il dettaglio e in `tests/security/csp-form-action.test.ts`.
    const consentita = new URL(TEST_REDIRECT_URI).origin;
    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { authorization: 'Bearer qualcosa', origin: consentita },
    });
    expect(res.headers.get('access-control-allow-origin')).toBe(consentita);
    expect(res.headers.get('access-control-allow-credentials')).toBeNull();

    const estranea = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { authorization: 'Bearer qualcosa', origin: 'https://attaccante.example' },
    });
    expect(estranea.headers.get('access-control-allow-origin')).toBeNull();
  });
});

describe('superficie esposta', () => {
  it('non esistono endpoint /internal/', async () => {
    const client = new HttpClient(h.baseUrl);
    for (const path of ['/internal/', '/internal/events/account-deleted', '/internal/debug']) {
      const res = await client.get(path);
      expect(res.status, `${path} risponde ${res.status}: non deve esistere`).toBe(404);
    }
  });

  it('gli endpoint di salute non dicono nulla di sensibile', async () => {
    const client = new HttpClient(h.baseUrl);
    for (const path of ['/healthz', '/readyz']) {
      const res = await client.get(path);
      const body = (await res.json()) as Record<string, unknown>;
      const testo = JSON.stringify(body).toLowerCase();
      // Nessuna connessione, nessun segreto, nessun path del filesystem.
      for (const pericolo of ['postgres://', 'password', 'secret', '/home/', 'host:']) {
        expect(testo, `${path} contiene "${pericolo}"`).not.toContain(pericolo);
      }
    }
  });

  it('le pagine dell\'account senza sessione non dicono chi sei', async () => {
    const client = new HttpClient(h.baseUrl);
    const res = await client.get('/account');
    expect(res.status).toBe(303);
    const location = res.headers.get('location') ?? '';
    expect(location).toContain('/ui/login');
    // Il redirect non porta via nulla.
    expect(location).not.toContain('token=');
    expect(location).not.toContain('code=');
  });
});
