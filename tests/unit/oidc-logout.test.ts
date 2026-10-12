import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Provider, type AdapterPayload } from 'oidc-provider';
import { logoutSource, postLogoutSuccessSource } from '../../src/oidc/logout.js';
import { CSP } from '../../src/security/headers.js';

// Nessun database, schema, account o chiave su disco: solo stato sintetico
// in memoria e richieste ai veri endpoint end_session di oidc-provider.
const data = new Map<string, AdapterPayload>();
class MemoryAdapter {
  constructor(private readonly name: string) {}
  async upsert(id: string, payload: AdapterPayload) { data.set(`${this.name}:${id}`, payload); }
  async find(id: string) { return data.get(`${this.name}:${id}`); }
  async findByUserCode() { return undefined; }
  async findByUid() { return undefined; }
  async consume() {}
  async destroy(id: string) { data.delete(`${this.name}:${id}`); }
  async revokeByGrantId(grantId: string) {
    for (const [key, payload] of data) {
      if (key.startsWith(`${this.name}:`) && payload.grantId === grantId) data.delete(key);
    }
  }
}

const clientId = 'logout-test-rp';
const redirect = 'https://rp.example.test/signed-out';
const loginTs = Math.floor(Date.now() / 1000) - 30;
let provider: Provider;
let server: Server;
let origin: string;
let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

beforeAll(async () => {
  const keys = await generateKeyPair('EdDSA', { extractable: true });
  privateKey = keys.privateKey;
  const key = { ...await exportJWK(privateKey), kid: 'logout-test-key', alg: 'EdDSA', use: 'sig' };
  // L'issuer non dipende dalla porta HTTP effimera del test.
  provider = new Provider('https://issuer.example.test', {
    adapter: MemoryAdapter,
    jwks: { keys: [key] },
    clients: [{ client_id: clientId, redirect_uris: ['https://rp.example.test/callback'],
      post_logout_redirect_uris: [redirect], token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      id_token_signed_response_alg: 'EdDSA' }],
    cookies: { keys: ['test-only-cookie-key'], long: { signed: false, secure: false } },
    features: { devInteractions: { enabled: false }, revocation: { enabled: true },
      rpInitiatedLogout: { enabled: true, logoutSource, postLogoutSuccessSource } },
    routes: { end_session: '/end-session', revocation: '/revoke' },
    ttl: { Session: 3600, IdToken: 300, Grant: 3600, AccessToken: 300, RefreshToken: 3600 },
    claims: { openid: ['sub', 'amr', 'auth_time'] },
  });
  const callback = provider.callback();
  server = createServer((request, response) => {
    response.setHeader('Content-Security-Policy', `${CSP}; upgrade-insecure-requests`);
    callback(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('porta di test non disponibile');
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server?.close((error) => error ? reject(error) : resolve()));
  data.clear();
});

async function hint(overrides: Record<string, unknown> = {}, expiresAt?: number) {
  return new SignJWT({ sub: 'synthetic-subject', auth_time: loginTs, ...overrides })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'logout-test-key' })
    .setIssuer(provider.issuer).setAudience(clientId).setIssuedAt().setExpirationTime(expiresAt ?? '5m')
    .sign(privateKey);
}

async function browser() {
  const session = new provider.Session();
  session.accountId = 'synthetic-subject';
  session.loginTs = loginTs;
  session.authorizations = { [clientId]: { grantId: 'synthetic-grant', sid: 'synthetic-sid' } };
  await session.save(3600);
  const cookie = `${provider.cookieName('session')}=${session.jti}`;
  return { session, request: (url: string, init: RequestInit = {}) => fetch(new URL(url, origin), {
    ...init, redirect: 'manual', headers: { cookie, ...init.headers },
  }) };
}

function logoutUrl(token?: string, uri = redirect) {
  const params = new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: uri, state: 'logout-state' });
  if (token) params.set('id_token_hint', token);
  return `/end-session?${params}`;
}

describe('logout OIDC senza pagina predefinita del provider', () => {
  it('il provider include auth_time nello scope openid e accetta il suo ID token', async () => {
    const client = await provider.Client.find(clientId);
    expect(client).toBeDefined();
    const token = new provider.IdToken({ sub: 'synthetic-subject', auth_time: loginTs }, { client });
    Object.assign(token, { scope: 'openid' });
    const jwt = await token.issue({ use: 'idtoken' });
    const validated = await provider.IdToken.validate(jwt, client!);
    expect(validated.payload.auth_time).toBe(loginTs);
    const b = await browser();
    const html = await (await b.request(logoutUrl(jwt))).text();
    expect(html).toContain('src="/static/logout.js"');
  });

  it('token verificato del login corrente: form CSRF originale e script esterno', async () => {
    const b = await browser();
    const response = await b.request(logoutUrl(await hint()));
    expect(response.status).toBe(200);
    const csp = response.headers.get('content-security-policy')!;
    expect(csp).toContain("form-action 'self' https://rp.example.test");
    expect(csp.replace("form-action 'self' https://rp.example.test", "form-action 'self'")).toBe(`${CSP}; upgrade-insecure-requests`);
    const html = await response.text();
    expect(html).toContain('Uscita in corso');
    expect(html).toContain('src="/static/logout.js"');
    expect(html).toContain('name="logout" value="yes"');
    expect(html).toContain('logout-page');
    expect(html).not.toContain('<style>');
    expect(html).not.toContain('fonts.googleapis.com');
    expect(html).not.toContain('Do you want to sign-out');
    expect(await provider.Session.find(b.session.jti)).toBeDefined();
    const action = /<form[^>]+action="([^"]+)"/.exec(html)?.[1];
    const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1];
    expect(action).toBeTruthy();
    expect(xsrf).toBeTruthy();
    const confirmed = await b.request(new URL(action!).pathname, { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ xsrf: xsrf!, logout: 'yes' }) });
    expect(confirmed.status).toBe(303);
    expect(confirmed.headers.get('location')).toBe(`${redirect}?state=logout-state`);
    expect(await provider.Session.find(b.session.jti)).toBeUndefined();
  });

  it('revocare refresh/access token prima del logout conserva il riferimento del grant nella sessione', async () => {
    const b = await browser();
    const client = (await provider.Client.find(clientId))!;
    const grant = new provider.Grant({ accountId: 'synthetic-subject', clientId });
    const grantId = await grant.save();
    b.session.authorizations![clientId]!.grantId = grantId;
    await b.session.save(3600);
    const refresh = new provider.RefreshToken({ client, accountId: 'synthetic-subject', grantId,
      scope: 'openid', gty: 'authorization_code' });
    const access = new provider.AccessToken({ client, accountId: 'synthetic-subject', grantId, gty: 'authorization_code' });
    const refreshValue = await refresh.save();
    const accessValue = await access.save();
    for (const [token_type_hint, token] of [['refresh_token', refreshValue], ['access_token', accessValue]]) {
      const response = await b.request('/revoke', { method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: clientId, token_type_hint: token_type_hint!, token: token! }) });
      expect(response.status).toBe(200);
    }
    expect(await provider.Grant.find(grantId)).toBeUndefined();
    const remaining = await provider.Session.find(b.session.jti);
    expect(remaining?.authorizations?.[clientId]?.grantId).toBe(grantId);
    const html = await (await b.request(logoutUrl(await hint()))).text();
    expect(html).toContain('src="/static/logout.js"');
  });

  it.each([
    ['senza hint', undefined],
    ['account diverso', { sub: 'other-subject' }],
    ['login precedente', { auth_time: loginTs - 100 }],
    ['senza auth_time', { auth_time: undefined }],
    ['sid diverso', { sid: 'other-sid' }],
  ])('richiede conferma esplicita: %s', async (_label, claims) => {
    const b = await browser();
    const html = await (await b.request(logoutUrl(claims ? await hint(claims) : undefined))).text();
    expect(html).toContain('Vuoi uscire?');
    expect(html).toContain('name="xsrf"');
    expect(html).not.toContain('/static/logout.js');
    expect(await provider.Session.find(b.session.jti)).toBeDefined();
  });

  it('non autorizza redirect non registrati, neppure con hint valido', async () => {
    const b = await browser();
    const response = await b.request(logoutUrl(await hint(), 'https://attacker.example/logout'));
    expect(response.status).toBe(400);
    expect(response.headers.get('content-security-policy')).not.toContain('https://attacker.example');
    expect(await provider.Session.find(b.session.jti)).toBeDefined();
  });

  it('un hint scaduto è valido per il protocollo, ma non salta la conferma', async () => {
    const b = await browser();
    const response = await b.request(logoutUrl(await hint({}, loginTs - 10)));
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain('Vuoi uscire?');
    expect(html).not.toContain('/static/logout.js');
  });

  it('senza redirect RP non salta la conferma', async () => {
    const b = await browser();
    const params = new URLSearchParams({ id_token_hint: await hint() });
    const html = await (await b.request(`/end-session?${params}`)).text();
    expect(html).toContain('Vuoi uscire?');
    expect(html).not.toContain('/static/logout.js');
  });

  it('senza grant del client nella sessione non salta la conferma', async () => {
    const b = await browser();
    b.session.authorizations = {};
    await b.session.save(3600);
    const html = await (await b.request(logoutUrl(await hint()))).text();
    expect(html).toContain('Vuoi uscire?');
    expect(html).not.toContain('/static/logout.js');
  });

  it('rifiuta hint con firma manomessa prima del renderer', async () => {
    const b = await browser();
    const token = await hint();
    const parts = token.split('.');
    parts[2] = `${parts[2]![0] === 'A' ? 'B' : 'A'}${parts[2]!.slice(1)}`;
    const response = await b.request(logoutUrl(parts.join('.')));
    expect(response.status).toBe(400);
    expect(await provider.Session.find(b.session.jti)).toBeDefined();
  });

  it('rifiuta il POST senza xsrf corretto e conserva la sessione', async () => {
    const b = await browser();
    const html = await (await b.request(logoutUrl(await hint()))).text();
    const action = /<form[^>]+action="([^"]+)"/.exec(html)![1]!;
    const response = await b.request(new URL(action).pathname, { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout: 'yes', xsrf: 'wrong' }) });
    expect(response.status).toBe(400);
    expect(await provider.Session.find(b.session.jti)).toBeDefined();
  });

  it('personalizza anche la pagina finale senza redirect RP', async () => {
    const b = await browser();
    const response = await b.request('/end-session/success');
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(html).toContain('Sei uscito');
    expect(html).toContain('logout-page');
    expect(html).not.toContain('<style>');
  });
});
