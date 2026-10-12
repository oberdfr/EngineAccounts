import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { exportJWK, generateKeyPair } from 'jose';
import { Provider, type AdapterPayload } from 'oidc-provider';
import { logoutSource, postLogoutSuccessSource } from '../../src/oidc/logout.js';
import { CSP } from '../../src/security/headers.js';

// Fixture esclusivamente locale: nessun DB, account reale, token su disco o log.
// Porte diverse da quelle dell'app; cookie non firmati solo in questo processo.
const data = new Map<string, AdapterPayload>();
class Adapter {
  constructor(private readonly model: string) {}
  async upsert(id: string, payload: AdapterPayload) { data.set(`${this.model}:${id}`, payload); }
  async find(id: string) { return data.get(`${this.model}:${id}`); }
  async destroy(id: string) { data.delete(`${this.model}:${id}`); }
  async findByUid() { return undefined; }
  async findByUserCode() { return undefined; }
  async consume() {}
  async revokeByGrantId() {}
}
const issuer = 'http://127.0.0.1:18080';
const rp = 'http://127.0.0.1:15173/signed-out';
const clientId = 'browser-logout-fixture';
const { privateKey } = await generateKeyPair('EdDSA', { extractable: true });
const provider = new Provider(issuer, {
  adapter: Adapter,
  jwks: { keys: [{ ...await exportJWK(privateKey), kid: 'fixture-key', alg: 'EdDSA', use: 'sig' }] },
  clients: [{ client_id: clientId, token_endpoint_auth_method: 'none',
    redirect_uris: ['http://127.0.0.1:15173/callback'], post_logout_redirect_uris: [rp],
    id_token_signed_response_alg: 'EdDSA' }],
  cookies: { names: { session: 'logout_browser_fixture' }, keys: ['fixture-only-key'],
    long: { signed: false, secure: false } },
  claims: { openid: ['sub', 'auth_time'] },
  ttl: { Session: 3600, IdToken: 300 },
  routes: { end_session: '/end-session' },
  features: { devInteractions: { enabled: false },
    rpInitiatedLogout: { enabled: true, logoutSource, postLogoutSuccessSource } },
  // Come il servizio reale: niente stile inline nel renderer di errore.
  renderError(ctx) {
    ctx.type = 'html';
    ctx.body = '<!doctype html><html lang="it"><title>Richiesta rifiutata</title><h1>Richiesta rifiutata</h1></html>';
  },
});
let lastSessionId: string;
let confirmCount = 0;
const callback = provider.callback();
const server = createServer(async (request, response) => {
  response.setHeader('Content-Security-Policy', CSP);
  const url = new URL(request.url!, issuer);
  if (url.pathname === '/start') {
    confirmCount = 0;
    const loginTs = Math.floor(Date.now() / 1000);
    const session = new provider.Session();
    session.accountId = 'synthetic-browser-subject';
    session.loginTs = loginTs;
    session.authorizations = { [clientId]: { grantId: 'synthetic-browser-grant' } };
    await session.save(3600);
    lastSessionId = session.jti;
    const client = (await provider.Client.find(clientId))!;
    const token = new provider.IdToken({ sub: session.accountId, auth_time: loginTs }, { client });
    Object.assign(token, { scope: 'openid' });
    const params = new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: rp, state: 'browser-logout-state' });
    if (url.searchParams.get('mode') !== 'manual') params.set('id_token_hint', await token.issue({ use: 'idtoken' }));
    if (url.searchParams.get('mode') === 'unsafe') params.set('post_logout_redirect_uri', 'http://127.0.0.1:15174/not-registered');
    response.setHeader('Set-Cookie', `${provider.cookieName('session')}=${session.jti}; Path=/; HttpOnly; SameSite=Lax`);
    response.writeHead(303, { Location: `/end-session?${params}` }).end();
    return;
  }
  if (url.pathname === '/test-result') {
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ confirmCount, sessionExists: !!await provider.Session.find(lastSessionId) }));
    return;
  }
  if (url.pathname === '/static/logout.js' || url.pathname === '/static/app.css') {
    response.setHeader('Content-Type', url.pathname.endsWith('.js') ? 'application/javascript' : 'text/css');
    response.end(await readFile(new URL(`../../src/ui${url.pathname}`, import.meta.url)));
    return;
  }
  if (url.pathname === '/end-session/confirm') confirmCount += 1;
  callback(request, response);
});
const rpServer = createServer((_request, response) => {
  response.setHeader('Content-Type', 'text/html');
  response.end('<!doctype html><html lang="it"><title>RP fixture</title><h1>Uscita completata</h1></html>');
});
await Promise.all([
  new Promise<void>((resolve) => server.listen(18080, '127.0.0.1', resolve)),
  new Promise<void>((resolve) => rpServer.listen(15173, '127.0.0.1', resolve)),
]);
console.log('Fixture logout browser pronta su loopback (18080, 15173).');
// Arresto automatico: il server non rimane attivo dopo la verifica.
setTimeout(() => { server.close(); rpServer.close(); }, 120_000).unref();
