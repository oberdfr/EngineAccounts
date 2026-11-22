import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, jwtVerify, type JWK } from 'jose';
import { ensureDefaultClients } from '../../src/db/seed.js';
import { HttpClient, TEST_AUDIENCE, createTestUser, setupHarness, type Harness } from '../helpers/harness.js';

/**
 * Device Authorization Grant (RFC 8628) per il client TV `streamingengine-tv`.
 *
 * Il client e' dichiarato in `OIDC_CLIENTS_JSON` e seminato da
 * `ensureDefaultClients`, esattamente come in produzione.
 */

const TV = 'streamingengine-tv';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const SCOPE = 'openid profile email offline_access streaming:catalog streaming:playback streaming:account';
const ANDROID_WEBVIEW = 'https://appassets.androidplatform.net';

const clientsJson = JSON.stringify([{
  clientId: TV,
  clientName: 'TV StreamingEngine',
  audience: TEST_AUDIENCE,
  grantTypes: ['refresh_token', DEVICE_GRANT],
  applicationType: 'native',
  corsOrigins: [ANDROID_WEBVIEW, 'null'],
  scope: SCOPE.split(' '),
}]);

let h: Harness;
let user: { id: string; email: string; password: string };

beforeAll(async () => {
  h = await setupHarness({ overrides: { OIDC_DEVICE_FLOW_ENABLED: 'true', OIDC_CLIENTS_JSON: clientsJson } });
  await ensureDefaultClients(h.db, h.config);
  user = await createTestUser(h, { verified: true });
}, 120_000);

afterAll(async () => { await h?.close(); });

interface DeviceStart { device_code: string; user_code: string; verification_uri: string; verification_uri_complete: string; expires_in: number; interval: number }

async function start(tv = new HttpClient(h.baseUrl), clientId = TV): Promise<{ res: Response; body: DeviceStart & Record<string, string> }> {
  const res = await tv.postForm('/device/auth', { client_id: clientId, scope: SCOPE });
  return { res, body: (await res.json()) as never };
}

const poll = (tv: HttpClient, deviceCode: string) =>
  tv.postForm('/token', { grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: TV });

/** Il telefono apre /device e restituisce il token `xsrf` del form. */
async function openDevicePage(phone: HttpClient): Promise<string> {
  const res = await phone.get('/device');
  expect(res.status).toBe(200);
  const html = await res.text();
  expect(html).toContain('Collega un dispositivo');
  const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1];
  expect(xsrf).toBeTruthy();
  return xsrf!;
}

describe('registrazione e discovery', () => {
  it('annuncia device_authorization_endpoint e il grant device_code', async () => {
    const doc = (await (await new HttpClient(h.baseUrl).get('/.well-known/openid-configuration')).json()) as Record<string, unknown>;
    expect(new URL(String(doc.device_authorization_endpoint)).pathname).toBe('/device/auth');
    expect(doc.grant_types_supported).toContain(DEVICE_GRANT);
  });

  it('il client TV e` pubblico, senza redirect, con CORS esplicito', async () => {
    const client = (await h.store.findClient(TV))!;
    expect(client).toMatchObject({ clientType: 'public', tokenEndpointAuthMethod: 'none', redirectUris: [],
      applicationType: 'native', grantTypes: ['refresh_token', DEVICE_GRANT] });
    expect(client.corsOrigins).toEqual([ANDROID_WEBVIEW, 'null']);
  });
});

describe('device_authorization', () => {
  it('risponde con codice leggibile ABCD-EFGH, URI, scadenza e intervallo', async () => {
    const { res, body } = await start();
    expect(res.status).toBe(200);
    expect(body.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(body.device_code.length).toBeGreaterThan(20);
    expect(new URL(body.verification_uri).pathname).toBe('/device');
    expect(body.verification_uri_complete).toContain(encodeURIComponent(body.user_code));
    expect(body.expires_in).toBeGreaterThan(590);
    expect(body.expires_in).toBeLessThanOrEqual(600);
    expect(body.interval).toBe(5);
  });

  it('client sconosciuto: invalid_client', async () => {
    const { res, body } = await start(new HttpClient(h.baseUrl), 'client-che-non-esiste');
    expect(res.status).toBe(401);
    expect(body.error).toBe('invalid_client');
  });

  it('il client web non puo` usare il device grant: unauthorized_client', async () => {
    const { res, body } = await start(new HttpClient(h.baseUrl), h.client.clientId);
    expect(res.status).toBe(400);
    expect(body.error).toBeTruthy();
  });

  it.each([ANDROID_WEBVIEW, 'null'])('CORS per l\'origine %s', async (origin) => {
    const tv = new HttpClient(h.baseUrl);
    const res = await tv.postForm('/device/auth', { client_id: TV, scope: SCOPE }, { headers: { origin } });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe(origin);
  });

  it('nessun CORS per origini non dichiarate', async () => {
    const res = await new HttpClient(h.baseUrl).postForm('/device/auth', { client_id: TV, scope: SCOPE },
      { headers: { origin: 'https://evil.example' } });
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('`null` non e` ammesso per il client web', async () => {
    const res = await new HttpClient(h.baseUrl).postForm('/token', { grant_type: 'refresh_token', refresh_token: 'x', client_id: h.client.clientId },
      { headers: { origin: 'null' } });
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });
});

describe('flusso completo TV + telefono', () => {
  it('pending -> codice errato -> conferma (con login) -> token con refresh', async () => {
    const tv = new HttpClient(h.baseUrl);
    const { body } = await start(tv);

    // 1. nessuna conferma ancora: authorization_pending
    const pending = await poll(tv, body.device_code);
    expect(pending.status).toBe(400);
    expect(((await pending.json()) as { error: string }).error).toBe('authorization_pending');

    // 2. il telefono inserisce un codice sbagliato
    const phone = new HttpClient(h.baseUrl);
    let xsrf = await openDevicePage(phone);
    const wrong = await phone.postForm('/device', { xsrf, user_code: 'BBBB-BBBB' });
    expect(wrong.status).toBe(200);
    const wrongHtml = await wrong.text();
    expect(wrongHtml).toContain('non è corretto');
    expect(wrongHtml).not.toMatch(/<script(?![^>]*\bsrc=)/);
    xsrf = /name="xsrf" value="([^"]+)"/.exec(wrongHtml)![1]!;

    // 3. codice giusto: pagina di conferma con il nome del dispositivo
    const confirm = await phone.postForm('/device', { xsrf, user_code: body.user_code.toLowerCase().replace('-', '') });
    expect(confirm.status).toBe(200);
    const confirmHtml = await confirm.text();
    expect(confirmHtml).toContain('TV StreamingEngine');
    expect(confirmHtml).toContain(body.user_code);
    expect(confirmHtml).toContain('Conferma');
    expect(confirmHtml).toContain('Annulla');
    xsrf = /name="xsrf" value="([^"]+)"/.exec(confirmHtml)![1]!;

    // La TV e` ancora in attesa.
    expect(((await (await poll(tv, body.device_code)).json()) as { error: string }).error).toBe('authorization_pending');

    // 4. Conferma: utente non loggato -> login normale -> consenso -> successo
    const go = await phone.postForm('/device', { xsrf, user_code: body.user_code, confirm: 'yes' });
    expect(go.status).toBe(303);
    let loc = go.headers.get('location')!;
    let page = '';
    for (let hop = 0; hop < 6 && !page; hop++) {
      const res = await phone.get(loc);
      if (res.status >= 300 && res.status < 400) { loc = res.headers.get('location')!; continue; }
      page = await res.text();
    }
    expect(page).toContain('Accedi per continuare');
    const uid = /\/ui\/interaction\/([^/?#]+)/.exec(loc)![1]!;
    const csrf = /name="_csrf" value="([^"]+)"/.exec(page)![1]!;
    const login = await phone.postForm(`/ui/interaction/${uid}/login`, { _csrf: csrf, email: user.email, password: user.password });
    expect(login.status).toBe(303);

    loc = login.headers.get('location')!;
    let consentHtml = '';
    for (let hop = 0; hop < 6 && !consentHtml; hop++) {
      const res = await phone.get(loc);
      if (res.status >= 300 && res.status < 400) { loc = res.headers.get('location')!; continue; }
      consentHtml = await res.text();
    }
    expect(consentHtml).toContain('Autorizza');
    expect(consentHtml).toContain('TV StreamingEngine');
    const consentUid = /\/interaction\/([^/?#]+)/.exec(loc)![1]!;
    const consentCsrf = /name="_csrf" value="([^"]+)"/.exec(consentHtml)![1]!;
    let res = await phone.postForm(`/ui/interaction/${consentUid}/consent`, { _csrf: consentCsrf, decision: 'allow' });
    let success = '';
    for (let hop = 0; hop < 8 && !success; hop++) {
      if (res.status >= 300 && res.status < 400) { res = await phone.get(res.headers.get('location')!); continue; }
      success = await res.text();
    }
    expect(success).toContain('Dispositivo collegato');

    // 5. la TV riceve access + refresh token
    const tokenRes = await poll(tv, body.device_code);
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string; refresh_token?: string; id_token: string; scope: string };
    expect(tokens.refresh_token, 'offline_access deve produrre un refresh token').toBeTruthy();
    expect(tokens.scope).toContain('streaming:playback');
    const jwks = (await (await tv.get('/jwks')).json()) as { keys: JWK[] };
    const access = await jwtVerify(tokens.access_token, createLocalJWKSet(jwks), { issuer: h.config.issuer, audience: TEST_AUDIENCE });
    expect(access.payload.sub).toBe(user.id);
    expect(access.payload.client_id).toBe(TV);

    // 7. refresh con rotazione
    const refreshed = await tv.postForm('/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: TV });
    expect(refreshed.status, JSON.stringify(await refreshed.clone().json())).toBe(200);
    const next = (await refreshed.json()) as { refresh_token: string };
    expect(next.refresh_token).not.toBe(tokens.refresh_token);

    // 8. Durata scorrevole identica agli altri client (REFRESH_TOKEN_TTL = 90 giorni).
    const row = (await h.db.one<{ ttl: number }>(
      `SELECT EXTRACT(EPOCH FROM (expires_at - now()))::int AS ttl FROM "${h.db.schema}"."oidc_tokens"
         WHERE kind = 'RefreshToken' AND client_id = $1 AND revoked_at IS NULL AND consumed_at IS NULL
         ORDER BY expires_at DESC LIMIT 1`, [TV]))!;
    expect(row.ttl).toBeGreaterThan(h.config.REFRESH_TOKEN_TTL - 120);
    expect(row.ttl).toBeLessThanOrEqual(h.config.REFRESH_TOKEN_TTL);

    // 9. il device code e` monouso; il riuso revoca il grant (RFC 6749 §4.1.2)
    const again = await poll(tv, body.device_code);
    expect(again.status).toBe(400);
    const revoked = await tv.postForm('/token', { grant_type: 'refresh_token', refresh_token: next.refresh_token, client_id: TV });
    expect(revoked.status).toBe(400);
  });

  it('annulla dal telefono: la TV riceve access_denied', async () => {
    const tv = new HttpClient(h.baseUrl);
    const { body } = await start(tv);
    const phone = new HttpClient(h.baseUrl);
    let xsrf = await openDevicePage(phone);
    const confirm = await (await phone.postForm('/device', { xsrf, user_code: body.user_code })).text();
    xsrf = /name="xsrf" value="([^"]+)"/.exec(confirm)![1]!;
    const aborted = await phone.postForm('/device', { xsrf, user_code: body.user_code, abort: 'yes' });
    expect(await aborted.text()).toContain('annullata');
    const res = await poll(tv, body.device_code);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe('access_denied');
  });

  it('codice scaduto: expired_token alla TV e messaggio sul telefono', async () => {
    const tv = new HttpClient(h.baseUrl);
    const { body } = await start(tv);
    await h.db.query(`UPDATE "${h.db.schema}"."oidc_codes" SET expires_at = now() - interval '1 minute', payload = jsonb_set(payload, '{exp}', to_jsonb(floor(extract(epoch from now()))::int - 60)) WHERE user_code = $1`,
      [body.user_code.replace('-', '')]);
    const res = await poll(tv, body.device_code);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe('expired_token');

    const phone = new HttpClient(h.baseUrl);
    const xsrf = await openDevicePage(phone);
    const page = await (await phone.postForm('/device', { xsrf, user_code: body.user_code })).text();
    expect(page).toContain('scaduto');
  });

  it('polling troppo rapido: slow_down', async () => {
    const tv = new HttpClient(h.baseUrl);
    const { body } = await start(tv);
    await poll(tv, body.device_code);
    const res = await poll(tv, body.device_code);
    expect(((await res.json()) as { error: string }).error).toMatch(/^(slow_down|authorization_pending)$/);
  });

  it('GET /device?user_code= mostra il form precompilato, senza script inline', async () => {
    const { body } = await start();
    const res = await new HttpClient(h.baseUrl).get(`/device?user_code=${encodeURIComponent(body.user_code)}`);
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain(`value="${body.user_code}"`);
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)/);
    expect(res.headers.get('content-security-policy')).toContain("script-src 'self'");
  });
});

describe('anti brute force', () => {
  it('limita i tentativi di inserimento codice per IP (429)', async () => {
    const phone = new HttpClient(h.baseUrl);
    const xsrf = await openDevicePage(phone);
    let limited: Response | undefined;
    for (let i = 0; i < 20 && !limited; i++) {
      const res = await phone.postForm('/device', { xsrf, user_code: 'CCCC-CCCC' });
      if (res.status === 429) limited = res;
    }
    expect(limited, 'dopo un numero limitato di tentativi deve rispondere 429').toBeTruthy();
    expect(limited!.headers.get('retry-after')).toBeTruthy();
  });
});
