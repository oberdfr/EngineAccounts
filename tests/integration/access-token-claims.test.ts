import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, jwtVerify, type JWK } from 'jose';
import {
  HttpClient,
  TEST_AUDIENCE,
  TEST_CLIENT_ID,
  TEST_REDIRECT_URI,
  createTestUser,
  pkce,
  setupHarness,
  type Harness,
} from '../helpers/harness.js';

/**
 * Claim `email` / `email_verified` **nell'access token**.
 *
 * Il contratto (`engine-accounts.md` §5) dichiara `email` e `email_verified` in
 * *entrambi* i token, se lo scope `email` e' concesso. Fin qui la libreria li
 * metteva solo nell'id token e in `/userinfo`: il proxy, che legge il claim
 * dall'access token perche' e' l'unico token che possiede (il refresh non e'
 * firmato, D1), rispondeva `/v1/me` con `email: ""`.
 *
 * Il test verifica il **contenuto del token emesso**, non la risposta di un
 * endpoint: un endpoint puo' rispondere 200 e mascherare un claim assente,
 * mentre qui si legge il JWT firmato con la JWKS, come fa il proxy.
 *
 * Copre anche la parte di sicurezza: il claim deve comparire **solo** con lo
 * scope `email`, e un account senza indirizzo utilizzabile non deve vedersi
 * attribuire una stringa inventata.
 */

let h: Harness;
let user: { id: string; email: string; password: string };
let unverified: { id: string; email: string; password: string };

interface Tokens {
  access_token: string;
  id_token: string;
  refresh_token?: string;
  scope: string;
}

beforeAll(async () => {
  h = await setupHarness();
  user = await createTestUser(h, { verified: true });
  unverified = await createTestUser(h, { verified: false });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

/** Login completo (UI + consenso) e scambio del code: restituisce i token. */
async function login(options: { scope: string; as?: string }): Promise<Tokens> {
  const client = new HttpClient(h.baseUrl);
  const pair = pkce('S256');
  const email = options.as ?? user.email;
  const password = options.as ? unverified.password : user.password;

  const start = await client.get(
    `/auth?response_type=code&client_id=${encodeURIComponent(TEST_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(TEST_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(options.scope)}` +
      `&state=st-claims&nonce=nonce-claims&prompt=consent` +
      `&code_challenge=${encodeURIComponent(pair.challenge)}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(TEST_AUDIENCE)}`,
  );
  const toUi = start.headers.get('location') ?? '';
  expect(toUi, 'il provider deve redirigere alla UI di interazione').toContain('/ui/interaction/');

  const loginHtml = await (await client.get(toUi)).text();
  const csrf = /name="_csrf" value="([^"]+)"/.exec(loginHtml)?.[1];
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1];
  expect(csrf && uid, 'il form di login deve essere pronto').toBeTruthy();

  const logged = await client.postForm(`/ui/interaction/${uid}/login`, {
    _csrf: csrf!,
    email,
    password,
  });
  expect(logged.status).toBe(303);

  // Il resume del provider rimanda al prompt di consenso.
  let cursor = client.resolve(logged.headers.get('location') ?? '');
  let consentHtml = '';
  let consentUid = '';
  let consentCsrf = '';
  for (let hop = 0; hop < 5; hop++) {
    const res = await client.get(cursor);
    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      cursor = client.resolve(location);
      continue;
    }
    consentHtml = await res.text();
    consentUid = /\/ui\/interaction\/([^/?#]+)/.exec(cursor)?.[1] ?? '';
    consentCsrf = /name="_csrf" value="([^"]+)"/.exec(consentHtml)?.[1] ?? '';
    break;
  }
  expect(consentHtml, 'il prompt di consenso deve comparire').toContain('Autorizza');
  expect(consentUid && consentCsrf, 'il form di consenso deve essere pronto').toBeTruthy();

  const submitted = await client.postForm(`/ui/interaction/${consentUid}/consent`, {
    _csrf: consentCsrf,
    decision: 'allow',
  });

  // La catena che porta al `redirect_uri`: il provider rivaluta la richiesta e
  // solo poi consegna il code, quindi il redirect va seguito hop per hop.
  let next = submitted.headers.get('location');
  expect(next, 'il consenso deve far ripartire il provider').toBeTruthy();
  let code = '';
  let hops = 0;
  while (hops++ < 8) {
    const parsed = new URL(client.resolve(next!));
    if (parsed.origin + parsed.pathname === TEST_REDIRECT_URI) {
      code = parsed.searchParams.get('code') ?? '';
      break;
    }
    const res = await client.get(parsed.toString());
    next = res.headers.get('location');
    if (!next) throw new Error(`catena interrotta: nessun redirect da ${parsed}`);
  }
  expect(code, 'il flusso deve arrivare a un code').toBeTruthy();

  const tokenRes = await client.postForm('/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: TEST_REDIRECT_URI,
    client_id: TEST_CLIENT_ID,
    code_verifier: pair.verifier,
  });
  expect(tokenRes.status).toBe(200);
  return (await tokenRes.json()) as Tokens;
}

/** Payload dell'access token, verificato con la JWKS come fa il proxy. */
async function accessPayload(token: string): Promise<Record<string, unknown>> {
  const jwks = (await (await new HttpClient(h.baseUrl).get('/.well-known/jwks.json')).json()) as {
    keys: JWK[];
  };
  const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), {
    issuer: h.config.issuer,
    audience: TEST_AUDIENCE,
    algorithms: ['EdDSA', 'RS256'],
    requiredClaims: ['sub', 'iat', 'exp', 'jti'],
  });
  return payload as Record<string, unknown>;
}

describe('claim email nell\'access token (contratto §5)', () => {
  it('il token emesso con scope `email` contiene davvero `email` ed `email_verified`', async () => {
    const tokens = await login({
      scope: 'openid profile email offline_access streaming:account',
    });
    const access = await accessPayload(tokens.access_token);

    // Il contratto §5: `email` e `email_verified` nell'access token se lo scope
    // c'e'. Prima della correzione il claim era ASSENTE dal token.
    expect(String(access.scope)).toContain('email');
    expect(access.email, "l'access token deve portare `email` (contratto §5)").toBe(user.email);
    expect(access.email_verified).toBe(true);
    expect(access.sub).toBe(user.id);
  }, 60_000);

  it('`email` e `email_verified` arrivano anche con il refresh (rotazione)', async () => {
    const tokens = await login({
      scope: 'openid profile email offline_access streaming:account',
    });
    expect(tokens.refresh_token).toBeTruthy();

    const res = await new HttpClient(h.baseUrl).postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
      client_id: TEST_CLIENT_ID,
    });
    expect(res.status).toBe(200);
    const refreshed = (await res.json()) as { access_token: string; id_token: string };
    const access = await accessPayload(refreshed.access_token);
    expect(access.email).toBe(user.email);
    expect(access.email_verified).toBe(true);
    // Lo `scope` del token rinnovato non puo' perdere `email`: un token che
    // cambia significato a ogni rinnovo (ecco il difetto) non e' accettabile.
    expect(String(access.scope)).toContain('email');
    // E il proxy continua a poterlo usare: `streaming:account` resta dentro.
    expect(String(access.scope)).toContain('streaming:account');
  }, 60_000);

  it('l\'access token e `/userinfo` dicono la stessa email', async () => {
    const tokens = await login({ scope: 'openid profile email streaming:account' });
    const access = await accessPayload(tokens.access_token);

    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(res.status).toBe(200);
    const profile = (await res.json()) as Record<string, unknown>;

    // Divergenza qui = il difetto: due sorgenti diverse per lo stesso dato.
    expect(profile.email).toBe(access.email);
    expect(profile.email).toBe(user.email);
  }, 60_000);

  it('senza scope `email` il claim NON compare: nessun dato personale nel token', async () => {
    const tokens = await login({ scope: 'openid profile streaming:account' });
    const access = await accessPayload(tokens.access_token);

    expect(String(access.scope)).not.toContain('email');
    // Il proxy dichiara `email: ""` quando il claim manca: non deve mai
    // arrivare una stringa inventata al posto di un indirizzo.
    expect(access.email).toBeUndefined();
    expect(access.email_verified).toBeUndefined();

    // E `/userinfo` con lo stesso token non inventa niente.
    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(res.status).toBe(200);
    const profile = (await res.json()) as Record<string, unknown>;
    expect(profile.email).toBeUndefined();
  }, 60_000);

  it('`email_verified` segue lo stato reale dell\'account', async () => {
    const tokens = await login({
      scope: 'openid profile email streaming:account',
      as: unverified.email,
    });
    const access = await accessPayload(tokens.access_token);

    expect(access.email).toBe(unverified.email);
    // Non verificato: il claim c'e' ma vale `false`, non viene promosso a true.
    expect(access.email_verified).toBe(false);
  }, 60_000);

  it('l\'access token NON porta i claim che il contratto riserva all\'id token', async () => {
    const tokens = await login({ scope: 'openid profile email streaming:account' });
    const access = await accessPayload(tokens.access_token);

    // Contratto §5: `name` e' "id" (solo id token). Nell'access token non deve
    // comparire: e' un dato di profilo che nessun resource server chiede.
    expect(access.name).toBeUndefined();
    expect(access.preferred_username).toBeUndefined();
    // `sub` non e' mai l'email (contratto §5).
    expect(access.sub).not.toBe(user.email);
  }, 60_000);
});