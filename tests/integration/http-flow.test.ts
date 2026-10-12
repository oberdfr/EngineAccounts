import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, decodeJwt, jwtVerify, type JWK } from 'jose';
import {
  CONF_CLIENT_ID,
  CONF_CLIENT_SECRET,
  HttpClient,
  TEST_AUDIENCE,
  TEST_CLIENT_ID,
  TEST_REDIRECT_URI,
  pkce,
  setupHarness,
  type Harness,
} from '../helpers/harness.js';
import type { InMemoryMailer } from '../../src/services/mailer.js';

/**
 * Flusso OIDC **su HTTP reale**, dalla registrazione al refresh.
 *
 * Diversamente da `oidc-flow.test.ts`, qui l'utente non e' creato dal
 * repository: viene registrato `POST /ui/register`, come farebbe una persona,
 * e la mail di verifica arriva davvero. Poi si segue la catena di redirect
 * esattamente come la seguirebbe il browser, con il jar dei cookie.
 *
 * Il percorso e' quello di un frontend:
 *
 *   POST /ui/register -> GET /auth -> POST /ui/interaction/:uid/login
 *   -> GET /auth/:uid (resume) -> POST /ui/interaction/:uid/consent
 *   -> GET /auth/:uid -> redirect al client
 *   -> POST /token -> GET /userinfo -> POST /token (refresh con rotazione)
 *
 * Ogni passo asserisce stato, `Location` e cookie: un test che passa
 * dimostrando che la catena regge, non che i pezzi esistono.
 */

let h: Harness;

const PASSWORD = 'PasswordLungaCheNonEsiste123!';
let userEmail = '';
let userSub = '';

/** Una risposta e la sua posizione nella catena, per messaggi di errore utili. */
function where(res: Response): string {
  return `${res.status}${res.headers.get('location') ? ` -> ${res.headers.get('location')}` : ''}`;
}

/** Estrae il token di verifica dal testo dell'email inviata all'utente. */
function verificationTokenFrom(html: string, text: string): string {
  const fromLink = /\/ui\/verify-email\?token=([A-Za-z0-9_-]+)/.exec(html ?? '') ?? null;
  if (fromLink?.[1]) return fromLink[1];
  const fromText = /verify-email\?token=([A-Za-z0-9_-]+)/.exec(text ?? '');
  if (fromText?.[1]) return fromText[1];
  throw new Error('token di verifica non trovato nell\'email');
}

/** L'ultima email inviata a quell'indirizzo (il mailer e' in memoria). */
function lastMailTo(email: string): { html?: string; text?: string } {
  const mail = (h.mailer as InMemoryMailer).lastTo(email);
  if (!mail) throw new Error(`nessuna email inviata a ${email}`);
  return mail;
}

beforeAll(async () => {
  h = await setupHarness();
  (h.mailer as InMemoryMailer).clear();
}, 120_000);

afterAll(async () => {
  await h?.close();
});

describe('flusso completo su HTTP (registrazione -> refresh)', () => {
  it('registrazione via POST /ui/register crea l\'utente e manda l\'email', async () => {
    const client = new HttpClient(h.baseUrl);
    userEmail = `http-${Date.now()}@example.test`;

    const page = await client.get('/ui/register');
    expect(page.status, 'la pagina di registrazione deve rispondere').toBe(200);
    const csrf = await client.csrfFrom('/ui/register');
    expect(csrf, 'il form deve avere un token CSRF').toBeTruthy();

    const res = await client.postForm('/ui/register', {
      _csrf: csrf,
      email: userEmail,
      displayName: 'Utente HTTP',
      password: PASSWORD,
    });
    // Risposta neutra: 303 verso `?sent=1` qualunque cosa sia successa
    // (anti-enumerazione). Non dice se l'account e' stato creato.
    expect(res.status, where(res)).toBe(303);
    expect(res.headers.get('location') ?? '').toContain('/ui/register?sent=1');

    // L'utente c'è davvero, e la mail è partita con il link di verifica.
    const user = await h.store.findUserByEmail(userEmail);
    expect(user?.email, 'l\'account deve esistere nel database').toBe(userEmail);
    userSub = user!.id;
    expect(user!.emailVerifiedAt, 'prima della verifica l\'email non e\' verificata').toBeNull();

    // L'email di verifica e' partita con il link: senza, il resto del test
    // non avrebbe niente da cliccare.
    const mail = (h.mailer as InMemoryMailer).lastTo(userEmail);
    expect(mail, 'deve essere partita un\'email di verifica').toBeTruthy();
  });

  it('il link di verifica valorizza email_verified_at', async () => {
    const mail = lastMailTo(userEmail);
    const token = verificationTokenFrom(mail.html ?? '', mail.text ?? '');

    const client = new HttpClient(h.baseUrl);
    const res = await client.get(`/ui/verify-email?token=${encodeURIComponent(token)}`);
    expect(res.status, where(res)).toBe(200);
    expect(await res.text()).toContain('Indirizzo verificato');

    const user = await h.store.findUserById(userSub);
    expect(user?.emailVerifiedAt, 'email_verified_at deve essere valorizzato').not.toBeNull();
  });

  it('il token di verifica e\' monouso', async () => {
    const client = new HttpClient(h.baseUrl);
    const email = `riuso-${Date.now()}@example.test`;
    await h.accounts.register({ email, password: PASSWORD }, { ip: null, userAgent: null });
    const mail = lastMailTo(email);
    const token = verificationTokenFrom(mail.html ?? '', mail.text ?? '');

    const first = await client.get(`/ui/verify-email?token=${encodeURIComponent(token)}`);
    expect(first.status, 'primo uso').toBe(200);
    const second = await client.get(`/ui/verify-email?token=${encodeURIComponent(token)}`);
    expect(second.status, 'il token verificato non e\' riusabile').toBe(400);
  });

  it('login -> interazione -> consenso -> code -> token -> userinfo -> refresh', async () => {
    const client = new HttpClient(h.baseUrl);
    const pair = pkce('S256');
    const state = 'st-http-e2e';
    const nonce = 'nonce-http-e2e';

    /* --- 1. GET /auth: il provider non conosce l'utente, manda alla UI --- */
    const authUrl =
      `/auth?response_type=code` +
      `&client_id=${encodeURIComponent(TEST_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(TEST_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent('openid profile email offline_access streaming:account')}` +
      `&state=${encodeURIComponent(state)}` +
      `&nonce=${encodeURIComponent(nonce)}` +
      // Senza `prompt=consent` la libreria scarta `offline_access`: senza questo
      // parametro il refresh token non arriva (OIDC Core §11).
      `&prompt=consent` +
      `&code_challenge=${encodeURIComponent(pair.challenge)}` +
      `&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(TEST_AUDIENCE)}`;

    const start = await client.get(authUrl);
    expect(start.status, where(start)).toBe(303);
    const toUi = start.headers.get('location') ?? '';
    expect(toUi, 'il provider deve mandare alla UI di interazione').toContain('/ui/interaction/');

    /* --- 2. la pagina di interazione e' la nostra UI, servita dallo stesso origin --- */
    const interaction = await client.get(toUi);
    expect(interaction.status, where(interaction)).toBe(200);
    const loginHtml = await interaction.text();
    expect(loginHtml).toContain('Accedi per continuare');
    const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1] ?? '';
    expect(uid, 'la pagina deve contenere il form di login').toBeTruthy();
    const loginCsrf = /name="_csrf" value="([^"]+)"/.exec(loginHtml)?.[1] ?? '';
    expect(loginCsrf, 'il form di login deve avere un token CSRF').toBeTruthy();

    /* --- 3. POST login --- */
    const login = await client.postForm(`/ui/interaction/${uid}/login`, {
      _csrf: loginCsrf,
      email: userEmail,
      password: PASSWORD,
    });
    expect(login.status, where(login)).toBe(303);
    // Il cookie di sessione deve arrivare al client: e' quello che rende
    // possibile il passo di consenso.
    expect(login.headers.get('set-cookie') ?? '').toContain('ea_sid=');
    const afterLogin = login.headers.get('location') ?? '';
    expect(afterLogin, 'dopo il login si torna al provider').toContain('/auth/');

    /* --- 4. il resume del provider rimanda al prompt di consenso --- */
    const resumed = await client.get(afterLogin);
    expect([200, 303], where(resumed)).toContain(resumed.status);
    let url = resumed.headers.get('location')
      ? client.resolve(resumed.headers.get('location')!)
      : client.resolve(afterLogin);
    const consentPage = await client.get(url);
    expect(consentPage.status, where(consentPage)).toBe(200);
    const consentHtml = await consentPage.text();
    expect(consentHtml).toContain('Autorizza');
    const consentUid = /\/ui\/interaction\/([^/?#]+)/.exec(url)?.[1] ?? '';
    const consentCsrf = /name="_csrf" value="([^"]+)"/.exec(consentHtml)?.[1] ?? '';
    expect(consentUid && consentCsrf, 'il form di consenso deve essere pronto').toBeTruthy();

    /* --- 5. POST consenso: il provider rivaluta e rimanda il code --- */
    const consent = await client.postForm(`/ui/interaction/${consentUid}/consent`, {
      _csrf: consentCsrf,
      decision: 'allow',
    });
    expect(consent.status, where(consent)).toBe(303);
    let next = consent.headers.get('location');
    expect(next, 'il consenso deve far ripartire il provider').toBeTruthy();

    // La catena che porta al `redirect_uri`: uno o piu' hop sul path del
    // provider, poi il redirect al client.
    let code = '';
    let hops = 0;
    let cursor = client.resolve(next!);
    while (hops++ < 8) {
      const res = await client.get(cursor);
      const location = res.headers.get('location');
      if (!location) {
        throw new Error(`catena interrotta su ${cursor}: ${where(res)}`);
      }
      cursor = client.resolve(location);
      const parsed = new URL(cursor);
      if (parsed.origin + parsed.pathname === TEST_REDIRECT_URI) {
        expect(parsed.searchParams.get('state'), 'lo state torna al client').toBe(state);
        code = parsed.searchParams.get('code') ?? '';
        break;
      }
    }
    expect(code, `il flusso deve arrivare a un code (hop: ${hops})`).toBeTruthy();

    /* --- 6. POST /token: code + verifier --- */
    const tokenRes = await client.postForm('/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: TEST_REDIRECT_URI,
      client_id: TEST_CLIENT_ID,
      code_verifier: pair.verifier,
    });
    expect(tokenRes.status, where(tokenRes)).toBe(200);
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      id_token: string;
      refresh_token?: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBe(h.config.ACCESS_TOKEN_TTL);
    expect(tokens.refresh_token, 'offline_access deve abilitare il refresh token').toBeTruthy();
    expect(tokens.scope).toContain('streaming:account');

    // Token firmati, con l'audience del proxy (contratto §4 e §5).
    const jwks = (await (await client.get('/.well-known/jwks.json')).json()) as { keys: JWK[] };
    const verify = createLocalJWKSet(jwks);
    const access = await jwtVerify(tokens.access_token, verify, {
      issuer: h.config.issuer,
      audience: TEST_AUDIENCE,
      algorithms: ['EdDSA', 'RS256'],
      requiredClaims: ['sub', 'iat', 'exp', 'jti'],
    });
    expect(access.payload.sub, 'il sub e\' quello dell\'utente appena registrato').toBe(userSub);
    expect(access.payload.aud).toBe(TEST_AUDIENCE);
    expect(access.payload.client_id).toBe(TEST_CLIENT_ID);
    // L'id token non porta lo scope (contratto §5).
    expect(decodeJwt(tokens.id_token).scope).toBeUndefined();

    /* --- 7. GET /userinfo con il token --- */
    const userinfo = await client.request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.status, where(userinfo)).toBe(200);
    const profile = (await userinfo.json()) as Record<string, unknown>;
    expect(profile.sub).toBe(userSub);
    expect(profile.email).toBe(userEmail);
    expect(profile.email_verified).toBe(true);
    expect(profile.name).toBeTruthy();

    /* --- 8. refresh con rotazione --- */
    const refresh = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
      client_id: TEST_CLIENT_ID,
    });
    expect(refresh.status, where(refresh)).toBe(200);
    const rotated = (await refresh.json()) as { access_token: string; refresh_token: string };
    expect(rotated.refresh_token, 'il refresh token deve cambiare a ogni uso').not.toBe(tokens.refresh_token);

    const userinfo2 = await client.request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${rotated.access_token}` },
    });
    expect(userinfo2.status, 'il nuovo access token vale').toBe(200);
    expect(((await userinfo2.json()) as Record<string, unknown>).sub).toBe(userSub);

    // Il riuso del vecchio refresh token e' il caso che chiama la revoca di
    // famiglia: lo qui verifichiamo solo che venga rifiutato, la famiglia e'
    // coperta dalla suite di sicurezza.
    const replay = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
      client_id: TEST_CLIENT_ID,
    });
    expect(replay.status, 'il riuso deve essere rifiutato').toBeGreaterThanOrEqual(400);
  }, 60_000);

  it('client confidenziale: stesso percorso HTTP con client_secret_basic', async () => {
    const client = new HttpClient(h.baseUrl);
    const pair = pkce('S256');
    const redirectUri = 'https://app.example.test/cb';

    const start = await client.get(
      `/auth?response_type=code` +
        `&client_id=${encodeURIComponent(CONF_CLIENT_ID)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&scope=${encodeURIComponent('openid profile email')}` +
        `&state=st-conf-http` +
        `&nonce=n-conf-http` +
        `&code_challenge=${encodeURIComponent(pair.challenge)}` +
        `&code_challenge_method=S256` +
        `&resource=${encodeURIComponent(TEST_AUDIENCE)}`,
    );
    expect(start.status, where(start)).toBe(303);
    const toUi = start.headers.get('location') ?? '';
    expect(toUi).toContain('/ui/interaction/');

    const loginHtml = await (await client.get(toUi)).text();
    const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1] ?? '';
    const loginCsrf = /name="_csrf" value="([^"]+)"/.exec(loginHtml)?.[1] ?? '';
    const login = await client.postForm(`/ui/interaction/${uid}/login`, {
      _csrf: loginCsrf,
      email: userEmail,
      password: PASSWORD,
    });
    expect(login.status, where(login)).toBe(303);

    let url = login.headers.get('location')!;
    const resumed = await client.get(url);
    url = resumed.headers.get('location') ?? url;
    const consentHtml = await (await client.get(client.resolve(url))).text();
    const consentUid = /\/ui\/interaction\/([^/?#]+)/.exec(url)?.[1] ?? '';
    const consentCsrf = /name="_csrf" value="([^"]+)"/.exec(consentHtml)?.[1] ?? '';
    const consent = await client.postForm(`/ui/interaction/${consentUid}/consent`, {
      _csrf: consentCsrf,
      decision: 'allow',
    });
    expect(consent.status, where(consent)).toBe(303);

    let code = '';
    let cursor = client.resolve(consent.headers.get('location')!);
    for (let hop = 0; hop < 8 && !code; hop++) {
      const res = await client.get(cursor);
      const location = res.headers.get('location');
      expect(location, `catena interrotta su ${cursor}`).toBeTruthy();
      cursor = client.resolve(location!);
      const parsed = new URL(cursor);
      if (parsed.origin + parsed.pathname === redirectUri) code = parsed.searchParams.get('code') ?? '';
    }
    expect(code, 'il client confidenziale deve arrivare a un code').toBeTruthy();

    const tokenRes = await client.postForm(
      '/token',
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: pair.verifier,
      },
      {
        headers: {
          authorization:
            'Basic ' + Buffer.from(`${CONF_CLIENT_ID}:${CONF_CLIENT_SECRET}`).toString('base64'),
        },
      },
    );
    expect(tokenRes.status, where(tokenRes)).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string };
    expect(decodeJwt(tokens.access_token).client_id).toBe(CONF_CLIENT_ID);
  }, 60_000);
});