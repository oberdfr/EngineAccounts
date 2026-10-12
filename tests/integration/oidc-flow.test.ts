import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, decodeJwt, jwtVerify, type JWK } from 'jose';
import {
  CONF_CLIENT_ID,
  CONF_CLIENT_SECRET,
  HttpClient,
  TEST_AUDIENCE,
  TEST_CLIENT_ID,
  TEST_REDIRECT_URI,
  createTestUser,
  pkce,
  registerTestClientViaCli,
  setupHarness,
  testEnv,
  type Harness,
} from '../helpers/harness.js';

/**
 * Flusso completo Authorization Code + PKCE, end to end.
 *
 * Il client di test e' registrato **dalla CLI in un processo separato**
 * (`engine-accounts client add`, vedi `setupHarness`): quello che segue prova
 * il percorso che un operatore seguirebbe davvero, non una ricostruzione
 * in-process.
 *
 * Sequenza provata:
 *   discovery -> authorize (UI di login nostra) -> consenso -> token
 *   -> userinfo -> refresh con rotazione.
 */

let h: Harness;
let user: { id: string; email: string; password: string };

interface AuthResult {
  code: string;
  state: string;
  client: HttpClient;
}

/**
 * Segue i redirect finche' non si arriva alla pagina di consenso.
 *
 * Il provider, dopo il login, risponde con un 303 verso il proprio endpoint di
 * resume (`/auth/:uid`) che a sua volta rimanda alla UI di interazione con il
 * prompt `consent`. Il test attraversa la catena esattamente come farebbe un
 * browser.
 */
async function followToConsent(
  client: HttpClient,
  start: string,
): Promise<{ html: string; csrf: string; uid: string; location: string }> {
  let url = start;
  for (let hop = 0; hop < 5; hop++) {
    const res = await client.get(url);
    const location = res.headers.get('location');
    const body = await res.text();
    if (res.status >= 300 && res.status < 400 && location) {
      url = location;
      continue;
    }
    const csrf = /name="_csrf" value="([^"]+)"/.exec(body)?.[1];
    const uid = /\/ui\/interaction\/([^/?#]+)/.exec(url)?.[1] ?? /\/interaction\/([^/?#]+)/.exec(url)?.[1];
    if (csrf && uid) return { html: body, csrf, uid, location: url };
    throw new Error(`flusso interazione interrotto su ${url} (status ${res.status}): ${body.slice(0, 200)}`);
  }
  throw new Error(`troppi redirect a partire da ${start}`);
}

/**
 * Segue la catena di redirect fino al `redirect_uri` del client ed estrae i
 * parametri della risposta (code, state, eventuale errore).
 *
 * Dopo il consenso `oidc-provider` **non** emette il code direttamente: rimanda
 * al proprio endpoint di autorizzazione, rivaluta la richiesta (i prompt sono
 * ormai soddisfatti) e solo allora consegna il code al client. E' il
 * comportamento atteso della libreria, non un errore: il browser segue la
 * catena, e il test deve fare lo stesso invece di accettare solo un 303.
 */
async function followToClient(
  client: HttpClient,
  first: Response,
  redirectUri: string,
  maxHops = 8,
): Promise<URL> {
  let res = first;
  let url = '';
  for (let hop = 0; hop < maxHops; hop++) {
    const location = res.headers.get('location');
    if (res.status < 300 || res.status >= 400 || !location) {
      throw new Error(
        `catena interrotta (status ${res.status}, location ${location ?? 'nessuna'}): ` +
          `${(await res.text()).slice(0, 300)}`,
      );
    }
    url = client.resolve(location);
    const target = new URL(url);
    if (target.origin + target.pathname === redirectUri) return target;
    res = await client.get(url);
  }
  throw new Error(`troppi redirect verso ${redirectUri}: ultimo hop ${url}`);
}

beforeAll(async () => {
  h = await setupHarness();
  user = await createTestUser(h, { verified: true });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

describe('registrazione client via CLI', () => {
  it('il client di test e\' stato creato dalla CLI, non a mano', () => {
    expect(h.client.clientId).toBe(TEST_CLIENT_ID);
    expect(h.client.clientType).toBe('public');
    expect(h.client.redirectUris).toEqual([TEST_REDIRECT_URI]);
    expect(h.client.audience).toBe(TEST_AUDIENCE);
    expect(h.client.tokenEndpointAuthMethod).toBe('none');
    // Nessun secret per un client pubblico.
    expect(h.client.clientSecretHash).toBeNull();
  });

  it('la CLI registra anche un client confidenziale con secret hashato', async () => {
    const result = registerTestClientViaCli(testEnv(), [
      'client',
      'add',
      'cli-confidential-demo',
      '--type',
      'confidential',
      '--redirect-uri',
      'https://app.example.test/cb',
      '--audience',
      TEST_AUDIENCE,
      '--scope',
      'openid,profile',
    ]);
    expect(result.status, result.stdout).toBe(0);
    // Il secret in chiaro viene mostrato una volta sola e non e' nel DB.
    expect(result.stdout).toContain('CLIENT_SECRET');
    const row = await h.db.one<{ client_secret_hash: string | null }>(
      `SELECT client_secret_hash FROM "engine_accounts_test"."clients" WHERE client_id = 'cli-confidential-demo'`,
    );
    return expect(row?.client_secret_hash ?? '').toMatch(/^\$argon2id\$/);
  });
});

describe('discovery', () => {
  it('annuncia issuer, endpoint e algoritmi del contratto', async () => {
    const client = new HttpClient(h.baseUrl);
    const res = await client.get('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    const doc = (await res.json()) as Record<string, unknown>;

    // L'issuer e' il valore configurato (e' quello che il proxy valida in `iss`).
    expect(doc.issuer).toBe(h.config.issuer);
    // I path sono quelli del contratto; l'host segue l'Host della richiesta.
    const path = (value: unknown) => new URL(String(value)).pathname;
    expect(path(doc.authorization_endpoint)).toBe('/auth');
    expect(path(doc.token_endpoint)).toBe('/token');
    expect(path(doc.userinfo_endpoint)).toBe('/userinfo');
    expect(path(doc.introspection_endpoint)).toBe('/introspect');
    expect(path(doc.revocation_endpoint)).toBe('/revoke');
    expect(path(doc.end_session_endpoint)).toBe('/end-session');
    expect(path(doc.jwks_uri)).toBe('/jwks');
    // Nessun implicit, nessun `none`.
    expect(doc.response_types_supported).toEqual(['code']);
    expect(doc.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    // Solo S256: `plain` non e' neppure annunciato.
    expect(doc.code_challenge_methods_supported).toEqual(['S256']);
    const algs = doc.id_token_signing_alg_values_supported as string[];
    expect(algs.every((alg) => alg === 'EdDSA' || alg === 'RS256')).toBe(true);
    expect(algs).not.toContain('none');
    expect(algs.some((alg) => alg.startsWith('HS'))).toBe(false);
  });

  it('`/.well-known/jwks.json` e\' lo stesso contenuto di `/jwks`, con kid', async () => {
    const client = new HttpClient(h.baseUrl);
    const [native, alias] = await Promise.all([
      client.get('/jwks').then((r) => r.json() as Promise<{ keys: JWK[] }>),
      client.get('/.well-known/jwks.json').then((r) => r.json() as Promise<{ keys: JWK[] }>),
    ]);
    expect(alias.keys.map((k) => k.kid)).toEqual(native.keys.map((k) => k.kid));
    expect(native.keys.length).toBeGreaterThan(0);
    for (const key of native.keys) {
      expect(key.kid, 'ogni chiave deve avere un kid').toBeTruthy();
      // Nessuna chiave privata pubblicata: e' il errore piu' grave possibile qui.
      expect(key.d).toBeUndefined();
    }
  });
});

describe('Authorization Code + PKCE end to end', () => {
  it('discovery -> authorize -> token -> userinfo -> refresh con rotazione', async () => {
    const client = new HttpClient(h.baseUrl);

    // 1. discovery (gia' verificato sopra, qui si parte dal token endpoint)
    const discovery = (await (await client.get('/.well-known/openid-configuration')).json()) as {
      token_endpoint: string;
    };
    expect(discovery.token_endpoint).toBeTruthy();

    const pair = pkce('S256');
    const nonce = 'nonce-e2e';

    // 2. authorize con la UI di login (nostra)
    const state = 'st-e2e';
    const auth = await authorizeWithNonce({
      client,
      nonce,
      state,
      pair,
      scope: 'openid profile email offline_access streaming:account',
    });
    const code = auth.code;

    // 5. token: scambio code + verifier
    const tokenRes = await client.postForm('/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: TEST_REDIRECT_URI,
      client_id: TEST_CLIENT_ID,
      code_verifier: pair.verifier,
    });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      id_token: string;
      refresh_token?: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    // RFC 6749 §7.1: il valore di `token_type` e' case-insensitive
    // (`oidc-provider` risponde `bearer`).
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBe(h.config.ACCESS_TOKEN_TTL);
    expect(tokens.refresh_token, 'offline_access deve abilitare il refresh token').toBeTruthy();

    // 6. verifica locale dei token con la JWKS (come fa' il proxy, D1)
    const jwks = (await (await client.get('/.well-known/jwks.json')).json()) as { keys: JWK[] };
    // Come fa il proxy (D1): chiavi locali dalla JWKS, nessuna chiamata al provider.
    const publicKeys = createLocalJWKSet(jwks as { keys: JWK[] });

    const header = JSON.parse(
      Buffer.from(tokens.access_token.split('.')[0]!, 'base64url').toString('utf8'),
    ) as { alg: string; kid?: string };
    expect(['EdDSA', 'RS256']).toContain(header.alg);
    expect(header.alg).not.toBe('none');
    expect(header.alg.startsWith('HS')).toBe(false);
    expect(header.kid, 'il token firmato deve avere un kid').toBeTruthy();

    const access = await jwtVerify(tokens.access_token, publicKeys, {
      issuer: h.config.issuer,
      audience: TEST_AUDIENCE,
      algorithms: ['EdDSA', 'RS256'],
      requiredClaims: ['sub', 'iat', 'exp', 'jti'],
    });
    // Contratto 5: sub stabile e opaco, aud = audience del proxy.
    expect(access.payload.sub).toBe(user.id);
    expect(access.payload.aud).toBe(TEST_AUDIENCE);
    expect(access.payload.client_id).toBe(TEST_CLIENT_ID);
    expect(String(access.payload.scope)).toContain('streaming:account');
    expect(access.payload.exp! - access.payload.iat!).toBe(h.config.ACCESS_TOKEN_TTL);

    const idToken = await jwtVerify(tokens.id_token, publicKeys, {
      issuer: h.config.issuer,
      audience: TEST_CLIENT_ID,
      algorithms: ['EdDSA', 'RS256'],
    });
    expect(idToken.payload.sub).toBe(user.id);
    expect(idToken.payload.nonce).toBe(nonce);
    expect(idToken.payload.email).toBe(user.email);
    expect(idToken.payload.email_verified).toBe(true);
    expect(idToken.payload.amr, 'il contratto richiede amr con i metodi di autenticazione').toContain('pwd');
    // L'id token NON porta lo scope (contratto 5).
    expect(idToken.payload.scope).toBeUndefined();

    // 7. userinfo
    const userinfo = await client.request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.status).toBe(200);
    const profile = (await userinfo.json()) as Record<string, unknown>;
    expect(profile.sub).toBe(user.id);
    expect(profile.email).toBe(user.email);
    expect(profile.name).toBeTruthy();

    // 8. refresh con rotazione: il nuovo refresh token deve essere diverso
    const refreshRes = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
      client_id: TEST_CLIENT_ID,
    });
    expect(refreshRes.status).toBe(200);
    const refreshed = (await refreshRes.json()) as {
      access_token: string;
      refresh_token: string;
      id_token: string;
      expires_in: number;
    };
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    expect(refreshed.expires_in).toBe(h.config.ACCESS_TOKEN_TTL);

    // Il nuovo access token e' valido e ha lo stesso sub.
    const access2 = await jwtVerify(refreshed.access_token, publicKeys, {
      issuer: h.config.issuer,
      audience: TEST_AUDIENCE,
      algorithms: ['EdDSA', 'RS256'],
    });
    expect(access2.payload.sub).toBe(user.id);

    // Il codice non e' riusabile (authorization code monouso).
    const replay = await client.postForm('/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: TEST_REDIRECT_URI,
      client_id: TEST_CLIENT_ID,
      code_verifier: pair.verifier,
    });
    expect(replay.status).toBeGreaterThanOrEqual(400);
    const replayBody = (await replay.json()) as { error?: string };
    expect(['invalid_grant', 'invalid_request']).toContain(replayBody.error);
  }, 60_000);
});

describe('client confidenziale', () => {
  it('autenticazione client_secret_basic con argon2id sul secret', async () => {
    const client = new HttpClient(h.baseUrl);
    const pair = pkce('S256');
    const auth = await authorizeViaConfidentialClient(pair);
    expect(auth.ok, auth.error).toBe(true);
    expect(auth.code).toBeTruthy();

    const tokenRes = await client.postForm('/token', {
      grant_type: 'authorization_code',
      code: auth.code,
      redirect_uri: 'https://app.example.test/cb',
      code_verifier: pair.verifier,
    }, {
      headers: {
        authorization:
          'Basic ' +
          Buffer.from(`${CONF_CLIENT_ID}:${CONF_CLIENT_SECRET}`).toString('base64'),
      },
    });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string };
    const payload = decodeJwt(tokens.access_token);
    expect(payload.client_id).toBe(CONF_CLIENT_ID);
  }, 60_000);

  it('rifiuta il secret sbagliato (invalid_client)', async () => {
    const client = new HttpClient(h.baseUrl);
    const res = await client.postForm(
      '/token',
      { grant_type: 'authorization_code', code: 'qualsiasi', client_id: CONF_CLIENT_ID },
      {
        headers: {
          authorization:
            'Basic ' + Buffer.from(`${CONF_CLIENT_ID}:segreto-sbagliato`).toString('base64'),
        },
      },
    );
    // La libreria risponde 400 (RFC 6749: `invalid_client` puo' essere 401 solo
    // con `WWW-Authenticate` Basic). Quel che conta e' l'errore.
    expect([400, 401]).toContain(res.status);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('invalid_client');
  });
});

/** Login completo per un client confidenziale (redirect uri dedicato). */
async function authorizeViaConfidentialClient(
  pair: ReturnType<typeof pkce>,
): Promise<{ ok: boolean; code: string; error?: string }> {
  const client = new HttpClient(h.baseUrl);
  const redirectUri = 'https://app.example.test/cb';
  const first = await client.get(
    `/auth?response_type=code&client_id=${CONF_CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent('openid profile email')}` +
      `&state=st-conf&code_challenge=${encodeURIComponent(pair.challenge)}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(TEST_AUDIENCE)}`,
  );
  const toUi = first.headers.get('location') ?? '';
  if (!toUi.includes('/ui/interaction/')) {
    return { ok: false, code: '', error: `auth -> ${first.status} ${toUi}` };
  }

  const loginHtml = await (await client.get(toUi)).text();
  const csrf = /name="_csrf" value="([^"]+)"/.exec(loginHtml)?.[1];
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1];
  if (!csrf || !uid) return { ok: false, code: '', error: 'form di login non trovato' };

  const login = await client.postForm(`/ui/interaction/${uid}/login`, {
    _csrf: csrf,
    email: user.email,
    password: user.password,
  });
  if (login.status !== 303) {
    return { ok: false, code: '', error: `login -> ${login.status} ${(await login.text()).slice(0, 200)}` };
  }

  let consent;
  try {
    consent = await followToConsent(client, login.headers.get('location') ?? '');
  } catch (err) {
    return { ok: false, code: '', error: (err as Error).message };
  }
  if (!consent.html.includes('Autorizza')) {
    return { ok: false, code: '', error: 'prompt di consenso non trovato' };
  }

  const submit = await client.postForm(`/ui/interaction/${consent.uid}/consent`, {
    _csrf: consent.csrf,
    decision: 'allow',
  });
  const location = submit.headers.get('location');
  if (!location) return { ok: false, code: '', error: `consenso -> ${submit.status} senza redirect` };
  try {
    const redirect = await followToClient(client, submit, redirectUri);
    return {
      ok: true,
      code: redirect.searchParams.get('code') ?? '',
      error: redirect.searchParams.get('error') ?? undefined,
    };
  } catch (err) {
    return { ok: false, code: '', error: (err as Error).message };
  }
}

/** Percorso completo con `nonce` fissato (serve per validare l'id token). */
async function authorizeWithNonce(options: {
  client: HttpClient;
  nonce: string;
  state: string;
  pair: ReturnType<typeof pkce>;
  scope: string;
  clientId?: string;
  redirectUri?: string;
}): Promise<{ code: string }> {
  const { client, nonce, state, pair, scope } = options;
  const clientId = options.clientId ?? TEST_CLIENT_ID;
  const redirectUri = options.redirectUri ?? TEST_REDIRECT_URI;

  const first = await client.get(
    `/auth?response_type=code&client_id=${encodeURIComponent(clientId)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent(scope)}` +
      `&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}` +
      // `prompt=consent` e' obbligatorio per ottenere un refresh token: senza,
      // `oidc-provider` (come OIDC Core §11) scarta `offline_access`.
      `&prompt=consent` +
      `&code_challenge=${encodeURIComponent(pair.challenge)}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(TEST_AUDIENCE)}`,
  );
  const toUi = first.headers.get('location') ?? '';
  expect(toUi, 'il provider deve redirigire alla UI di interazione').toContain('/ui/interaction/');

  const loginHtml = await (await client.get(toUi)).text();
  expect(loginHtml).toContain('Accedi per continuare');
  const csrf = /name="_csrf" value="([^"]+)"/.exec(loginHtml)?.[1];
  expect(csrf, 'la pagina di login deve avere un token CSRF').toBeTruthy();
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1];

  const login = await client.postForm(`/ui/interaction/${uid}/login`, {
    _csrf: csrf!,
    email: user.email,
    password: user.password,
  });
  expect(login.status).toBe(303);

  const consent = await followToConsent(client, login.headers.get('location') ?? '');
  expect(consent.html).toContain('Autorizza');
  const submit = await client.postForm(`/ui/interaction/${consent.uid}/consent`, {
    _csrf: consent.csrf,
    decision: 'allow',
  });

  const redirect = await followToClient(client, submit, redirectUri);
  expect(redirect.searchParams.get('state')).toBe(state);
  const code = redirect.searchParams.get('code');
  expect(code, 'il provider deve emettere il code').toBeTruthy();
  return { code: code! };
}
