import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, decodeJwt, jwtVerify, type JWK } from 'jose';
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
 * Suite di sicurezza: cosa il provider **rifiuta**.
 *
 * Ogni test dimostra un negato, non una conferma. I quattro temi sono quelli
 * della Definition of Done e del contratto:
 *   - PKCE `plain` mai accettato, `S256` sempre;
 *   - `redirect_uri` a match esatto (niente wildcard, niente prefisso);
 *   - nessun token con `alg: none`, nessuna firma HS* su chiave pubblica;
 *   - il riuso di un refresh token revoca l'intera famiglia.
 *
 * Il percorso di login e' quello vero (UI di interazione, consenso, code), cosi'
 * i rifiuti sono provati sull'endpoint pubblico e non su un mock.
 */

let h: Harness;
let user: { id: string; email: string; password: string };

/** Compila una richiesta di autorizzazione con parametri arbitrari. */
function authorizeUrl(params: Record<string, string>): string {
  return `/auth?${new URLSearchParams(params).toString()}`;
}

/**
 * Va fino all'interfaccia di login. Ritorna l'errore di `/auth` quando il
 * provider rifiuta la richiesta: e' li' che i rifiuti si vedono.
 */
async function startAuthorization(params: Record<string, string>): Promise<Response> {
  const client = new HttpClient(h.baseUrl);
  const res = await client.get(authorizeUrl(params));
  if (res.status >= 300 && res.status < 400) return res;
  return res;
}

async function loginThroughUi(client: HttpClient, toUi: string): Promise<Response> {
  const html = await (await client.get(toUi)).text();
  const csrf = /name="_csrf" value="([^"]+)"/.exec(html)?.[1] ?? '';
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1] ?? '';
  return client.postForm(`/ui/interaction/${uid}/login`, {
    _csrf: csrf,
    email: user.email,
    password: user.password,
  });
}

beforeAll(async () => {
  h = await setupHarness();
  user = await createTestUser(h, { verified: true });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

/* -------------------------------------------------------------------------- */
/* 1. PKCE: solo S256                                                          */
/* -------------------------------------------------------------------------- */

describe('PKCE', () => {
  it('rifiuta code_challenge_method=plain (contratto §7)', async () => {
    const pair = pkce('plain');
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: TEST_REDIRECT_URI,
      scope: 'openid profile email',
      state: 'st-plain',
      code_challenge: pair.challenge,
      code_challenge_method: 'plain',
      resource: TEST_AUDIENCE,
    });
    // Il provider rifiuta `plain` e, come vuole OIDC Core §4.1.2.1, riporta
    // l'errore **al redirect_uri registrato** con `error=invalid_request`
    // invece di completare il flusso. Quel che conta e' che il rifiuto
    // arrivi e che nessun codice venga emesso.
    const location = new URL(res.headers.get('location') ?? '', h.baseUrl);
    expect(`${location.origin}${location.pathname}`).toBe(TEST_REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('code')).toBeNull();
  });

  it('rifiuta una richiesta senza code_challenge (PKCE obbligatoria)', async () => {
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: TEST_REDIRECT_URI,
      scope: 'openid profile email',
      state: 'st-none',
      resource: TEST_AUDIENCE,
    });
    const location = new URL(res.headers.get('location') ?? '', h.baseUrl);
    expect(`${location.origin}${location.pathname}`).toBe(TEST_REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('code')).toBeNull();
  });

  it('non annuncia `plain` in discovery', async () => {
    const doc = (await (await new HttpClient(h.baseUrl).get('/.well-known/openid-configuration')).json()) as {
      code_challenge_methods_supported?: string[];
    };
    expect(doc.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('un code_challenge valido con S256 viene accettato (contro-prova)', async () => {
    const client = new HttpClient(h.baseUrl);
    const pair = pkce('S256');
    const first = await client.get(
      authorizeUrl({
        response_type: 'code',
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid profile email',
        state: 'st-s256',
        code_challenge: pair.challenge,
        code_challenge_method: 'S256',
        resource: TEST_AUDIENCE,
      }),
    );
    expect(first.status).toBe(303);
    // Il contro-prova conta: senza questo, i test di rifiuto sopra
    // dimostrerebbero solo che il provider e' rotto.
    const toUi = first.headers.get('location') ?? '';
    expect(toUi).toContain('/ui/interaction/');
    const login = await loginThroughUi(client, toUi);
    expect(login.status).toBe(303);
  });
});

/**
 * Porta la richiesta fino a un `code`, attraversando login e consenso.
 *
 * Un solo posto dove conoscere la catena di redirect: gli endpoint li usano
 * tutti e i test restano leggibili. Ritorna `''` se la catena si interrompe.
 */
async function followToCode(client: HttpClient, start: Response): Promise<string> {
  let url = start.headers.get('location') ?? '';
  for (let hop = 0; hop < 10; hop++) {
    if (!url) return '';
    const res = await client.get(url);
    const location = res.headers.get('location');
    if (!location) return '';
    url = client.resolve(location);
    const parsed = new URL(url);
    if (parsed.origin + parsed.pathname === TEST_REDIRECT_URI) {
      return parsed.searchParams.get('code') ?? '';
    }
    if (parsed.pathname.startsWith('/ui/interaction/')) {
      const html = await (await client.get(url)).text();
      const csrf = /name="_csrf" value="([^"]+)"/.exec(html)?.[1] ?? '';
      const uid = /\/ui\/interaction\/([^/?#]+)/.exec(url)?.[1] ?? '';
      const submitted = await client.postForm(`/ui/interaction/${uid}/consent`, {
        _csrf: csrf,
        decision: 'allow',
      });
      const next = submitted.headers.get('location');
      url = next ? client.resolve(next) : '';
    }
  }
  return '';
}

/* -------------------------------------------------------------------------- */
/* 2. redirect_uri: match esatto                                                */
/* -------------------------------------------------------------------------- */

describe('redirect_uri', () => {
  it('rifiuta un prefisso non registrato', async () => {
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      // Prefisso del redirect_uri registrato: il match e' stringa per stringa.
      redirect_uri: TEST_REDIRECT_URI.replace('/auth/callback', ''),
      scope: 'openid profile email',
      state: 'st-prefix',
      code_challenge: pkce('S256').challenge,
      code_challenge_method: 'S256',
      resource: TEST_AUDIENCE,
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.headers.get('location') ?? '').not.toContain('code=');
  });

  it('rifiuta un uri registrato con query diversa', async () => {
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: `${TEST_REDIRECT_URI}?code=attaccato`,
      scope: 'openid profile email',
      state: 'st-query',
      code_challenge: pkce('S256').challenge,
      code_challenge_method: 'S256',
      resource: TEST_AUDIENCE,
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.headers.get('location') ?? '').not.toContain('code=');
  });

  it('rifiuta il wildcard letterale', async () => {
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: 'http://localhost:5173/*',
      scope: 'openid profile email',
      state: 'st-wildcard',
      code_challenge: pkce('S256').challenge,
      code_challenge_method: 'S256',
      resource: TEST_AUDIENCE,
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.headers.get('location') ?? '').not.toContain('code=');
  });

  it('non riversa il codice nel redirect_uri non registrato (open redirect)', async () => {
    const evil = 'https://attaccante.example/cb';
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: evil,
      scope: 'openid profile email',
      state: 'st-evil',
      code_challenge: pkce('S256').challenge,
      code_challenge_method: 'S256',
      resource: TEST_AUDIENCE,
    });
    const location = res.headers.get('location') ?? '';
    // Se il provider decidesse di reindirizzare comunque, il codice non deve
    // essere li': il rischio e' il furto di un account, non un 400.
    expect(location).not.toContain('code=');
    if (location) expect(new URL(location, h.baseUrl).origin).not.toBe(new URL(evil).origin);
  });

  it('accetta esattamente il redirect_uri registrato (contro-prova)', async () => {
    const res = await startAuthorization({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: TEST_REDIRECT_URI,
      scope: 'openid profile email',
      state: 'st-exact',
      code_challenge: pkce('S256').challenge,
      code_challenge_method: 'S256',
      resource: TEST_AUDIENCE,
    });
    expect(res.status).toBe(303);
    expect(res.headers.get('location') ?? '').toContain('/ui/interaction/');
  });
});

/* -------------------------------------------------------------------------- */
/* 3. token con alg: none e firma HS*                                          */
/* -------------------------------------------------------------------------- */

describe('firmatura dei token', () => {
  it('non accetta un access token con alg=none', async () => {
    const jwks = (await (await new HttpClient(h.baseUrl).get('/.well-known/jwks.json')).json()) as { keys: JWK[] };
    const verifier = createLocalJWKSet(jwks);

    // Token "none": header con alg=none, payload del provider, firma vuota.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'at+jwt' })).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(
      JSON.stringify({
        iss: h.config.issuer,
        sub: user.id,
        aud: TEST_AUDIENCE,
        scope: 'streaming:account',
        client_id: TEST_CLIENT_ID,
        iat: now,
        exp: now + 900,
        jti: 'forged-none',
      }),
    ).toString('base64url');
    const forged = `${header}.${payload}.`;

    await expect(jwtVerify(forged, verifier, { algorithms: ['EdDSA', 'RS256'] })).rejects.toThrow();
    // E il nostro endpoint deve rifiutarlo con 401, non degradare in anonimo.
    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${forged}` },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate') ?? '').toContain('invalid_token');
  });

  it('non accetta un token firmato HS256 con la chiave pubblica (confusione HS/RS)', async () => {
    const jwks = (await (await new HttpClient(h.baseUrl).get('/.well-known/jwks.json')).json()) as { keys: JWK[] };
    const verifier = createLocalJWKSet(jwks);
    // Segreto derivato dalla parte pubblica: il classico attacco "usa la chiave
    // pubblica come chiave simmetrica".
    const { SignJWT } = await import('jose');
    const publicJwk = jwks.keys[0]!;
    const secret = new TextEncoder().encode(JSON.stringify(publicJwk));
    const forged = await new SignJWT({ sub: user.id })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(secret);

    await expect(jwtVerify(forged, verifier, { algorithms: ['EdDSA', 'RS256'] })).rejects.toThrow();
    const res = await new HttpClient(h.baseUrl).request('/userinfo', {
      method: 'GET',
      headers: { authorization: `Bearer ${forged}` },
    });
    expect(res.status).toBe(401);
  });

  it('non pubblica mai chiavi private in JWKS', async () => {
    for (const path of ['/jwks', '/.well-known/jwks.json']) {
      const doc = (await (await new HttpClient(h.baseUrl).get(path)).json()) as { keys: (JWK & Record<string, unknown>)[] };
      expect(doc.keys.length).toBeGreaterThan(0);
      for (const key of doc.keys) {
        expect(key.d, `campo d esposto da ${path}`).toBeUndefined();
        expect(key.p, `campo p esposto da ${path}`).toBeUndefined();
        expect(key.q, `campo q esposto da ${path}`).toBeUndefined();
        expect(key.k, `campo k esposto da ${path}`).toBeUndefined();
        expect(key.kid).toBeTruthy();
      }
    }
  });

  it('i token emessi dal provider sono firmati solo con EdDSA/RS256', async () => {
    // Contro-prova: il percorso legittimo produce token con alg ammessi e con
    // il kid della JWKS pubblicata.
    const client = new HttpClient(h.baseUrl);
    const pair = pkce('S256');
    const first = await client.get(
      authorizeUrl({
        response_type: 'code',
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid profile email offline_access',
        state: 'st-alg',
        nonce: 'n-alg',
        prompt: 'consent',
        code_challenge: pair.challenge,
        code_challenge_method: 'S256',
        resource: TEST_AUDIENCE,
      }),
    );
    const toUi = first.headers.get('location') ?? '';
    const login = await loginThroughUi(client, toUi);
    expect(login.status).toBe(303);

    const code = await followToCode(client, login);
    expect(code, 'il flusso legittimo deve arrivare a un code').toBeTruthy();

    const tokenRes = await client.postForm('/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: TEST_REDIRECT_URI,
      client_id: TEST_CLIENT_ID,
      code_verifier: pair.verifier,
    });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string; id_token: string };
    const jwks = (await (await client.get('/.well-known/jwks.json')).json()) as { keys: JWK[] };

    for (const token of [tokens.access_token, tokens.id_token]) {
      const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString('utf8')) as {
        alg: string;
        kid?: string;
      };
      expect(['EdDSA', 'RS256']).toContain(header.alg);
      expect(header.alg).not.toBe('none');
      expect(header.alg.startsWith('HS')).toBe(false);
      expect(jwks.keys.map((k) => k.kid)).toContain(header.kid);
    }
    // E il payload dell'access token porta `jti` (replay protection, §5).
    expect(decodeJwt(tokens.access_token).jti).toBeTruthy();
  });
});

/* -------------------------------------------------------------------------- */
/* 4. riuso del refresh token: revoca della famiglia                            */
/* -------------------------------------------------------------------------- */

/**
 * Percorso completo fino a ottenere una coppia (access, refresh) fresca.
 * Restituisce il client HTTP con il jar dei cookie gia' usato.
 */
async function issueTokenPair(state: string): Promise<{
  client: HttpClient;
  accessToken: string;
  refreshToken: string;
}> {
  const client = new HttpClient(h.baseUrl);
  const pair = pkce('S256');
  const first = await client.get(
    authorizeUrl({
      response_type: 'code',
      client_id: TEST_CLIENT_ID,
      redirect_uri: TEST_REDIRECT_URI,
      scope: 'openid profile email offline_access streaming:account',
      state,
      nonce: `n-${state}`,
      prompt: 'consent',
      code_challenge: pair.challenge,
      code_challenge_method: 'S256',
      resource: TEST_AUDIENCE,
    }),
  );
  const toUi = first.headers.get('location') ?? '';
  const login = await loginThroughUi(client, toUi);
  expect(login.status).toBe(303);

  const code = await followToCode(client, login);
  expect(code, `il flusso ${state} deve arrivare a un code`).toBeTruthy();

  const tokenRes = await client.postForm('/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: TEST_REDIRECT_URI,
    client_id: TEST_CLIENT_ID,
    code_verifier: pair.verifier,
  });
  expect(tokenRes.status).toBe(200);
  const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string };
  return { client, accessToken: tokens.access_token, refreshToken: tokens.refresh_token };
}

describe('rotazione e rilevamento del riuso del refresh token', () => {
  it('ruota il refresh token a ogni uso (contratto §6)', async () => {
    const { client, refreshToken } = await issueTokenPair('st-rotate');
    const first = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: TEST_CLIENT_ID,
    });
    expect(first.status).toBe(200);
    const rotated = (await first.json()) as { refresh_token: string; access_token: string };
    expect(rotated.refresh_token).not.toBe(refreshToken);

    const second = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: rotated.refresh_token,
      client_id: TEST_CLIENT_ID,
    });
    expect(second.status).toBe(200);
    const rotatedAgain = (await second.json()) as { refresh_token: string };
    expect(rotatedAgain.refresh_token).not.toBe(rotated.refresh_token);
  }, 60_000);

  it('rifiuta il riuso di un refresh token gia\' usato', async () => {
    const { client, refreshToken } = await issueTokenPair('st-reuse');
    const first = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: TEST_CLIENT_ID,
    });
    expect(first.status).toBe(200);
    const { refresh_token: rotated } = (await first.json()) as { refresh_token: string };

    // Il token **gia' consumato**: deve fallire. E' il rilevamento del riuso.
    const replay = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: TEST_CLIENT_ID,
    });
    expect(replay.status, 'il riuso di un refresh token deve essere rifiutato').toBeGreaterThanOrEqual(400);
    const body = (await replay.json()) as { error?: string };
    expect(['invalid_grant', 'invalid_request']).toContain(body.error);
    void rotated;
  }, 60_000);

  it('il riuso revoca l\'intera famiglia: anche il token nuovo muore', async () => {
    const { client, refreshToken } = await issueTokenPair('st-family');
    const first = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: TEST_CLIENT_ID,
    });
    expect(first.status).toBe(200);
    const { refresh_token: rotated } = (await first.json()) as { refresh_token: string };

    // Riuso del vecchio: scatena la revoca della famiglia.
    const replay = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: TEST_CLIENT_ID,
    });
    expect(replay.status).toBeGreaterThanOrEqual(400);

    // Il token ruotato, fino a un momento prima valido, deve ora fallire:
    // e' questo il punto dell'intera famiglia (contratto §6).
    const afterRevoke = await client.postForm('/token', {
      grant_type: 'refresh_token',
      refresh_token: rotated,
      client_id: TEST_CLIENT_ID,
    });
    expect(
      afterRevoke.status,
      'la famiglia deve essere revocata: un furto di refresh token deve costare la sessione, non il solo furto',
    ).toBeGreaterThanOrEqual(400);
    const body = (await afterRevoke.json()) as { error?: string };
    expect(['invalid_grant', 'invalid_request']).toContain(body.error);
  }, 60_000);
});