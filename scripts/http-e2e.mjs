#!/usr/bin/env node
/**
 * Flusso OIDC completo **su HTTP reale**: richieste vere al servizio in
 * ascolto, niente in comune con i test.
 *
 *   node scripts/http-e2e.mjs [baseUrl]
 *
 * Cosa dimostra, nell'ordine:
 *   discovery -> register -> verify -> login -> consenso -> code
 *   -> token -> userinfo -> refresh con rotazione
 *
 * Lo script e' autosufficiente: registra lui il client che gli serve (o lo
 * aggiorna, `client add` e' un upsert) e ne cattura il secret, quindi non ha
 * precondizioni da eseguire a mano. Se pero' non riesce a registrarlo, dice il
 * comando esatto da eseguire invece di proseguire e fallire piu' avanti con un
 * errore che sembra un altro.
 *
 * Variabili d'ambiente riconosciute:
 *   E2E_CLIENT_ID     (default http-e2e-client)
 *   E2E_REDIRECT_URI  (default http://127.0.0.1:5173/auth/callback)
 *   MAILPIT_API       (default http://localhost:8025)
 *   E2E_KEEP_SECRET=1 non cancellare il client alla fine
 */
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_ROOT = path.resolve(HERE, '..');

const BASE = process.argv[2] ?? 'http://localhost:8080';
const REDIRECT = process.env.E2E_REDIRECT_URI ?? 'http://127.0.0.1:5173/auth/callback';
const POST_LOGOUT = new URL('/', REDIRECT).toString();
const AUDIENCE = process.env.E2E_AUDIENCE ?? 'https://api.engine.local/streaming';
const SCOPE = 'openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account';
const CLIENT_ID = process.env.E2E_CLIENT_ID ?? 'http-e2e-client';
const MAILPIT = process.env.MAILPIT_API ?? 'http://localhost:8025';
const KEEP = process.env.E2E_KEEP_SECRET === '1';

/* -------------------------------------------------------------------------- */
/* utilita'                                                                    */
/* -------------------------------------------------------------------------- */

const jar = new Map();
const csrfOf = (html) => /name="_csrf" value="([^"]+)"/.exec(html ?? '')?.[1] ?? '';
let stepNo = 0;

function step(what) {
  stepNo += 1;
  console.log(`\n${stepNo}. ${what}`);
}

function info(...parts) {
  console.log('  ', ...parts);
}

function fail(message, hint) {
  console.error(`\nFALLITO: ${message}`);
  if (hint) console.error(`\n${hint}`);
  process.exit(1);
}

function saveCookies(res) {
  for (const raw of res.headers.getSetCookie?.() ?? []) {
    const [pair] = raw.split(';');
    const i = pair?.indexOf('=') ?? -1;
    if (i < 0) continue;
    const name = pair.slice(0, i).trim();
    const value = decodeURIComponent(pair.slice(i + 1).trim());
    if (/expires=Thu, 01 Jan 1970/i.test(raw) || value === '') jar.delete(name);
    else jar.set(name, value);
  }
}

async function req(pathOrUrl, init = {}) {
  const url = new URL(pathOrUrl, BASE).toString();
  const headers = new Headers(init.headers);
  if (jar.size && !headers.has('cookie')) {
    headers.set('cookie', [...jar].map(([k, v]) => `${k}=${v}`).join('; '));
  }
  const res = await fetch(url, { ...init, headers, redirect: 'manual' });
  saveCookies(res);
  return res;
}

async function postForm(path, fields, init = {}) {
  // `...init` va PRIMA: se venisse dopo, i suoi header (per esempio
  // `authorization`) sovrascriverebbero il content-type e il provider
  // risponderebbe "only application/x-www-form-urlencoded bodies are supported".
  return req(path, {
    ...init,
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(init.headers ?? {}) },
    body: new URLSearchParams(fields).toString(),
  });
}

const basicAuth = (id, secret) => ({
  authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`,
});

/** Codice di errore OIDC dentro una pagina di errore HTML del provider. */
function errorCodeOf(html) {
  return /<code>([a-z_]+)<\/code>/.exec(html ?? '')?.[1] ?? '';
}

/** Fallisce con un messaggio che dice davvero cosa non va. */
async function expectOk(res, what, extraHint) {
  if (res.status < 400) return;
  const body = await res.clone().text();
  const code = errorCodeOf(body);
  const detail = code ? ` (${code})` : '';
  fail(
    `${what}: HTTP ${res.status}${detail}`,
    extraHint ?? `corpo della risposta:\n${body.slice(0, 400)}`,
  );
}

/* -------------------------------------------------------------------------- */
/* 0. precondizioni: il servizio c'e' e il client c'e'                         */
/* -------------------------------------------------------------------------- */

/**
 * Registra (o aggiorna) il client e restituisce il secret in chiaro.
 *
 * La CLI lo mostra una volta sola e lo stampa su stdout: qui lo catturiamo.
 * `client add` e' un upsert sul `client_id`, quindi rieseguire lo script non
 * crea duplicati.
 */
function ensureClient() {
  const args = [
    path.join(SERVICE_ROOT, 'node_modules/tsx/dist/cli.mjs'),
    path.join(SERVICE_ROOT, 'src/cli/main.ts'),
    'client',
    'add',
    CLIENT_ID,
    '--type',
    'confidential',
    '--redirect-uri',
    REDIRECT,
    '--post-logout-uri',
    POST_LOGOUT,
    '--scope',
    SCOPE,
    '--audience',
    AUDIENCE,
  ];
  let stdout = '';
  try {
    stdout = execFileSync('node', args, {
      encoding: 'utf8',
      cwd: SERVICE_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_ENV: process.env.NODE_ENV ?? 'development' },
    });
  } catch (err) {
    const e = { stdout: err.stdout, stderr: err.stderr };
    const output = `${e.stdout ?? ''}${e.stderr ?? ''}`.trim();
    fail(
      `impossibile registrare il client di test: ${output.slice(0, 300) || String(err.message ?? err)}`,
      `La CLI ha bisogno del database. Su questa macchina:\n` +
        `  cd ${SERVICE_ROOT} && npm run cli -- client add ${CLIENT_ID} --type confidential \\\n` +
        `    --redirect-uri "${REDIRECT}" --post-logout-uri "${POST_LOGOUT}" \\\n` +
        `    --scope ${SCOPE} --audience "${AUDIENCE}"`,
    );
  }
  const secret = /CLIENT_SECRET[^\n]*\n\s*(\S+)/.exec(stdout)?.[1] ?? '';
  if (!secret) {
    fail(
      'la CLI ha registrato il client ma non ha stampato il secret: non posso autenticarlo.',
      `Guarda l'output della CLI:\n${stdout.slice(0, 400)}`,
    );
  }
  return secret;
}

function removeClient() {
  try {
    execFileSync(
      'node',
      [
        path.join(SERVICE_ROOT, 'node_modules/tsx/dist/cli.mjs'),
        path.join(SERVICE_ROOT, 'src/cli/main.ts'),
        'client',
        'remove',
        CLIENT_ID,
      ],
      { encoding: 'utf8', cwd: SERVICE_ROOT, stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch {
    /* la pulizia non deve far fallire il test */
  }
}

step(`precondizioni: servizio su ${BASE}`);
const health = await fetch(`${BASE}/healthz`).catch(() => undefined);
if (!health?.ok) {
  fail(
    `nessun servizio su ${BASE} (healthz non risponde).`,
    `Avvialo dalla root EngineAccounts:\n  cd ${SERVICE_ROOT} && npm run dev`,
  );
}
info('healthz ok');

const clientSecret = ensureClient();
info(`client ${CLIENT_ID} pronto (confidential, secret catturato)`);

/* -------------------------------------------------------------------------- */

const email = `http-e2e-${Date.now()}@example.test`;
const password = 'PasswordLungaCheNonEsiste123!';
const verifier = crypto.randomBytes(48).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
const state = `st-${crypto.randomBytes(6).toString('hex')}`;

try {
  /* --- 1. discovery ------------------------------------------------------- */
  step('discovery');
  const discRes = await req('/.well-known/openid-configuration');
  await expectOk(discRes, 'discovery');
  const disc = await discRes.json();
  info('issuer:', disc.issuer);
  info('token_endpoint:', disc.token_endpoint);
  info('code_challenge_methods_supported:', disc.code_challenge_methods_supported);
  if (disc.code_challenge_methods_supported?.includes('plain')) {
    fail('la discovery annuncia PKCE plain: il contratto vieta S256-only');
  }

  /* --- 2. registrazione --------------------------------------------------- */
  step('registrazione via POST /ui/register');
  const regPage = await req('/ui/register');
  await expectOk(regPage, 'pagina di registrazione');
  const reg = await postForm('/ui/register', {
    _csrf: csrfOf(await regPage.text()),
    email,
    displayName: 'Utente HTTP E2E',
    password,
  });
  await expectOk(reg, 'registrazione');
  info('HTTP', reg.status, '->', reg.headers.get('location'), '(risposta neutra)');

  /* --- 3. verifica email -------------------------------------------------- */
  step('verifica email dal link');
  let token = '';
  try {
    const list = await (await fetch(`${MAILPIT}/api/v1/messages?limit=30`)).json();
    for (const item of (list.messages ?? []).slice().reverse()) {
      const detail = await (await fetch(`${MAILPIT}/api/v1/message/${item.ID}`)).json();
      const to = (detail.To ?? []).map((t) => t.Address).join(',');
      if (!to.includes(email)) continue;
      const body = `${detail.Text ?? ''}${detail.HTML ?? ''}`;
      token = /\/ui\/verify-email\?token=([A-Za-z0-9_-]+)/.exec(body)?.[1] ?? '';
      if (token) break;
    }
  } catch {
    info('Mailpit non raggiungibile');
  }
  if (token) {
    const verifyRes = await req(`/ui/verify-email?token=${encodeURIComponent(token)}`);
    await expectOk(verifyRes, 'verifica email');
    info('HTTP', verifyRes.status, '(email verificata)');
  } else {
    info('nessun link di verifica trovato: l\'account resta non verificato, il login funziona lo stesso');
  }

  /* --- 4. GET /auth ------------------------------------------------------- */
  step('GET /auth');
  const auth = await req(
    `/auth?response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
      `&scope=${encodeURIComponent('openid profile email offline_access streaming:account')}` +
      `&state=${encodeURIComponent(state)}&nonce=n-http-e2e&prompt=consent` +
      `&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256` +
      `&resource=${encodeURIComponent(AUDIENCE)}`,
  );
  if (auth.status >= 400) {
    const body = await auth.text();
    const code = errorCodeOf(body);
    if (code === 'invalid_client') {
      fail(
        'GET /auth: invalid_client: il provider non conosce il client.',
        `Il client registrato e' "${CLIENT_ID}" con redirect_uri "${REDIRECT}".\n` +
          `Se l'hai cambiato con E2E_CLIENT_ID, i redirect_uri devono combaciare:\n` +
          `  E2E_CLIENT_ID=altro E2E_REDIRECT_URI="http://altro/cb" node scripts/http-e2e.mjs`,
      );
    }
    fail(`GET /auth: HTTP ${auth.status}${code ? ` (${code})` : ''}`, body.slice(0, 400));
  }
  const toUi = auth.headers.get('location') ?? '';
  info('HTTP', auth.status, '->', toUi);
  if (!toUi.includes('/ui/interaction/')) {
    fail(`GET /auth non ha mandato alla UI di interazione: ${toUi}`);
  }

  /* --- 5. login ----------------------------------------------------------- */
  step('login sulla UI di interazione');
  const interaction = await req(toUi);
  await expectOk(interaction, 'pagina di interazione');
  const loginHtml = await interaction.text();
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(toUi)?.[1] ?? '';
  const loginCsrf = csrfOf(loginHtml);
  if (!uid || !loginCsrf) fail('la pagina di interazione non ha il form di login');
  const login = await postForm(`/ui/interaction/${uid}/login`, {
    _csrf: loginCsrf,
    email,
    password,
  });
  await expectOk(login, 'login', 'Login fallito: controlla che l\'account sia stato creato al passo 2.');
  info('HTTP', login.status, '->', login.headers.get('location'));
  if (!jar.has('ea_sid')) fail('dopo il login non e\' arrivato il cookie di sessione');
  info('cookie di sessione ricevuto:', [...jar.keys()].join(', '));

  /* --- 6. consenso ------------------------------------------------------- */
  step('prompt di consenso');
  let cursor = login.headers.get('location');
  let consentDone = false;
  for (let i = 0; i < 6 && !consentDone; i++) {
    const page = await req(cursor);
    const html = await page.text();
    if (html.includes('Autorizza')) {
      const cuid = /\/ui\/interaction\/([^/?#]+)/.exec(page.url)?.[1] ?? '';
      const consent = await postForm(`/ui/interaction/${cuid}/consent`, {
        _csrf: csrfOf(html),
        decision: 'allow',
      });
      await expectOk(consent, 'consenso');
      info('POST consenso HTTP', consent.status, '->', consent.headers.get('location'));
      cursor = consent.headers.get('location');
      consentDone = true;
    } else {
      cursor = page.headers.get('location') ?? cursor;
    }
  }
  if (!consentDone) fail('il prompt di consenso non e\' comparso');

  /* --- 7. redirect al client con il code ---------------------------------- */
  step('redirect al client');
  let code = '';
  for (let i = 0; i < 8 && !code; i++) {
    const res = await req(cursor);
    const location = res.headers.get('location');
    if (!location) fail(`catena interrotta su ${cursor}: HTTP ${res.status}`);
    cursor = new URL(location, BASE).toString();
    const parsed = new URL(cursor);
    if (parsed.origin + parsed.pathname === REDIRECT) {
      info('redirect:', location.slice(0, 96));
      if (parsed.searchParams.get('state') !== state) {
        fail(`lo state non torna al client: atteso ${state}, ricevuto ${parsed.searchParams.get('state')}`);
      }
      code = parsed.searchParams.get('code') ?? '';
    }
  }
  if (!code) fail(`nessun code nella catena di redirect (ultimo hop: ${cursor})`);
  info('code:', code.slice(0, 16), '...');

  /* --- 8. POST /token ----------------------------------------------------- */
  step('POST /token (authorization_code + client_secret_basic)');
  const tokenRes = await postForm(
    '/token',
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    },
    { headers: basicAuth(CLIENT_ID, clientSecret) },
  );
  if (tokenRes.status >= 400) {
    const body = await tokenRes.text();
    fail(`POST /token: HTTP ${tokenRes.status} (${errorCodeOf(body) || 'senza codice'})`, body.slice(0, 300));
  }
  const tokens = await tokenRes.json();
  const header = JSON.parse(Buffer.from(tokens.access_token.split('.')[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(tokens.access_token.split('.')[1], 'base64url').toString());
  info('token_type:', tokens.token_type, '| expires_in:', tokens.expires_in);
  info('scope:', tokens.scope);
  info('refresh_token:', tokens.refresh_token ? 'presente' : 'ASSENTE');
  info('alg:', header.alg, '| kid:', header.kid);
  info('iss:', payload.iss, '| aud:', payload.aud, '| client_id:', payload.client_id);
  if (!tokens.refresh_token) {
    fail('nessun refresh_token: manca `prompt=consent`? (senza, la libreria scarta offline_access)');
  }
  if (payload.iss !== disc.issuer) {
    fail(`il claim iss del token non coincide con la discovery: ${payload.iss} != ${disc.issuer}`);
  }
  if (payload.aud !== AUDIENCE) {
    fail(`aud inatteso: ${payload.aud} != ${AUDIENCE}`);
  }
  if (!['EdDSA', 'RS256'].includes(header.alg)) {
    fail(`alg non ammesso: ${header.alg}`);
  }
  // Se richiesto, lascia il token su disco: serve a ispezionarlo e a provare
  // cosa risponde un consumer con un issuer diverso.
  if (process.env.E2E_DUMP_TOKEN) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(process.env.E2E_DUMP_TOKEN, tokens.access_token, { mode: 0o600 });
    info('token scritto in', process.env.E2E_DUMP_TOKEN);
  }

  /* --- 9. GET /userinfo --------------------------------------------------- */
  step('GET /userinfo');
  const userinfo = await req('/userinfo', {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  await expectOk(userinfo, 'userinfo');
  const profile = await userinfo.json();
  info('sub:', profile.sub, '| email:', profile.email, '| verified:', profile.email_verified);
  if (profile.sub !== payload.sub) fail('lo sub di /userinfo non coincide con quello del token');

  /* --- 10. refresh con rotazione ------------------------------------------ */
  step('POST /token (refresh_token)');
  const refresh = await postForm(
    '/token',
    {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
    },
    { headers: basicAuth(CLIENT_ID, clientSecret) },
  );
  if (refresh.status >= 400) {
    const body = await refresh.text();
    fail(`refresh: HTTP ${refresh.status} (${errorCodeOf(body) || 'senza codice'})`, body.slice(0, 300));
  }
  const rotated = await refresh.json();
  const changed = rotated.refresh_token !== tokens.refresh_token;
  info('refresh ruotato:', changed);
  if (!changed) fail('il refresh token non e\' cambiato: la rotazione non sta funzionando');

  const userinfo2 = await req('/userinfo', {
    headers: { authorization: `Bearer ${rotated.access_token}` },
  });
  await expectOk(userinfo2, 'userinfo con il token ruotato');
  info('sub:', (await userinfo2.json()).sub);

  step('rifiuto del riuso del refresh token');
  const replay = await postForm(
    '/token',
    { grant_type: 'refresh_token', refresh_token: tokens.refresh_token },
    { headers: basicAuth(CLIENT_ID, clientSecret) },
  );
  if (replay.status < 400) fail('il riuso di un refresh token è stato accettato');
  info('HTTP', replay.status, '(rifiutato, come deve)');

  console.log(
    '\nTUTTO OK: discovery -> register -> verify -> login -> consenso -> code -> token -> userinfo -> refresh',
  );
} finally {
  if (KEEP) {
    console.log(`\nclient ${CLIENT_ID} lasciato in piedi (E2E_KEEP_SECRET=1).`);
  } else {
    removeClient();
  }
}
