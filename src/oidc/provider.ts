import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { errors, interactionPolicy, Provider } from 'oidc-provider';
import { isAllowedBackchannelUri, type Config } from '../config.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import { createLogger } from '../logger.js';
import { createFullAdapter } from './adapter.js';
import { nativeCorsAllowed } from './native-client.js';
import {
  accessTokenProfileClaims,
  findAccount,
  resolveSupportedScopes,
  resourceServerFor,
} from './account-adapter.js';
import { verifyPassword } from '../security/password.js';
import type { ArgonConfig } from '../security/argon.js';
import { logoutSource, postLogoutSuccessSource } from './logout.js';
import type { ServiceAuthorization } from '../services/service-authz.js';
import { getEffectiveSettings } from '../services/administration.js';
import type { Db } from '../db/pool.js';
import type { User } from '../domain/types.js';

const logger = createLogger((process.env.LOG_LEVEL as never) ?? 'info', { svc: 'engine-accounts' });

/**
 * Costruzione del provider OIDC.
 *
 * `oidc-provider` (panva) fa il grosso del lavoro: discovery, PKCE S256 con
 * `plain` rifiutato, emissione e firma dei token, `introspect`, `revoke`,
 * `end_session`, chiavi con `kid`, JWKS, resource indicator RFC 8707, match
 * esatto dei `redirect_uri`. Qui decidiamo solo **cosa** vogliamo.
 *
 * Le scelte non negoziabili del contratto:
 *  - `alg` ammessi: solo EdDSA e RS256. Nessun `none`, nessun `HS*`: la
 *    confusione HS/RS non e' nemmeno configurabile, perche' `enabledJWA` non
 *    contiene algoritmi simmetrici;
 *  - PKCE S256 obbligatorio per tutti, senza eccezioni;
 *  - `redirect_uri` a match esatto (default della libreria, nessun wildcard);
 *  - refresh token con rotazione e rilevamento del riuso (revoca della famiglia).
 */

/** Algoritmo di firma primario. `RS256` resta ammesso in `enabledJWA`. */
const KID_ALG = 'Ed25519';

function jwksPath(config: Config): string {
  return path.resolve(process.cwd(), config.ENGINE_ACCOUNTS_JWKS_PATH);
}

/** Genera (se assente) o riusa il JWKS su disco. */
export async function loadOrCreateJwks(config: Config): Promise<{ keys: JWK[] }> {
  const file = jwksPath(config);
  await fs.mkdir(path.dirname(file), { recursive: true });

  if (existsSync(file)) {
    const parsed = JSON.parse(await fs.readFile(file, 'utf8')) as { keys: JWK[] };
    if (!parsed.keys.length) throw new Error(`JWKS vuoto in ${file}`);
    logger.info('JWKS caricato da disco', { keys: parsed.keys.length, path: file });
    return parsed;
  }

  const jwks = await createNewKeypair();
  await fs.writeFile(file, JSON.stringify(jwks, null, 2), { mode: 0o600 });
  logger.info('JWKS creato', { path: file, kid: jwks.keys[0]?.kid });
  return jwks;
}

async function createNewKeypair(): Promise<{ keys: JWK[] }> {
  const { publicKey, privateKey } = await generateKeyPair(KID_ALG, { extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  const kid = `k${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}`;
  return { keys: [{ ...priv, ...pub, kid, use: 'sig', alg: 'EdDSA' } as JWK] };
}

/**
 * Rotazione chiavi.
 *
 * Aggiunge una chiave nuova e **tira fuori** solo quelle che non hanno piu'
 * token vivi che le hanno firmate: il contratto chiede esattamente questo ("le
 * chiavi vecchie restano pubblicate finche' non scadono i token che hanno
 * firmato"). Con il TTL del contratto (15 minuti per l'access token, 30 giorni
 * per il refresh, che non e' firmato) la chiave si puo' ritirare dopo ~15
 * minuti dal cambio.
 *
 * `retainOldKeys` dice quanti cicli di rotazione conservare. Uno e' il minimo:
 * senza chiavi usate in parallelo, un JWKS pubblicato mentre il proxy ha la
 * cache piu' vecchia porta a token non verificabili.
 */
export async function rotateKeys(
  config: Config,
  options: { retainOldKeys?: number; dropUnusedKeys?: string[] } = {},
): Promise<{ kid: string; retained: number; dropped: string[] }> {
  const file = jwksPath(config);
  const current = JSON.parse(await fs.readFile(file, 'utf8')) as { keys: JWK[] };
  const fresh = await createNewKeypair();
  /*
   * Ordine: **la nuova chiave per prima**.
   *
   * `oidc-provider` sceglie per la firma la prima chiave del keystore che
   * combacia con `alg`/`use`, a parita' di punteggio l'ordine del JWKS decide.
   * Appendendo la chiave nuova in fondo, la rotazione non cambierebbe nulla: i
   * token continuerebbero a essere firmati con la chiave vecchia per sempre.
   * Mettendola in testa la rotazione e' reale, e le chiavi vecchie restano
   * pubblicate (indice 1+) per verificare i token che hanno gia' firmato.
   */
  const next = [...fresh.keys, ...current.keys];

  const retain = options.retainOldKeys ?? 1;
  const dropped: string[] = [];
  if (next.length > retain + 1) {
    // Si buttano le piu' vecchie, cioe' quelle in coda.
    const surplus = next.length - (retain + 1);
    for (const key of next.slice(next.length - surplus)) {
      if (key.kid) dropped.push(String(key.kid));
    }
    next.splice(next.length - surplus, surplus);
  }

  await fs.writeFile(file, JSON.stringify({ keys: next }, null, 2), { mode: 0o600 });
  void options.dropUnusedKeys;
  return { kid: String(fresh.keys[0]?.kid), retained: next.length, dropped };
}

export interface BuildProviderDeps {
  config: Config;
  store: AccountsStore;
  tokens: OidcTokenStore;
  argon: ArgonConfig;
  authorization?: ServiceAuthorization;
  db?: Db;
}

export async function buildProvider(deps: BuildProviderDeps): Promise<Provider> {
  const { config, store, tokens, argon } = deps;
  const { scopes } = await resolveSupportedScopes(store);
  const clients = await store.listClients();
  const services = await store.listServices();
  const jwks = await loadOrCreateJwks(config);
  let currentSettings = config;
  const policySettings = async () => {
    currentSettings = deps.db ? { ...config, ...Object.fromEntries((await getEffectiveSettings(deps.db, config)).map((s) => [s.key, s.value])) } as Config : config;
    return currentSettings;
  };
  await policySettings();
  const eligible = async (user: User) => {
    const settings = await policySettings();
    return (!settings.EMAIL_VERIFICATION_REQUIRED || Boolean(user.emailVerifiedAt)) && (!settings.TOTP_REQUIRED || user.totpEnabled);
  };
  const policy = interactionPolicy.base();
  policy.get('login')!.checks.add(new interactionPolicy.Check(
    'account_policy', 'Account authentication requires attention', async (ctx) => {
      const sub = ctx.oidc.session?.accountId;
      if (!sub) return false;
      const user = await store.findUserById(sub);
      return !user || user.status !== 'active' || Boolean(user.mustChangePassword) || !await eligible(user);
    },
  ));

  const provider = new Provider(config.issuer, {
    // --- persistenza -------------------------------------------------------
    // I token passano da `OidcTokenStore` (le nostre tabelle), i client da
    // `clients`: sono dati, non codice (D2).
    adapter: createFullAdapter({ store, tokens, config, argon, eligible }) as never,
    findAccount: (ctx, sub) => findAccount(store, ctx, sub, eligible),

    // --- TTL (contratto 6) -------------------------------------------------
    ttl: {
      AccessToken: config.ACCESS_TOKEN_TTL,
      AuthorizationCode: 60,
      IdToken: config.ID_TOKEN_TTL,
      RefreshToken: config.REFRESH_TOKEN_TTL,
      ClientCredentials: 600,
      DeviceCode: 600,
      Interaction: 3600,
      Session: () => currentSettings.SESSION_TTL,
      Grant: () => currentSettings.SESSION_TTL,
      PushedAuthorizationRequest: 60,
      InitialAccessToken: 600,
      RegistrationAccessToken: 600,
    },
    // Rotazione a ogni uso + rilevamento del riuso: un refresh token gia'
    // consumato revoca l'intera famiglia (contratto 6).
    rotateRefreshToken: true,

    // --- path degli endpoint: quelli del CONTRATTO -------------------------
    // La libreria usa nativamente `/token/introspection`, `/token/revocation`,
    // `/session/end` e `/me`. Il contratto congelato chiede `/introspect`,
    // `/revoke`, `/end-session` e `/userinfo`: li dichiariamo qui, cosi'
    // discovery li annuncia gia' corretti e il proxy (Agente 2) puo' usare i
    // path del contratto senza sapere di noi.
    routes: {
      authorization: '/auth',
      token: '/token',
      introspection: '/introspect',
      revocation: '/revoke',
      end_session: '/end-session',
      userinfo: '/userinfo',
      jwks: '/jwks',
    },

    // Solo Authorization Code: niente implicit, niente `none` come response type.
    // La discovery annuncia esattamente cio' che accettiamo.
    responseTypes: ['code'],

    // --- chiavi -------------------------------------------------------------
    jwks: jwks as never,
    enabledJWA: {
      // Nessun `none`, nessun `HS*`: la confusione HS/RS non e' nemmeno
      // configurabile, perche' qui non ci sono algoritmi simmetrici.
      idTokenSigningAlgValues: ['EdDSA', 'RS256'],
      userinfoSigningAlgValues: ['EdDSA', 'RS256'],
      introspectionSigningAlgValues: ['EdDSA', 'RS256'],
      authorizationSigningAlgValues: ['EdDSA', 'RS256'],
      requestObjectSigningAlgValues: ['EdDSA', 'RS256'],
      clientAuthSigningAlgValues: ['EdDSA', 'RS256'],
      // Disabilitiamo ogni cifratura di token: non serve e allarga la superficie.
      introspectionEncryptionAlgValues: [],
      introspectionEncryptionEncValues: [],
      idTokenEncryptionAlgValues: [],
      idTokenEncryptionEncValues: [],
      userinfoEncryptionAlgValues: [],
      userinfoEncryptionEncValues: [],
      requestObjectEncryptionAlgValues: [],
      requestObjectEncryptionEncValues: [],
      authorizationEncryptionAlgValues: [],
      authorizationEncryptionEncValues: [],
    },

    // --- PKCE: S256 obbligatorio per TUTTI, `plain` mai accettato ----------
    // `required` come funzione: la libreria non ha una forma "sempre true" e
    // senza questo la PKCE sarebbe opzionale.
    pkce: {
      required: () => true,
    },

    // --- claim ---------------------------------------------------------------
    claims: {
      // `amr` e' un claim del contratto (5) e deve arrivare nell'id token a ogni
      // richiesta: lo dichiariamo come claim dello scope `openid`, altrimenti la
      // libreria lo mascherebbe via e il proxy non saprebbe come l'utente si e'
      // autenticato.
      // auth_time lega l'id_token_hint al login corrente nel renderer logout.
      openid: ['sub', 'amr', 'auth_time'],
      profile: ['name', 'preferred_username', 'updated_at'],
      email: ['email', 'email_verified'],
    },
    /*
     * Claim dell'**access token**. La mappa `claims` qui sopra vale solo per
     * l'id token e per `/userinfo`: l'access token e' costruito in
     * `lib/models/formats/jwt.js` come `{ ...extra, ...claim standard }`, e
     * `extra` proviene unicamente da questo hook (default della libreria:
     * `undefined`, `lib/helpers/defaults.js`). Senza questo blocco il claim
     * `email` finiva solo nell'id token e in `/userinfo`, e il proxy — che legge
     * l'utente dal solo access token, senza chiamate di rete (D1) — rispondeva
     * `/v1/me` con `email: ""`. Il contratto §5 chiede `email` ed
     * `email_verified` in *entrambi* i token: e' il contratto che va onorato,
     * non il proxy che si adatta.
     *
     * Il claim e' filtrato per scope dentro l'adapter
     * (`accessTokenProfileClaims`): senza scope `email` nell'access token non
     * compare, e non viene inventata una stringa al posto di un indirizzo
     * mancante.
     */
    extraTokenClaims: async (_ctx, token) => accessTokenProfileClaims(store, token, deps.authorization),
    scopes,
    // Il contratto vuole `email`/`email_verified` anche nell'id token quando lo
    // scope c'e': la conformita' ai claim dello scope e' cio' che il proxy si
    // aspetta di trovare.
    conformIdTokenClaims: true,

    // --- interazione: la UI e' nostra, stesso origin --------------------------
    interactions: {
      policy,
      url: (ctx, interaction) => `/ui/interaction/${interaction.uid}`,
    },
    cookies: {
      // Prefisso dei cookie: attivo solo con COOKIE_HOST_PREFIX esplicito.
      // Il cookie di resume (`ea_res`) NON porta mai `__Host-`: oidc-provider lo
      // imposta con path `/auth/<uid>`, che i browser rifiutano per i cookie `__Host-`
      // (che richiedono categoricamente `Path=/`).
      // I cookie sono comunque Secure (su https), HttpOnly, SameSite=Lax e host-only.
      names: {
        session: `${config.cookiePrefix}ea_oidc`,
        interaction: `${config.cookiePrefix}ea_int`,
        resume: 'ea_res',
      },
      keys: [config.cookieSecret],
      long: { signed: true, httpOnly: true, sameSite: 'lax', path: '/', secure: config.secureCookies },
      short: { signed: true, httpOnly: true, sameSite: 'lax', path: '/', secure: config.secureCookies },
    },

    // --- client ---------------------------------------------------------------
    // CORS per i client pubblici (SPA, TV): la libreria ammette l'origin solo
    // se combacia con uno dei `redirect_uris` registrati del client. Non e'
    // `'*'`: un browser non deve poter chiamare /token da qualunque pagina.
    clientBasedCORS: (ctx, origin, client) => {
      if (origin === 'null') return false;
      if (client.applicationType === 'native') {
        return nativeCorsAllowed(origin, { applicationType: 'native',
          corsOrigins: (client as unknown as { cors_origins?: string[] }).cors_origins });
      }
      if (ctx.oidc.route === 'userinfo' || client.clientAuthMethod === 'none') {
        return (client.redirectUris ?? []).some((uri) => {
          try {
            return new URL(uri).origin === origin;
          } catch {
            return false;
          }
        });
      }
      return false;
    },
    clientDefaults: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      id_token_signed_response_alg: 'EdDSA',
      token_endpoint_auth_method: 'client_secret_basic',
      require_pkce: true,
    },
    // I client sono dati: `audience` e `backchannel_events_uri` sono colonne.
    extraClientMetadata: {
      properties: ['audience', 'backchannel_events_uri', 'secret_hash', 'cors_origins'],
      validator(_ctx, key, value) {
        if (key === 'cors_origins' && value !== undefined &&
          (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string'))) {
          throw new TypeError('cors_origins must be an explicit string array');
        }
        if (key === 'audience' && value !== undefined && typeof value !== 'string') {
          throw new TypeError('client audience deve essere una stringa');
        }
        if (key === 'secret_hash' && value !== undefined && typeof value !== 'string') {
          throw new TypeError('client secret_hash deve essere una stringa');
        }
        if (key === 'backchannel_events_uri' && value !== undefined) {
          if (typeof value !== 'string' || !isAllowedBackchannelUri(value, config.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) {
            throw new TypeError('backchannel_events_uri richiede HTTPS, loopback o origine HTTP interna autorizzata');
          }
        }
      },
    },

    // --- RFC 8707 ---------------------------------------------------------------
    features: {
      rpInitiatedLogout: { enabled: true, logoutSource, postLogoutSuccessSource },
      resourceIndicators: {
        enabled: true,
        // Nessun resource richiesto = audience di default della suite.
        defaultResource: () => config.OIDC_AUDIENCE,
        /*
         * Al token endpoint il client non rimanda `resource`: senza questo la
         * libreria si fermerebbe allo scope OIDC e restituirebbe un access
         * token **opaco**, mentre il contratto (e il proxy) vogliono un JWT
         * firmato con `aud`, `scope` e `client_id`. Ogni client della suite ha
         * un solo audience registrato, quindi riusare quello concesso in fase di
         * autorizzazione e' esattamente la semantica RFC 8707.
         */
        useGrantedResource: () => true,
        getResourceServerInfo: async (_ctx, resourceIndicator, client) => {
          const info = await resourceServerFor(
            store,
            await store.listClients(),
            await store.listServices(),
            resourceIndicator,
            client?.clientId,
          );
          if (!info) throw new errors.InvalidTarget('resource non autorizzato per questo client');
          return info as never;
        },
      },
      // Niente flussi che non servono: ogni feature disabilitata e' un
      // endpoint in meno da proteggere e da testare.
      devInteractions: { enabled: false },
      introspection: { enabled: true },
      revocation: { enabled: true },
      registration: { enabled: false },
      clientCredentials: { enabled: false },
      deviceFlow: { enabled: false },
      ciba: { enabled: false },
      pushedAuthorizationRequests: { enabled: false },
      webMessageResponseMode: { enabled: false },
      dPoP: { enabled: false },
      jwtUserinfo: { enabled: false },
      fapi: { enabled: false },
      mTLS: { enabled: false },
      richAuthorizationRequests: { enabled: false },
      externalSigningSupport: { enabled: false },
      userinfo: { enabled: true },
    },

    // --- errori ----------------------------------------------------------------
    // Le API OIDC rispondono JSON (RFC 6749) quando il client chiede JSON.
    // Quando arriva un browser (`Accept: text/html`) la libreria chiama
    // `renderError`: la nostra pagina e' la stessa della UI, con il CSS
    // esterno, perche' la CSP non ammette stili inline.
    renderError(ctx, out) {
      ctx.type = 'text/html; charset=utf-8';
      ctx.body = errorPage(out.error, out.error_description);
    },
  });

  patchClientSecretComparison(provider, argon);
  applyProxyTrust(provider, config);

  logger.info('provider OIDC costruito', {
    issuer: config.issuer,
    scopes,
    clients: clients.length,
    services: services.length,
    pkce: 'S256 (obbligatorio)',
    algs: 'EdDSA,RS256',
  });

  return provider;
}

/**
 * Il secret del client confidential e' un hash argon2id (contratto 7). La
 * libreria confronterebbe il candidato con `client.clientSecret` a tempo
 * costante: quel confronto sarebbe sempre falso, perche' i due valori non
 * coincidono mai. Sostituiamo il metodo con la verifica argon2id: il segreto in
 * chiaro non esiste nel processo, e il confronto costa lo stesso di una password
 * utente.
 */
function patchClientSecretComparison(provider: Provider, argon: ArgonConfig): void {
  const ClientClass = provider.Client as unknown as {
    prototype: {
      compareClientSecret(this: { clientSecret?: string; secret_hash?: string }, actual: string): Promise<boolean>;
    };
  };
  ClientClass.prototype.compareClientSecret = async function (
    this: { clientSecret?: string; secret_hash?: string },
    actual: string,
  ) {
    const hash = this.secret_hash;
    if (typeof hash === 'string' && hash.startsWith('$argon2')) {
      return verifyPassword(hash, actual, argon);
    }
    // Nessun hash: solo per client statici, che questo servizio non usa.
    if (typeof this.clientSecret === 'string' && this.clientSecret.length > 0) {
      const { constantTimeEqual } = await import('../security/crypto.js');
      return constantTimeEqual(this.clientSecret, actual);
    }
    return false;
  };
}

/**
 * Fiducia nel reverse proxy (`TRUST_PROXY`).
 *
 * `oidc-provider` **e'** una app Koa, e Koa guarda `X-Forwarded-Proto` solo se
 * `app.proxy` e' acceso. Senza questo, dietro un proxy che termina il TLS
 * (Caddy, nginx, Traefik) il provider vede una connessione http, la libreria
 * `cookies` **rifiuta di impostare un cookie `Secure`** e ogni richiesta su
 * `/auth` risponde 500: il login è morto nel momento in cui si passa dal
 * `http://localhost` a `https://account.oberdfr.top`, senza che nient'altro
 * cambi.
 *
 * Costa fiducia in quell'intestazione, quindi e' dietro interruttore e va
 * acceso solo se il proxy e' l'unico modo per arrivare al servizio. Se il
 * servizio e' raggiungibile anche in chiaro, un cliente qualsiasi puo' mandare
 * `X-Forwarded-Proto: https` e ottenere risposte con cookie marcati `Secure`:
 * innocuo (il browser li scarta sulla connessione non cifrata), ma non e'
 * piu' una garanzia.
 */
function applyProxyTrust(provider: Provider, config: Config): void {
  if (!config.TRUST_PROXY) return;
  // `Provider extends Koa`: la proprieta' e' quella di Koa, non una nostra.
  (provider as unknown as { proxy: boolean }).proxy = true;
}

/** Chiave pubblica attualmente nel JWKS, senza i campi privati. */
export async function activePublicJwks(config: Config): Promise<JWK[]> {
  const { keys } = await loadOrCreateJwks(config);
  const out: JWK[] = [];
  for (const key of keys) {
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, k: _k, ...rest } = key as JWK & Record<string, unknown>;
    void _d; void _p; void _q; void _dp; void _dq; void _qi; void _k;
    out.push(rest as JWK);
  }
  return out;
}

/** Pagina d'errore OIDC per i browser: stessa CSP della UI, CSS esterno. */
function errorPage(error: string, description: string | undefined): string {
  const esc = (value: string) =>
    value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
  return `<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Errore · Engine Accounts</title><link rel="stylesheet" href="/static/app.css"></head>
<body class="layout-narrow"><header class="top"><a class="brand" href="/">Engine Accounts</a></header>
<main><h1>Richiesta non riuscita</h1>
<p class="lede">Errore: <code>${esc(error)}</code></p>
${description ? `<p>${esc(description)}</p>` : ''}
<p><a href="/ui/login">Torna all'accesso</a></p></main></body></html>`;
}
