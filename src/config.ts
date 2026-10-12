import crypto from 'node:crypto';
import { z } from 'zod';

/**
 * Configurazione del servizio, validata una sola volta all'avvio.
 *
 * Regola (D8): nessun segreto nel codice, tutto da env/secret file. Il resto ha
 * default espliciti, perche' il contratto congelato fissa i valori (TTL 15 min /
 * 30 giorni, PKCE S256, issuer) e devono valere anche se qualcuno sbaglia l'env.
 */

const booleanish = z
  .union([z.boolean(), z.string()])
  .transform((value) => (typeof value === 'boolean' ? value : ['1', 'true', 'yes', 'on'].includes(value.toLowerCase())));

const int = (fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER) =>
  z.coerce.number().int().min(min).max(max).default(fallback);

/**
 * Compone la `DATABASE_URL` dalle variabili del `.env` di sviluppo.
 *
 * In sviluppo il Postgres e' esposto su `POSTGRES_PORT` (55432, per non
 * litigare con un Postgres di sistema) con `POSTGRES_PASSWORD` impostata: sono
 * le uniche informazioni che il `.env` contiene, quindi la connessione si puo'
 * ricavare senza duplicare qui porta e password.
 *
 * Fuori dallo sviluppo, se `DATABASE_URL` non c'e', non si indovina niente:
 * `loadConfig()` solleva un errore che dice cosa manca.
 */
export function databaseUrlFromPostgresEnv(
  env: NodeJS.ProcessEnv,
): string | undefined {
  if (env.DATABASE_URL) return env.DATABASE_URL;
  const password = env.POSTGRES_PASSWORD;
  if (!password) return undefined;
  const user = env.POSTGRES_USER ?? 'engine';
  const host = env.POSTGRES_HOST ?? '127.0.0.1';
  const port = env.POSTGRES_PORT ?? '5432';
  const database = env.POSTGRES_DB ?? 'engine';
  return `postgres://${user}:${encodeURIComponent(password)}@${host}:${port}/${database}`;
}

const clientUri = z.string().url().refine((value) => {
  const url = new URL(value);
  return !value.includes('*') && !url.username && !url.password && !url.hash;
}, 'URI client esatta, senza wildcard, credenziali o fragment');

const publicClientSchema = z.object({
  clientId: z.string().min(1),
  clientName: z.string().min(1).optional(),
  redirectUris: z.array(clientUri).min(1),
  postLogoutRedirectUris: z.array(clientUri).default([]),
  scope: z.array(z.string().min(1)).default(['openid', 'profile', 'email', 'offline_access'])
    .refine((scopes) => scopes.includes('openid'), 'scope deve includere openid'),
  audience: z.string().url(),
  backchannelEventsUri: clientUri.optional(),
}).strict();

const configuredClientsSchema = z.string().default('[]').transform((value, ctx) => {
  try { return JSON.parse(value) as unknown; }
  catch {
    ctx.addIssue({ code: 'custom', message: 'OIDC_CLIENTS_JSON deve essere JSON valido' });
    return z.NEVER;
  }
}).pipe(z.array(publicClientSchema).refine((clients) =>
  new Set(clients.map((client) => client.clientId)).size === clients.length,
  'clientId duplicato').refine((clients) => {
    const audiences = new Map<string, string>();
    for (const client of clients) for (const scope of client.scope) {
      if (['openid', 'profile', 'email', 'offline_access'].includes(scope)) continue;
      if (audiences.has(scope) && audiences.get(scope) !== client.audience) return false;
      audiences.set(scope, client.audience);
    }
    return true;
  }, 'Uno scope di servizio deve appartenere a una sola audience'));

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  // --- rete -----------------------------------------------------------------
  PORT: int(8080, 1, 65535),
  ENGINE_ACCOUNTS_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  HOST: z.string().default('0.0.0.0'),
  // Dietro reverse proxy che termina il TLS: il provider deve fidarsi di
  // `X-Forwarded-Proto`, altrimenti rifiuta di emettere i cookie `Secure` su
  // una connessione che lui vede come http (vedi `TRUST_PROXY` in
  // `oidc/provider.ts`). Accenderlo significa fidarsi di quell'intestazione:
  // si accende solo se il proxy e' l'unico modo per arrivare al servizio.
  TRUST_PROXY: booleanish.default(false),
  // Base pubblica: se non coincide con l'emettente, discovery e issuer divergono.
  PUBLIC_BASE_URL: z.string().url().optional(),

  // --- database -------------------------------------------------------------
  // Nessun default: una `DATABASE_URL` indovinata e' peggio di nessuna, perche'
  // il servizio parte e parla con il database sbagliato. Quando manca viene
  // composta dalle variabili `POSTGRES_*` del `.env` (vedi
  // `databaseUrlFromPostgresEnv`).
  DATABASE_URL: z.string().min(1).optional(),
  // Schema Postgres dedicato: il database `engine` e' condiviso con il proxy,
  // nessuna tabella deve uscire dal proprio schema.
  DB_SCHEMA: z
    .string()
    .regex(/^[a-z_][a-z0-9_]*$/i, 'DB_SCHEMA deve essere un identificatore Postgres')
    .default('engine_accounts'),
  DB_POOL_MAX: int(10, 1, 200),
  DB_SSL: booleanish.default(false),

  // --- OIDC -----------------------------------------------------------------
  OIDC_ISSUER: z.string().url().default('http://localhost:8080'),
  // Audience di default (RFC 8707) quando il client non manda `resource`.
  OIDC_AUDIENCE: z.string().url().default('https://api.engine.local/streaming'),
  // Registrazione dichiarativa di SPA pubbliche. Nessun dominio di un consumer
  // nel core; i client confidenziali restano amministrati tramite CLI.
  OIDC_CLIENTS_JSON: configuredClientsSchema,
  // TLS outside loopback, unless an operator explicitly trusts an HTTP origin.
  BACKCHANNEL_HTTP_ALLOWED_ORIGINS: z.string().default(''),
  // Segreto condiviso per firmare/verificare gli eventi back-channel (C11).
  OIDC_EVENT_SIGNING_SECRET: z.string().min(1).optional(),
  // Chiave per cifrare a riposo i segreti degli utente (TOTP).
  // Se assente viene derivata (HKDF) dal segreto eventi: mai la stessa in chiaro.
  ENGINE_ACCOUNTS_DATA_KEY: z.string().min(1).optional(),
  // Segreto per firmare i cookie di sessione propri.
  ENGINE_ACCOUNTS_COOKIE_SECRET: z.string().min(1).optional(),
  ENGINE_ACCOUNTS_JWKS_PATH: z.string().default('var/jwks.json'),
  // `Secure` sui cookie: in produzione (issuer https) obbligatorio.
  // Se assente, derivato dall'issuer.
  COOKIE_SECURE: booleanish.optional(),
  // Prefisso `__Host-` per i cookie: disattivato di default perche' oidc-provider
  // assegna al cookie di resume (`ea_res`) un path scopato `/auth/<uid>`, che i
  // browser conformi a RFC 6265bis rifiutano categoricamente per i cookie `__Host-`
  // (che esigono `Path=/`).
  COOKIE_HOST_PREFIX: booleanish.default(false),
  // HSTS dietro interruttore: si emette solo su richieste gia' https, e solo
  // se acceso. Dietro un reverse proxy che termina il TLS va acceso a mano.
  HSTS_ENABLED: booleanish.optional(),
  HSTS_MAX_AGE: int(31_536_000, 0),
  HSTS_INCLUDE_SUBDOMAINS: booleanish.default(false),

  // --- scadenze (contratto: 15 min access, 30 giorni refresh) ---------------
  ACCESS_TOKEN_TTL: int(900, 60),
  REFRESH_TOKEN_TTL: int(2_592_000, 600),
  ID_TOKEN_TTL: int(900, 60),
  PASSWORD_RESET_TTL: int(900, 60),
  EMAIL_VERIFICATION_TTL: int(900, 60),
  EMAIL_CHANGE_TTL: int(900, 60),
  MAGIC_CODE_TTL: int(300, 60),
  SESSION_TTL: int(1_209_600, 300),
  CONSENT_TTL: int(31_536_000, 3600),

  // --- argon2id --------------------------------------------------------------
  ARGON2_MEMORY_KIB: int(65_536, 8_192, 1_048_576),
  ARGON2_ITERATIONS: int(3, 1, 20),
  ARGON2_PARALLELISM: int(1, 1, 16),
  // Limite anti-DoS, NON un limite di prodotto: 1024 caratteri sono gia' oltre
  // qualsiasi password umana plausibile, ma l'hash resta lineare nel tempo.
  PASSWORD_MAX_LENGTH: int(1024, 64, 65_536),
  PASSWORD_MIN_LENGTH: int(12, 8, 128),

  // --- anti-enumerazione / rate limiting -------------------------------------
  HTTP_LOGIN_SLOW_MS: int(200, 0, 10_000),
  LOGIN_RATE_IP_MAX: int(40, 1, 100_000),
  LOGIN_RATE_IP_WINDOW_MS: int(300_000, 1000),
  LOGIN_RATE_ACCOUNT_MAX: int(8, 1, 100_000),
  LOGIN_RATE_ACCOUNT_WINDOW_MS: int(900_000, 1000),
  // Lockout progressivo per account: attesa = BASE * 2^fallimenti, con tetto.
  ACCOUNT_LOCK_BASE_MS: int(1_000, 100),
  ACCOUNT_LOCK_MAX_MS: int(3_600_000, 1000),
  PASSWORD_RESET_RATE_MAX: int(5, 1, 100_000),
  PASSWORD_RESET_RATE_WINDOW_MS: int(3_600_000, 1000),
  REGISTRATION_RATE_MAX: int(5, 1, 100_000),
  REGISTRATION_RATE_WINDOW_MS: int(3_600_000, 1000),

  // --- password compromesse (k-anonymity) -----------------------------------
  HIBP_ENABLED: booleanish.default(true),
  HIBP_API_BASE: z.string().url().default('https://api.pwnedpasswords.com'),
  HIBP_TIMEOUT_MS: int(1500, 100, 30_000),
  HIBP_CACHE_TTL_MS: int(86_400_000, 0),

  // --- posta ----------------------------------------------------------------
  SMTP_HOST: z.string().default('127.0.0.1'),
  SMTP_PORT: int(1025, 1, 65535),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().default('no-reply@engine.local'),
  SMTP_FROM_NAME: z.string().default('Engine Accounts'),
  SMTP_SECURE: booleanish.default(false),
  MAIL_ENABLED: booleanish.default(true),
});

export type RawConfig = z.infer<typeof schema>;

export interface Config extends RawConfig {
  port: number;
  issuer: string;
  baseUrl: string;
  eventSigningKey: Buffer;
  dataKey: Buffer;
  cookieSecret: string;
  /** `Secure` sui cookie: con https e' sempre true. */
  secureCookies: boolean;
  /** Prefisso dei cookie: `__Host-` solo quando `Secure` e' possibile. */
  cookiePrefix: '' | '__Host-';
  /** HSTS: interruttore, durata e sottodomini. */
  hsts: { enabled: boolean; maxAge: number; includeSubDomains: boolean };
  /** Argon2id: i parametri sono espliciti e documentati. */
  argon2: { memoryCost: number; timeCost: number; parallelism: number };
}

/**
 * HKDF-SHA256 (RFC 5869) con `info` = scopo: dalla stessa radice deriviamo
 * chiavi diverse per eventi back-channel, cifratura a riposo e cookie.
 */
export function hkdf(secret: Buffer, info: string, length = 32): Buffer {
  return Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.alloc(32), Buffer.from(info, 'utf8'), length));
}

export function isAllowedBackchannelUri(uri: string, httpOrigins = ''): boolean {
  try {
    const url = new URL(uri);
    if (url.username || url.password || url.hash || uri.includes('*')) return false;
    if (url.protocol === 'https:') return true;
    if (url.protocol !== 'http:') return false;
    if (['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)) return true;
    return httpOrigins.split(',').map((origin) => origin.trim()).filter(Boolean).includes(url.origin);
  } catch { return false; }
}

/**
 * L'errore piu' silenzioso di questa architettura: l'issuer sbagliato.
 *
 * `OIDC_ISSUER` finisce nel claim `iss` di **ogni** token e i consumer lo
 * confrontano con il proprio. Se resta `localhost` mentre il frontend e' su
 * `streaming.oberdfr.top`, qui non si vede niente di rotto: la discovery
 * risponde, il login va, il token arriva — e il fallimento arriva
 * **dall'altra parte**, come 401 su ogni richiesta API, senza che nessuno
 * colleghi i due fatti.
 *
 * In produzione un issuer di loopback non ha senso (il browser non puo'
 * raggiungerlo da fuori, e il proxy non riuscirebbe a confrontarlo), quindi si
 * rifiuta di partire. Fuori produzione e' solo un avviso: in sviluppo
 * `localhost` e' la scelta giusta.
 *
 * Vive in `loadConfig()` e non in `server.ts` cosi' che **tutti** i punti
 * d'ingresso — servizio, CLI, migration — lo facciano rispettare.
 */
export function assertUsableIssuer(config: Pick<Config, 'issuer' | 'NODE_ENV'>): void {
  let host: string;
  try {
    host = new URL(config.issuer).hostname;
  } catch {
    return; // `loadConfig` ha gia' validato che sia una URL
  }
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  if (loopback && config.NODE_ENV === 'production') {
    throw new Error(
      `OIDC_ISSUER=${config.issuer} finisce nel claim iss di ogni token e i consumer lo ` +
        `confrontano. In produzione un issuer di loopback renderebbe invalido ogni token ` +
        `emesso (401 su ogni richiesta degli altri servizi). ` +
        `Imposta OIDC_ISSUER=https://<dominio>, per esempio https://account.oberdfr.top`,
    );
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  // La `DATABASE_URL` puo' arrivare compose gia' composta: in quel caso non
  // tocchiamo l'env, aggiungiamo solo il valore derivato a quanto c'e' gia'.
  const parsed = schema.safeParse(
    env.DATABASE_URL ? env : { ...env, DATABASE_URL: databaseUrlFromPostgresEnv(env) },
  );
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`);
    throw new Error(`configurazione non valida:\n${issues.join('\n')}`);
  }
  const raw = parsed.data;
  for (const client of raw.OIDC_CLIENTS_JSON) {
    if (client.backchannelEventsUri && !isAllowedBackchannelUri(client.backchannelEventsUri, raw.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) {
      throw new Error(`backchannelEventsUri non sicura per ${client.clientId}: HTTPS, loopback o origine HTTP interna autorizzata richiesti`);
    }
  }
  if (!raw.DATABASE_URL) {
    throw new Error(
      'configurazione non valida:\n  - DATABASE_URL: manca. Impostala, oppure fornisci POSTGRES_PASSWORD (e, se servono, POSTGRES_HOST/PORT/DB) per componderla dal .env',
    );
  }

  const port = raw.ENGINE_ACCOUNTS_PORT ?? raw.PORT;
  const issuer = raw.OIDC_ISSUER.replace(/\/+$/, '');
  const baseUrl = (raw.PUBLIC_BASE_URL ?? raw.OIDC_ISSUER).replace(/\/+$/, '');

  // Radice dei segreti derivati. In produzione OIDC_EVENT_SIGNING_SECRET e'
  // obbligatorio: e' il materiale condiviso col proxy per C11.
  let rootSecret: Buffer;
  if (raw.OIDC_EVENT_SIGNING_SECRET) {
    rootSecret = Buffer.from(raw.OIDC_EVENT_SIGNING_SECRET, 'utf8');
  } else if (raw.NODE_ENV === 'production') {
    throw new Error("OIDC_EVENT_SIGNING_SECRET e' obbligatorio in produzione");
  } else {
    rootSecret = crypto.randomBytes(32);
  }

  const eventSigningKey = hkdf(rootSecret, 'engine-accounts/backchannel-event-signing');
  const dataKey = raw.ENGINE_ACCOUNTS_DATA_KEY
    ? Buffer.from(raw.ENGINE_ACCOUNTS_DATA_KEY, 'utf8')
    : hkdf(rootSecret, 'engine-accounts/data-at-rest');
  const cookieSecret =
    raw.ENGINE_ACCOUNTS_COOKIE_SECRET ??
    (raw.NODE_ENV === 'production' ? null : hkdf(rootSecret, 'engine-accounts/cookie').toString('base64url'));
  if (!cookieSecret) {
    throw new Error("ENGINE_ACCOUNTS_COOKIE_SECRET e' obbligatorio in produzione");
  }

  const config: Config = {
    ...raw,
    port,
    issuer,
    baseUrl,
    eventSigningKey,
    dataKey,
    cookieSecret,
    // `Secure` sui cookie: in produzione (issuer https) obbligatorio.
    secureCookies: raw.COOKIE_SECURE ?? issuer.startsWith('https://'),
    // Il prefisso `__Host-` per RFC 6265bis ESIGE `Path=/`. Tuttavia, oidc-provider
    // imposta il cookie di resume (`ea_res`) con `path: /auth/<uid>` (scopato alla rotta di ripresa).
    // I browser rifiutano qualunque cookie `__Host-` il cui Path non sia esattamente `/`,
    // quindi con oidc-provider il prefisso `__Host-` fa fallire ogni login (`authorization request has expired`).
    // Di default resta spento anche su https. I cookie conservano comunque `Secure`, `HttpOnly`,
    // `SameSite=Lax` e natura host-only (nessun attributo Domain).
    cookiePrefix: raw.COOKIE_HOST_PREFIX ? '__Host-' : '',
    // HSTS: di default spento. Su un ambiente di sviluppo in http non ha
    // senso; in produzione va acceso esplicitamente, altrimenti ci si affida
    // solo al redirect del proxy e si perde la protezione al primo hop.
    hsts: {
      enabled: raw.HSTS_ENABLED ?? false,
      maxAge: raw.HSTS_MAX_AGE,
      includeSubDomains: raw.HSTS_INCLUDE_SUBDOMAINS,
    },
    argon2: {
      memoryCost: raw.ARGON2_MEMORY_KIB,
      timeCost: raw.ARGON2_ITERATIONS,
      parallelism: raw.ARGON2_PARALLELISM,
    },
  };
  assertUsableIssuer(config);
  return config;
}

let cached: Config | undefined;

/** Config di processo (memoizzata): usata da server e CLI. */
export function config(): Config {
  cached ??= loadConfig();
  return cached;
}
