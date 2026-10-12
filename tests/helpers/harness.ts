import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, type Config } from '../../src/config.js';
import { createDb, type Db } from '../../src/db/pool.js';
import { migrate } from '../../src/db/migrate.js';
import { createAccountsStore, createOidcTokenStore } from '../../src/db/repositories.js';
import { buildApp } from '../../src/app.js';
import { InMemoryMailer, type Mailer } from '../../src/services/mailer.js';
import { FixedBreachedChecker } from '../../src/security/breached-passwords.js';
import { RateLimiter } from '../../src/security/rate-limit.js';
import { hashPassword } from '../../src/security/password.js';
import { AccountService } from '../../src/services/account-service.js';
import { SessionManager } from '../../src/services/session-manager.js';
import { createAccountDeletedEmitter } from '../../src/services/account-deleted-event.js';
import { ChallengeStore } from '../../src/services/mfa.js';
import { nullLogger } from '../../src/logger.js';
import type { BuiltApp } from '../../src/app.js';
import type { ClientRecord } from '../../src/domain/types.js';

/**
 * Impalcatura per i test.
 *
 * Ogni suite parte da un database pulito ma non lo distrugge: lo schema
 * `engine_accounts` viene svuotato, il database resta. Le migration girano una
 * volta sola (advisory lock + versioning), quindi sono veloci anche ripetute.
 */

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** Client di test pubblico (SPA), registrato **via CLI** come da DoD. */
export const TEST_CLIENT_ID = 'streamingengine-web';
export const TEST_REDIRECT_URI = 'http://localhost:5173/auth/callback';
export const TEST_POST_LOGOUT_URI = 'http://localhost:5173/';
export const TEST_AUDIENCE = 'https://api.engine.local/streaming';

/** Client di test confidenziale: serve a provare `client_secret_basic`. */
export const CONF_CLIENT_ID = 'streamingengine-test-confidential';
export const CONF_CLIENT_SECRET = 'ea_test_confidential_secret_value_000000000000';

export function testEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    HOST: '127.0.0.1',
    // Postgres di sviluppo: lo schema dedicato tiene le tabelle separate
    // dal proxy, che lavora sullo stesso database.
    DATABASE_URL: process.env.DATABASE_URL ?? 'postgres://engine:engine_dev_password@127.0.0.1:55432/engine',
    DB_SCHEMA: process.env.DB_SCHEMA ?? 'engine_accounts_test',
    OIDC_ISSUER: 'http://127.0.0.1:8080',
    PUBLIC_BASE_URL: 'http://127.0.0.1:8080',
    OIDC_AUDIENCE: TEST_AUDIENCE,
    OIDC_EVENT_SIGNING_SECRET: 'test-event-signing-secret-non-production',
    MAIL_ENABLED: 'false',
    // Argon2 piu' leggero: i test fanno centinaia di hash, 64 MiB per hash
    // renderebbero la suite inutilizzabile. I parametri di produzione restano
    // quelli del `.env` e sono quelli documentati.
    ARGON2_MEMORY_KIB: '8192',
    ARGON2_ITERATIONS: '1',
    HTTP_LOGIN_SLOW_MS: '10',
    ENGINE_ACCOUNTS_JWKS_PATH: 'var/jwks-test.json',
    ...overrides,
  };
}

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig(testEnv(overrides));
}

export interface Harness extends BuiltApp {
  config: Config;
  db: Db;
  /**
   * Il mailer in uso. Di default `InMemoryMailer` (per leggere le email nei
   * test); una suite puo' passarne uno diverso, per provare cosa succede quando
   * la posta non funziona.
   */
  mailer: Mailer & Partial<InMemoryMailer>;
  challenges: ChallengeStore;
  /** Client pubblico registrato via CLI, presente nel database. */
  client: ClientRecord;
  baseUrl: string;
  close(): Promise<void>;
}

/**
 * Svuota le tabelle dello schema di test, senza toccare lo schema ne' i dati di
 * riferimento (`services`, `streaming_scopes`: i servizi e i loro scope sono
 * righe di configurazione, seminate dalla migration, e ogni suite deve trovarli).
 */
const KEEP_ROWS = new Set(['schema_migrations', 'services', 'streaming_scopes']);

export async function truncateAll(db: Db): Promise<void> {
  if (!db.schema.endsWith('_test')) throw new Error('Test cleanup requires a dedicated *_test schema');
  const rows = await db.query<{ tablename: string }>(
    `SELECT tablename FROM pg_tables WHERE schemaname = $1 AND tablename <> 'schema_migrations'`,
    [db.schema],
  );
  const list = rows
    .filter((r) => !KEEP_ROWS.has(r.tablename))
    .map((r) => `"${db.schema}"."${r.tablename}"`)
    .join(', ');
  if (list) await db.query(`TRUNCATE ${list} RESTART IDENTITY CASCADE`);
  await ensureReferenceData(db);
}

/**
 * Dati di riferimento (servizi e scope "di servizio"): li stesse righe della
 * migration `0002_clients.sql`, in forma idempotente. Servono perche' senza
 * scope di servizio non ci sarebbero client registrabili.
 */
export async function ensureReferenceData(db: Db): Promise<void> {
  await db.query(
    `INSERT INTO "${db.schema}"."services" (service_id, audience, name)
     VALUES ('streaming', $1, 'StreamingCommunityProxyApi')
     ON CONFLICT (service_id) DO NOTHING`,
    [TEST_AUDIENCE],
  );
  await db.query(
    `INSERT INTO "${db.schema}"."streaming_scopes" (scope, service_id, description) VALUES
       ('streaming:catalog',   'streaming', 'Catalogo, ricerca, metadati di catalogo'),
       ('streaming:playback', 'streaming', 'Avvio riproduzione di un titolo'),
       ('streaming:account',   'streaming', 'Dati utente (/v1/me/**)')
     ON CONFLICT (scope) DO NOTHING`,
  );
}

/**
 * Registra il client di test **chiamando la CLI in un processo separato**,
 * esattamente come farebbe un operatore. La DoD vuole la prova che il
 * percorso CLI funziona, non una sua ricostruzione in-process.
 */
export function registerTestClientViaCli(
  env: NodeJS.ProcessEnv,
  args: string[],
  extraEnv: Record<string, string> = {},
): { stdout: string; status: number } {
  try {
    const stdout = execFileSync('node', [path.join(REPO_ROOT, 'node_modules/tsx/dist/cli.mjs'), path.join(REPO_ROOT, 'src/cli/main.ts'), ...args], {
      env: { ...process.env, ...env, ...extraEnv },
      encoding: 'utf8',
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { stdout, status: 0 };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { stdout: `${e.stdout ?? ''}${e.stderr ?? ''}`, status: e.status ?? 1 };
  }
}

export async function setupHarness(options: { overrides?: Record<string, string>; mailer?: Mailer } = {}): Promise<Harness> {
  const config = testConfig(options.overrides);
  const db = createDb(config);
  await migrate(db);
  await truncateAll(db);

  const store = createAccountsStore(db);
  const tokens = createOidcTokenStore(db);
  const mailer = options.mailer ?? new InMemoryMailer();
  const limiter = new RateLimiter({
    ipMax: 1_000,
    ipWindowMs: 60_000,
    accountMax: 1_000,
    accountWindowMs: 60_000,
    lockBaseMs: 10,
    lockMaxMs: 100,
  });
  const breached = new FixedBreachedChecker(['passwordcompromessa123']);
  const events = createAccountDeletedEmitter(db, config);
  const accounts = new AccountService({ config, db, store, tokens, mailer, breached, limiter, events });
  const sessions = new SessionManager({ config, store, tokens });
  const challenges = new ChallengeStore();

  const built = await buildApp({
    config,
    db,
    logger: nullLogger,
    mailer,
    limiter,
    breachedChecker: breached,
  });

  // Client pubblico: registrato dalla CLI, non a mano.
  const env = testEnv(options.overrides);
  const result = registerTestClientViaCli(env, [
    'client',
    'add',
    TEST_CLIENT_ID,
    '--type',
    'public',
    '--redirect-uri',
    TEST_REDIRECT_URI,
    '--post-logout-uri',
    TEST_POST_LOGOUT_URI,
    '--scope',
    'openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account',
    '--audience',
    TEST_AUDIENCE,
  ]);
  if (result.status !== 0) {
    throw new Error(`registrazione client via CLI fallita: ${result.stdout}`);
  }

  // Client confidenziale: il secret resta un hash, ma il test deve poter
  // autenticarsi con il valore in chiaro.
  const secretHash = await hashPassword(CONF_CLIENT_SECRET, config);
  await store.upsertClient({
    clientId: CONF_CLIENT_ID,
    clientName: 'Test Confidential',
    clientType: 'confidential',
    clientSecretHash: secretHash,
    redirectUris: ['https://app.example.test/cb'],
    postLogoutRedirectUris: [],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scope: ['openid', 'profile', 'email', 'offline_access', 'streaming:catalog', 'streaming:account'],
    audience: TEST_AUDIENCE,
    backchannelEventsUri: null,
    tokenEndpointAuthMethod: 'client_secret_basic',
    enabled: true,
  });

  const client = (await store.findClient(TEST_CLIENT_ID))!;

  await built.app.listen({ port: 0, host: '127.0.0.1' });
  const address = built.app.server.address();
  const port = typeof address === 'object' && address ? address.port : 0;

  return {
    ...built,
    config,
    db,
    mailer,
    challenges,
    client,
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      await built.app.close();
      await db.close();
    },
  };
}

/* -------------------------------------------------------------------------- */
/* client HTTP con jar dei cookie                                               */
/* -------------------------------------------------------------------------- */

export class HttpClient {
  private readonly jar = new Map<string, string>();

  constructor(private readonly baseUrl: string) {}

  /** URL assoluto: l'issuer nei token e' `http://127.0.0.1:8080`, quindi i test
   * devono parlare con la porta 8080. `rebase` permette di redirigere il
   * traffico a una porta effimera mantenendo l'Host atteso dal provider. */
  withBaseUrl(baseUrl: string): HttpClient {
    const clone = new HttpClient(baseUrl);
    clone.jar.clear();
    return clone;
  }

  cookieHeader(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  /**
   * URL assoluta. I provider e la UI mandano `Location` ora assoluti ora
   * relativi: vanno risolti entrambi rispetto all'origine del server di test.
   */
  resolve(pathOrUrl: string): string {
    return new URL(pathOrUrl, this.baseUrl).toString();
  }

  clearCookies(): void {
    this.jar.clear();
  }

  setCookie(name: string, value: string): void {
    this.jar.set(name, value);
  }

  private captureCookies(res: Response): void {
    const raw = res.headers.getSetCookie?.() ?? [];
    for (const cookie of raw) {
      const [pair] = cookie.split(';');
      if (!pair) continue;
      const idx = pair.indexOf('=');
      if (idx === -1) continue;
      const name = pair.slice(0, idx).trim();
      const value = decodeURIComponent(pair.slice(idx + 1).trim());
      const expired = /expires=Thu, 01 Jan 1970/i.test(cookie);
      if (expired || value === '') this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  async request(pathOrUrl: string, init: RequestInit = {}): Promise<Response> {
    const url = this.resolve(pathOrUrl);
    const headers = new Headers(init.headers);
    if (this.jar.size && !headers.has('cookie')) headers.set('cookie', this.cookieHeader());
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    this.captureCookies(res);
    return res;
  }

  get(path: string, init: RequestInit = {}): Promise<Response> {
    return this.request(path, { ...init, method: 'GET' });
  }

  /** POST form-urlencoded con il token CSRF preso dalla pagina. */
  async postForm(path: string, fields: Record<string, string>, init: RequestInit = {}): Promise<Response> {
    const body = new URLSearchParams(fields).toString();
    return this.request(path, {
      ...init,
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(init.headers as Record<string, string> | undefined) },
      body,
    });
  }

  /** Legge il token CSRF dalla pagina (campo nascosto `_csrf`). */
  async csrfFrom(path: string): Promise<string> {
    const res = await this.get(path);
    const html = await res.text();
    const match = /name="_csrf" value="([^"]+)"/.exec(html);
    if (!match?.[1]) throw new Error(`token CSRF non trovato in ${path}`);
    return match[1];
  }
}

/* -------------------------------------------------------------------------- */
/* PKCE                                                                          */
/* -------------------------------------------------------------------------- */

export interface PkcePair {
  verifier: string;
  challenge: string;
  challengeMethod: 'S256' | 'plain';
}

export function pkce(method: 'S256' | 'plain' = 'S256'): PkcePair {
  const verifier = crypto.randomBytes(48).toString('base64url');
  if (method === 'plain') return { verifier, challenge: verifier, challengeMethod: 'plain' };
  return {
    verifier,
    challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    challengeMethod: 'S256',
  };
}

/** Crea un utente attivo e verificato, direttamente dal repository dei test. */
export async function createTestUser(
  harness: Pick<Harness, 'store'> | { store: ReturnType<typeof createAccountsStore> },
  options: { email?: string; password?: string; verified?: boolean } = {},
): Promise<{ id: string; email: string; password: string }> {
  const email = options.email ?? `utente-${crypto.randomBytes(4).toString('hex')}@example.test`;
  const password = options.password ?? 'PasswordLungaCheNonEsiste123!';
  const user = await harness.store.createUser({
    email,
    passwordHash: await hashPassword(password, {
      PASSWORD_MAX_LENGTH: 1024,
      PASSWORD_MIN_LENGTH: 12,
      ARGON2_MEMORY_KIB: 8192,
      ARGON2_ITERATIONS: 1,
      ARGON2_PARALLELISM: 1,
    } as never),
    displayName: 'Utente di Test',
    emailVerifiedAt: options.verified === false ? null : new Date(),
  });
  return { id: user.id, email, password };
}
