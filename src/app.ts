import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import fastifyStatic from '@fastify/static';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Provider } from 'oidc-provider';
import type { Config } from './config.js';
import type { Db } from './db/pool.js';
import { createAccountsStore, createOidcTokenStore } from './db/repositories.js';
import { applySecurityHeaders, flushReplyHeadersToRaw, redirectOriginsOf, redirectFormActionsOf } from './security/headers.js';
import { csrfCookieName, isCsrfProtected, CSRF_FIELD } from './security/csrf.js';
import { activePublicJwks, buildProvider } from './oidc/provider.js';
import { registerUserinfoRoute } from './oidc/userinfo.js';
import { AccountService } from './services/account-service.js';
import { SessionManager } from './services/session-manager.js';
import { createAccountDeletedEmitter } from './services/account-deleted-event.js';
import { mailerFromConfig, type Mailer } from './services/mailer.js';
import { PwnedPasswordChecker, type BreachedChecker } from './security/breached-passwords.js';
import { rateLimiterFromEnv, type RateLimiter } from './security/rate-limit.js';
import { argonFromConfig } from './security/argon.js';
import { ChallengeStore } from './services/mfa.js';
import { registerUiRoutes } from './ui/ui-routes.js';
import { registerAccountRoutes } from './ui/account-routes.js';
import { registerAdminRoutes, type AdministrationUI } from './ui/admin-routes.js';
import { AdministrationService, type AccountAction, type AccountFilters, type AuditFilters } from './services/administration.js';
import { registerServiceAuthzRoute, serviceAuthorizationFromAdministration } from './services/service-authz.js';
import { layout } from './ui/layout.js';
import type { Logger } from './logger.js';
import { createLogger, nullLogger } from './logger.js';

/**
 * Composizione dell'app.
 *
 * Fastify fa da scheletro HTTP; il provider OIDC e' un middleware Koa montato
 * sotto lo stesso origin — l'obbligo del contratto ("la UI e' nostra ma serve
 * dallo stesso origin del provider") e' anche un requisito tecnico: niente
 * redirect su un altro host per la sessione di login.
 */

/**
 * Directory degli asset statici. Funziona sia in sviluppo (`src/ui/static`,
 * via tsx) sia da `dist` (dove `scripts/copy-assets.mjs` li replica).
 */
function resolveStaticDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, 'ui/static'),
    path.resolve(here, '../src/ui/static'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return candidates[0]!;
}

/**
 * Endpoint gestiti dalla libreria.
 *
 * I path sono gia' quelli del contratto: li dichiariamo in `oidc/provider.ts`
 * (`routes`), quindi la discovery li annuncia corretti. Qui elenchiamo i
 * percorsi che Fastify deve cedere al provider, piu' i suoi interni
 * (resume, interazione, challenge del device flow disabilitato ma mappato).
 */
const OIDC_ROUTES = [
  '/auth',
  '/token',
  '/introspect',
  '/revoke',
  '/end-session',
  '/jwks',
  '/device',
] as const;

/**
 * `/userinfo` e' **nostro** (vedi `oidc/userinfo.ts`): la libreria rifiuta i
 * token con `aud`, che il contratto §5 impone. Resta fuori dalla lista perche'
 * Fastify lo serva, non la libreria — ma il path e' quello del contratto e la
 * discovery lo annuncia correttamente.
 */
const OIDC_ROUTES_OWNED_BY_FASTIFY = new Set<string>(['/userinfo']);

const OIDC_WELL_KNOWN = [
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
] as const;

/** Percorsi gestiti dalla libreria: la nostra UI non li tocca. */
const OIDC_PATHS = new Set<string>([
  ...OIDC_ROUTES,
  ...OIDC_WELL_KNOWN,
  '/interaction',
  '/resume',
  '/session',
  '/grant',
  '/me',
  '/reg',
  '/challenge',
  '/backchannel',
  '/request',
  '/credential',
  ...OIDC_ROUTES_OWNED_BY_FASTIFY,
]);

/** Anche le sotto-rotte con parametro (`/auth/:uid`, `/interaction/:uid/...`). */
function isOIDCPath(path: string): boolean {
  if (OIDC_PATHS.has(path)) return true;
  for (const known of OIDC_PATHS) {
    if (path.startsWith(`${known}/`)) return true;
  }
  return false;
}

export interface BuildAppOptions {
  config: Config;
  db: Db;
  logger?: Logger;
  mailer?: Mailer;
  breachedChecker?: BreachedChecker;
  limiter?: RateLimiter;
  /** Provider gia' costruito (test). */
  provider?: Provider;
}

export interface BuiltApp {
  app: FastifyInstance;
  provider: Provider;
  sessions: SessionManager;
  accounts: AccountService;
  store: ReturnType<typeof createAccountsStore>;
  tokens: ReturnType<typeof createOidcTokenStore>;
  limiter: RateLimiter;
}

export async function buildApp(options: BuildAppOptions): Promise<BuiltApp> {
  const { config, db } = options;
  const logger =
    options.logger ??
    (config.LOG_LEVEL === 'silent' ? nullLogger : createLogger(config.LOG_LEVEL, { svc: 'engine-accounts' }));

  const store = createAccountsStore(db);
  const tokens = createOidcTokenStore(db);
  const limiter = options.limiter ?? rateLimiterFromEnv(config);
  const mailer = mailerFromConfig(config, options.mailer);
  const breachedChecker =
    options.breachedChecker ??
    new PwnedPasswordChecker({
      enabled: config.HIBP_ENABLED,
      apiBase: config.HIBP_API_BASE,
      timeoutMs: config.HIBP_TIMEOUT_MS,
      cacheTtlMs: config.HIBP_CACHE_TTL_MS,
    });
  const events = createAccountDeletedEmitter(db, config);

  const accounts = new AccountService({ config, db, store, tokens, mailer, breached: breachedChecker, limiter, events });
  const sessions = new SessionManager({ config, store, tokens, db });
  const administration = new AdministrationService({ db, config, store, tokens, sessions });
  const authorization = serviceAuthorizationFromAdministration(administration);
  const challenges = new ChallengeStore();

  const app = Fastify({
    logger: false,
    // Il body dei form e' minuscolo; i limiti sono una barriera anti-DoS.
    bodyLimit: 128 * 1024,
    trustProxy: config.TRUST_PROXY,
    routerOptions: {
      // I nomi di campo del provider includono puntini: niente annidamento.
      caseSensitive: true,
      ignoreTrailingSlash: true,
    },
  });
  // Durable retries run only in a running non-test application. Consumer jti
  // deduplication also protects against another instance attempting delivery.
  let outboxTimer: ReturnType<typeof setInterval> | undefined;
  let flushingOutbox = false;
  app.addHook('onReady', async () => {
    if (config.NODE_ENV === 'test') return;
    outboxTimer = setInterval(async () => {
      if (flushingOutbox) return;
      flushingOutbox = true;
      try { await events.flushPending(20); }
      catch { logger.warn('retry outbox non disponibile'); }
      finally { flushingOutbox = false; }
    }, 30_000);
    outboxTimer.unref();
  });
  app.addHook('onClose', async () => { if (outboxTimer) clearInterval(outboxTimer); });
  app.addHook('onResponse', async (request, reply) => {
    const pathname = (request.raw.url ?? '').split('?')[0] ?? '';
    if (request.method !== 'POST' || !pathname.startsWith('/admin/') || reply.statusCode < 400) return;
    const { sessionCookieName } = await import('./services/session-manager.js');
    const active = await sessions.resolve(request.cookies?.[sessionCookieName(config)]);
    await store.appendAudit({ actor: active ? `admin:${active.user.id}` : 'anonymous',
      userId: active?.user.id ?? null, event: 'admin.request.rejected',
      outcome: reply.statusCode >= 500 ? 'failure' : 'denied', ip: request.ip, metadata: {} });
  });

  await app.register(cookie, { secret: config.cookieSecret });
  await app.register(formbody, { bodyLimit: 64 * 1024 });
  await app.register(fastifyStatic, {
    root: resolveStaticDir(),
    prefix: '/static/',
    decorateReply: false,
    maxAge: 3600_000,
  });
  // `tsx` serves src/static; fonts live in fontsource until the build copies
  // them into dist. A strict two-file route keeps development local too.
  if (config.NODE_ENV !== 'production') {
    app.get('/static/fonts/:font/:file', async (request, reply) => {
      const { font, file } = request.params as { font: string; file: string };
      if (!['geist', 'inter'].includes(font) || file !== `${font}-latin-wght-normal.woff2`) return reply.code(404).send();
      const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../node_modules/@fontsource-variable');
      try { return reply.type('font/woff2').header('Cache-Control', 'public, max-age=3600').send(await readFile(path.join(root, font, 'files', file))); }
      catch { return reply.code(404).send(); }
    });
  }

  /*
   * Origini autorizzate in `form-action` sulle pagine del flusso di
   * autorizzazione: sono le origini dei `redirect_uri` dei client registrati, e
   * nulla altro. Servono perche' un form che avvia la navigazione e' vincolato da
   * `form-action` per **tutta** la catena di redirect, e quella catena termina
   * dal lato del client: con `form-action 'self'` il browser blocca la
   * navigazione e l'utente resta fermo sulla pagina di consenso, senza che
   * niente sul server segnali un errore. Dettaglio in `security/headers.ts`.
   *
   * Le origini non sono congelate all'avvio: i client si registrano con la CLI,
   * che e' un processo separato, e una lista memorizzata farebbe fallire il
   * login di un client appena registrato fino al prossimo riavvio — cioe'
   * esattamente il difetto che questa allowlist risolve. Si rileggono dal
   * database, e solo dalle richieste che ne hanno bisogno.
   *
   * Le pagine che non sono di interazione restano con `'self'` e basta: non
   * escono mai dall'origine, e non serve allargare la loro politica.
   */
  const clientOrigins = async (): Promise<string[]> => redirectOriginsOf(await store.listClients());

  // Header di sicurezza su tutto, CSP inclusa.
  app.addHook('onRequest', async (request, reply) => {
    const path = (request.raw.url ?? '/').split('?')[0] ?? '/';
    const isPage = request.method === 'GET' && (path.startsWith('/ui/') || path.startsWith('/account') || path.startsWith('/admin') || path === '/');
    applySecurityHeaders(request, reply, {
      isPage,
      hsts: config.hsts,
      formActionOrigins: path.startsWith('/ui/interaction/') ? redirectFormActionsOf(await store.listClients()) : [],
    });
    if (request.method !== 'GET' && request.method !== 'HEAD' && !isOIDCPath(path)) {
      reply.header('Cache-Control', 'no-store');
    }
  });

  // CSRF su tutti i POST della UI (vedi security/csrf.ts).
  app.addHook('preValidation', async (request, reply) => {
    const path = (request.raw.url ?? '/').split('?')[0] ?? '/';
    if (!isCsrfProtected(request.method, request.raw.url ?? path)) return;
    if (path === '/admin' || path.startsWith('/admin/')) {
      const { sessionCookieName } = await import('./services/session-manager.js');
      const active = await sessions.resolve(request.cookies?.[sessionCookieName(config)]);
      const serviceId = (request.params as { serviceId?: string } | undefined)?.serviceId;
      const authorized = active && (await administration.isGlobalAdmin(active.user.id) ||
        (serviceId && (await administration.authorization(active.user.id, serviceId)).admin));
      if (!authorized) return reply.code(404).send({ error: 'not_found' });
    }
    const cookieValue = request.cookies?.[csrfCookieName(config.cookiePrefix)];
    const body = request.body as Record<string, unknown> | undefined;
    const { verifyCsrfToken } = await import('./security/csrf.js');
    const submitted = body?.[CSRF_FIELD] ?? request.headers['x-csrf-token'];
    if (!verifyCsrfToken(typeof cookieValue === 'string' ? cookieValue : undefined, submitted)) {
      logger.warn('controllo CSRF fallito', {
        path,
      });
      return reply.code(403).type('text/html; charset=utf-8').send(
        layout({
          title: 'Errore',
          body:
            '<h1>Richiesta non valida</h1><p class="lede">Token di sicurezza mancante o scaduto: ricarica la pagina.</p>',
        }),
      );
    }
  });

  /* --- provider OIDC ---------------------------------------------------- */

  const provider =
    options.provider ??
    (await buildProvider({ config, db, store, tokens, argon: argonFromConfig(config), authorization }));

  /*
   * Montaggio del provider.
   *
   * `oidc-provider` e' un'app Koa. Fastify non ha un adapter Koa, quindi
   * **rubiamo** la richiesta (`reply.hijack()`) per i soli percorsi OIDC e
   * passiamo `req`/`res` grezzi alla libreria. Il risultato: un solo server,
   * un solo origin — la sessione di login non attraversa mai un altro host, che
   * e' quanto chiede il contratto.
   *
   * Gli alias del contratto (`/introspect`, `/revoke`, `/end-session`,
   * `/userinfo`) riscrivono `req.url` sul path nativo prima di passare il
   * controllo: la libreria continua a vederli come se fossero suoi.
   */
  const oidcHandler = provider.callback();
  // Il contratto chiede `/.well-known/jwks.json` come alias di `/jwks`: la
  // libreria espone solo il path nativo, quindi riscriviamo l'URL.
  const aliasMap = new Map<string, string>([[`/.well-known/jwks.json`, '/jwks']]);

  app.addHook('onRequest', async (request, reply) => {
    const rawUrl = request.raw.url ?? '/';
    const path = rawUrl.split('?')[0] ?? '/';
    const native = aliasMap.get(path);
    // `/userinfo` e' nostro: non lo rubiamo alla libreria.
    if (OIDC_ROUTES_OWNED_BY_FASTIFY.has(path)) return;
    if (!native && !isOIDCPath(path)) return;
    // Le richieste che la nostra UI gestisce non arrivano mai qui: `/ui/*` e
    // `/account/*` non sono in OIDC_PATHS.
    reply.hijack();
    request.raw.url = native ? `${native}${rawUrl.slice(path.length)}` : rawUrl;
    // Le rotte del provider scrivono direttamente su `reply.raw`: senza questo
    // passaggio CSP, `nosniff` e `Referrer-Policy` non arriverebbero mai su
    // `/auth`, `/token`, `/jwks`, `/introspect` e discovery.
    flushReplyHeadersToRaw(reply);
    try {
      await oidcHandler(request.raw, reply.raw);
    } catch (err) {
      logger.error('errore nel middleware OIDC', { err: (err as Error).message, path });
      if (!reply.raw.headersSent) {
        reply.raw.statusCode = 500;
        reply.raw.setHeader('content-type', 'application/json; charset=utf-8');
      }
      reply.raw.end(JSON.stringify({ error: 'server_error' }));
    }
  });

  /* --- rotte nostre ------------------------------------------------------ */

  app.get('/', async (request, reply) => {
    const { sessionCookieName } = await import('./services/session-manager.js');
    const active = await sessions.resolve(request.cookies?.[sessionCookieName(config)]);
    if (active) return reply.redirect('/account', 303);
    return reply.type('text/html; charset=utf-8').send(
      layout({
        title: 'Benvenuto',
        body: `<section class="welcome panel"><p class="eyebrow">LA SUITE ENGINE · IDENTITÀ</p><h1>Il tuo account.<br>Un unico posto.</h1>
<p class="lede">Profilo, accessi e sicurezza dei tuoi servizi Engine. Il controllo resta nelle tue mani.</p>
<div class="row"><a class="button primary" href="/ui/login">Accedi al tuo account</a><a class="button secondary" href="/ui/register">Crea un account</a></div>
<p class="hint">Se amministri Engine o uno dei suoi servizi, troverai i pannelli autorizzati dopo l’accesso.</p></section>`,
      }),
    );
  });

  app.get('/healthz', async (_request, reply) => reply.send({ status: 'ok', service: 'engine-accounts' }));

  app.get('/readyz', async (_request, reply) => {
    try {
      await db.query('SELECT 1');
      return reply.send({ status: 'ready' });
    } catch (err) {
      return reply.code(503).send({ status: 'unavailable', error: (err as Error).message });
    }
  });

  registerUserinfoRoute(app, { config, store, jwks: () => activePublicJwks(config), allowedOrigins: clientOrigins });
  await registerUiRoutes(app, { config, store, tokens, accounts, sessions, provider, challenges });
  await registerAccountRoutes(app, { config, store, accounts, sessions, challenges, admin: administration, tokens });
  await registerServiceAuthzRoute(app, { store, argon: argonFromConfig(config), limiter, authorization });
  // Adapt form-boundary values to the service's validated domain types.
  const admin: AdministrationUI = {
    isGlobalAdmin: (sub) => administration.isGlobalAdmin(sub),
    authorization: async (sub, serviceId) => {
      const result = await administration.authorization(sub, serviceId);
      return { ...result, status: result.status ?? 'deleted' };
    },
    listServices: () => administration.listServices(),
    findService: (id) => administration.findService(id),
    assignments: (id) => administration.assignments(id),
    accounts: (filters) => administration.accounts(filters as AccountFilters),
    accountDetail: (sub) => administration.accountDetail(sub),
    mutateAccount: (actor, target, action, opts, context) => administration.mutateAccount(actor, target, action as AccountAction, opts, context),
    setServiceEnabled: (actor, id, enabled, context) => administration.setServiceEnabled(actor, id, enabled, context),
    grant: (actor, id, target, context) => administration.grant(actor, id, target, context),
    revoke: (actor, id, target, context) => administration.revoke(actor, id, target, context),
    setGlobalRole: (actor, target, enabled, options) => administration.setGlobalRole(actor, target, enabled, options),
    listAudit: (filters) => administration.listAudit(filters as AuditFilters),
    getSettings: () => administration.getSettings(),
    setSetting: (actor, key, value, context) => administration.setSetting(actor, key,
      typeof value !== 'string' ? value : ['EMAIL_VERIFICATION_REQUIRED', 'TOTP_REQUIRED', 'ADMIN_MFA_REQUIRED'].includes(key)
        ? value === 'true' : key === 'REGISTRATION_MODE' ? value : Number(value), context),
    diagnostics: () => administration.diagnostics(),
  };
  await registerAdminRoutes(app, { config, store, accounts, sessions, admin,
    purge: async (actor, sub, serviceId, context) => {
      const service = await administration.findService(serviceId);
      if (!service?.enabled || !service.adminApiUrl) throw Object.assign(new Error('not_found'), { statusCode: 404 });
      return administration.mutateAccount(actor, sub, 'purge', { serviceId,
        purge: () => events.emitDataPurge(sub, service) }, context);
    },
  });

  app.setNotFoundHandler((request, reply) => {
    const path = (request.raw.url ?? '/').split('?')[0] ?? '/';
    if (isOIDCPath(path)) {
      // Percorso del provider che non ha rotta: errore JSON, non HTML.
      return reply
        .code(404)
        .type('application/json')
        .send({ error: 'not_found', error_description: 'endpoint inesistente' });
    }
    return reply
      .code(404)
      .type('text/html; charset=utf-8')
      .send(
        layout({
          title: 'Non trovato',
          body: '<h1>Non trovato</h1><p class="lede">Questa pagina non esiste.</p><p><a href="/">Torna all\'inizio</a></p>',
        }),
      );
  });

  app.setErrorHandler((error: unknown, request, reply) => {
    const status = typeof (error as { statusCode?: number }).statusCode === 'number' ? (error as { statusCode: number }).statusCode : 500;
    const message = error instanceof Error ? error.message : 'errore sconosciuto';
    if (status >= 500) {
      logger.error('errore non gestito', { err: message, path: (request.raw.url ?? '').split('?')[0] });
    }
    const path = (request.raw.url ?? '/').split('?')[0] ?? '/';
    if (path.startsWith('/account') || path.startsWith('/ui/') || path.startsWith('/admin')) {
      // HTML per la nostra UI, senza dettagli interni nel messaggio.
      return reply
        .code(status)
        .type('text/html; charset=utf-8')
        .send(
          layout({
            title: 'Errore',
            body: "<h1>Qualcosa e' andato storto</h1><p class=\"lede\">Riprova. Se persiste, torna al pannello dell'account.</p><p><a href=\"/account\">Account</a></p>",
          }),
        );
    }
    return reply.code(status).type('application/json').send({
      error: status >= 500 ? 'server_error' : 'invalid_request',
      error_description: status >= 500 ? 'errore interno' : message,
    });
  });

  return { app, provider, sessions, accounts, store, tokens, limiter };
}
