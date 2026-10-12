import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { errors, type Provider } from 'oidc-provider';
import type { Config } from '../config.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import type { Amr, ScopeRecord } from '../domain/types.js';
import type { AccountService } from '../services/account-service.js';
import { CORE_SCOPES } from '../oidc/account-adapter.js';
import { holdFor, markStart, NEUTRAL_LOGIN } from '../security/timing.js';
import { flushReplyHeadersToRaw } from '../security/headers.js';
import { CSRF_FIELD, csrfCookieName, issueCsrfToken, verifyCsrfToken } from '../security/csrf.js';
import { hkdf } from '../config.js';
import {
  completeWebauthnRegistration,
  consumeRecoveryCode,
  verifyTotpForUser,
  webauthnAuthenticationOptions,
  webauthnRegistrationOptions,
  verifyWebauthnAuthentication,
  type ChallengeStore,
} from '../services/mfa.js';
import { providerSessionCookieName, sessionCookieName, type SessionManager } from '../services/session-manager.js';
import * as pages from '../ui/pages.js';
import { esc, layout, field } from '../ui/layout.js';
import crypto from 'node:crypto';
import { rateLimiterFromEnv } from '../security/rate-limit.js';

/**
 * UI di interazione (`/ui/*`): login, registrazione, verifica, reset, codice
 * monouso, secondo fattore, consenso.
 *
 * Il flusso OIDC reale:
 *   /auth -> provider -> redirect a /ui/interaction/:uid
 *          -> noi chiediamo le credenziali (o il secondo fattore)
 *          -> provider.interactionFinished(req, res, { login: { accountId } })
 *          -> il provider riprende e chiede il consenso
 *          -> noi confermiamo, lui emette il code.
 *
 * `interactionFinished` riceve le `req`/`res` **grezze**: e' cosi' che la libreria
 * possa scrivere i suoi cookie e fare il redirect.
 */

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verifica la tua identita\'',
  profile: 'Nome visualizzato',
  email: 'Il tuo indirizzo email',
  offline_access: 'Accesso continuo senza reinserire la password',
  'engine:admin': 'Verifica il ruolo amministrativo per questo servizio',
};

/** `resource` puo' arrivare una o piu' volte: la libreria lo tiene come lista. */
function resourceIndicators(value: string | undefined): string[] {
  if (!value) return [];
  return value.split(' ').filter(Boolean);
}

/** Nomi di tutti i claim richiesti col parametro `claims` (RFC 9068). */
function claimsFromParams(raw: string | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as Record<string, Record<string, unknown> | undefined>;
    const names = new Set<string>();
    for (const perUse of Object.values(parsed)) {
      for (const name of Object.keys(perUse ?? {})) names.add(name);
    }
    return [...names];
  } catch {
    // Un `claims` malformato l'ha gia' rifiutato la libreria prima di arrivare
    // qui: nessun claim da registrare.
    return [];
  }
}

export interface UiDeps {
  config: Config;
  store: AccountsStore;
  tokens: OidcTokenStore;
  accounts: AccountService;
  sessions: SessionManager;
  provider: Provider;
  challenges: ChallengeStore;
}

export async function registerUiRoutes(app: FastifyInstance, deps: UiDeps): Promise<void> {
  const { config, store, accounts, sessions, provider, challenges } = deps;
  const recoveryKey = hkdf(config.dataKey, 'engine-accounts/recovery-codes');
  let serviceScopes: ScopeRecord[] = await store.listServiceScopes();

  /** Descrizioni degli scope per la pagina di consenso. */
  function scopeCatalog(): Map<string, string> {
    const map = new Map<string, string>(Object.entries(SCOPE_DESCRIPTIONS));
    for (const scope of serviceScopes) map.set(scope.scope, scope.description);
    return map;
  }

  const csrfCookie = csrfCookieName(config.cookiePrefix);
  const sessionCookie = sessionCookieName(config);
  const providerCookie = providerSessionCookieName(config);
  const pendingCookie = `${config.cookiePrefix}ea_pending`;
  const passkeyCookie = `${config.cookiePrefix}ea_passkey`;
  const flowLimiter = rateLimiterFromEnv(config);
  type PendingLogin = { accountId: string; amr: Amr[] };

  function savePending(key: string, pending: PendingLogin): void {
    challenges.set(key, { kind: 'totp', value: JSON.stringify(pending), createdAt: Date.now() });
  }
  function readPending(key: string): PendingLogin | undefined {
    const item = challenges.get(key);
    if (!item) return undefined;
    if (Date.now() - item.createdAt > 300_000) { challenges.delete(key); return undefined; }
    try { return JSON.parse(item.value) as PendingLogin; } catch { return undefined; }
  }
  function standaloneKey(request: FastifyRequest): string | undefined {
    const cookie = request.cookies?.[pendingCookie];
    return cookie && /^[a-zA-Z0-9_-]{43}$/.test(cookie) ? `account-login:${cookie}` : undefined;
  }
  function beginStandalone(reply: FastifyReply, pending: PendingLogin): void {
    const opaque = crypto.randomBytes(32).toString('base64url');
    savePending(`account-login:${opaque}`, pending);
    reply.setCookie(pendingCookie, opaque, { ...sessions.cookieOptions(), maxAge: 300 });
  }
  function forcePage(request: FastifyRequest, reply: FastifyReply, action: string, message?: string) {
    return reply.header('Cache-Control', 'no-store').type('text/html; charset=utf-8').send(layout({
      title: 'Aggiorna la password', body: `<h1>Aggiorna la password</h1><p>Prima di continuare devi scegliere una nuova password.</p>
      ${message ? `<p role="alert">${esc(message)}</p>` : ''}
      <form class="stack" method="post" action="${esc(action)}"><input type="hidden" name="${CSRF_FIELD}" value="${esc(ensureCsrf(request, reply))}">
      ${field({ name: 'currentPassword', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
      ${field({ name: 'newPassword', label: 'Nuova password', type: 'password', autocomplete: 'new-password', required: true, error: message })}
      ${field({ name: 'confirm', label: 'Conferma nuova password', type: 'password', autocomplete: 'new-password', required: true })}
      <button class="primary" type="submit">Aggiorna e continua</button></form>`,
    }));
  }
  async function completeStandalone(request: FastifyRequest, reply: FastifyReply, pending: PendingLogin): Promise<FastifyReply> {
    const user = await store.findUserById(pending.accountId);
    if (!user || user.status !== 'active') return reply.redirect('/ui/login', 303);
    const settings = await accounts.effectivePolicy();
    if (settings.EMAIL_VERIFICATION_REQUIRED && !user.emailVerifiedAt) return reply.code(403).send({ error: 'email_verification_required' });
    if (user.mustChangePassword) {
      beginStandalone(reply, pending);
      return reply.redirect('/ui/force-password-change', 303);
    }
    if (user.totpEnabled && !pending.amr.some((m) => ['otp', 'webauthn', 'recovery_code'].includes(m))) {
      beginStandalone(reply, pending);
      return reply.redirect('/ui/mfa', 303);
    }
    // Repeating standalone login in an authenticated browser need not leave
    // another orphaned credential. Never apply this to finishLogin/OIDC linkage.
    const reusable = await sessions.reusableStandalone(request.cookies?.[sessionCookie], user.id, pending.amr);
    const created = reusable ? undefined : await sessions.create({ userId: user.id, amr: pending.amr, ...ctx(request) });
    await accounts.onLoginSucceeded(user, pending.amr, ctx(request));
    if (created) reply.setCookie(sessionCookie, created.cookieValue, { ...sessions.cookieOptions(), maxAge: Math.floor((created.record.expiresAt.getTime() - Date.now()) / 1000) });
    const key = standaloneKey(request);
    if (key) challenges.delete(key);
    reply.clearCookie(pendingCookie, sessions.cookieOptions());
    return reply.redirect(settings.TOTP_REQUIRED && !user.totpEnabled ? '/account/security/totp/setup' : '/account', 303);
  }

  async function standalonePending(request: FastifyRequest): Promise<PendingLogin | undefined> {
    const key = standaloneKey(request);
    const pending = key ? readPending(key) : undefined;
    if (pending) return pending;
    const active = await activeSession(request);
    return active ? { accountId: active.user.id, amr: active.session.amr as Amr[] } : undefined;
  }

  for (const action of ['/ui/force-password-change', '/ui/interaction/:uid/force-password-change']) {
    const interactionFlow = action.includes(':uid');
    const getPending = async (request: FastifyRequest, reply: FastifyReply) => {
      if (!interactionFlow) return standalonePending(request);
      const { uid } = request.params as { uid: string };
      const details = await safeDetails(request, reply, provider);
      if (!details || details.uid !== uid) return undefined;
      const saved = readPending(`force:${uid}`);
      if (saved) return saved;
      const active = await activeSession(request);
      return active ? { accountId: active.user.id, amr: active.session.amr as Amr[] } : undefined;
    };
    app.get(action, async (request, reply) => {
      const pending = await getPending(request, reply);
      const user = pending ? await store.findUserById(pending.accountId) : undefined;
      if (!user || user.status !== 'active') return reply.redirect('/ui/login', 303);
      return forcePage(request, reply, interactionFlow ? `/ui/interaction/${(request.params as { uid: string }).uid}/force-password-change` : action);
    });
    app.post(action, async (request, reply) => {
      if (!checkCsrf(request)) return csrfFailure(reply);
      const rate = flowLimiter.checkIp(`force:${request.ip}`, 10, 60_000);
      if (!rate.allowed) return reply.code(429).header('Retry-After', rate.retryAfterSeconds).send({ error: 'rate_limited' });
      const pending = await getPending(request, reply);
      if (!pending) return reply.redirect('/ui/login', 303);
      const body = (request.body ?? {}) as Record<string, unknown>;
      const uid = interactionFlow ? (request.params as { uid: string }).uid : '';
      const target = interactionFlow ? `/ui/interaction/${uid}/force-password-change` : action;
      if (typeof body.newPassword !== 'string' || body.newPassword !== body.confirm) {
        reply.code(400); return forcePage(request, reply, target, 'Le due password non coincidono.');
      }
      const result = await accounts.changePassword(pending.accountId, String(body.currentPassword ?? ''), body.newPassword, ctx(request));
      if (!result.ok) { reply.code(400); return forcePage(request, reply, target, result.message); }
      if (!interactionFlow) return completeStandalone(request, reply, pending);
      challenges.delete(`force:${uid}`);
      const user = await store.findUserById(pending.accountId);
      if (user?.totpEnabled && !pending.amr.some((m) => ['otp', 'webauthn', 'recovery_code'].includes(m))) {
        challenges.set(`interaction:${uid}`, { kind: 'totp', value: user.id, createdAt: Date.now() });
        return reply.redirect(`/ui/interaction/${uid}/mfa?method=totp`, 303);
      }
      return finishLogin(request, reply, pending.accountId, pending.amr);
    });
  }

  app.get('/ui/mfa', async (request, reply) => {
    const key = standaloneKey(request);
    if (!key || !readPending(key)) return reply.redirect('/ui/login', 303);
    const method = (request.query as { method?: string })?.method ?? 'totp';
    const usePasskey = method === 'webauthn';
    return reply.header('Cache-Control', 'no-store').type('text/html; charset=utf-8').send(layout({ title: 'Secondo fattore', flash: (request.query as { error?: string }).error ? { kind: 'error', text: 'Verifica non riuscita. Usa un codice valido o riprova con la passkey. Nessun accesso è stato completato.' } : undefined, body:
      `<p class="eyebrow">VERIFICA IDENTITÀ</p><h1>Un ultimo passaggio.</h1><p class="lede">${usePasskey ? 'Conferma l’accesso con la tua passkey.' : method === 'recovery' ? 'Inserisci uno dei codici di recupero che hai conservato. Ogni codice è utilizzabile una sola volta.' : 'Inserisci il codice a sei cifre della tua app di autenticazione.'}</p><form id="mfa-form" class="stack" method="post" action="/ui/mfa"><input type="hidden" name="${CSRF_FIELD}" value="${esc(ensureCsrf(request, reply))}"><input type="hidden" name="method" value="${usePasskey ? 'webauthn' : method === 'recovery' ? 'recovery' : 'totp'}">${usePasskey ? '<div data-webauthn="auth" data-webauthn-options="/ui/mfa/options"><p id="wa-status" role="status">Premi Continua e segui le istruzioni del dispositivo.</p></div><input type="hidden" name="webauthnResponse"><noscript><p class="warning">Le passkey richiedono JavaScript. Puoi usare TOTP o un codice di recupero.</p></noscript>' : field({ name: 'code', label: method === 'recovery' ? 'Codice di recupero' : 'Codice a sei cifre', autocomplete: 'one-time-code', inputmode: method === 'recovery' ? 'text' : 'numeric', required: true })}<button class="primary" type="submit">Continua</button></form><nav class="links"><a href="/ui/mfa?method=totp">Usa TOTP</a><a href="/ui/mfa?method=recovery">Usa un codice di recupero</a><a href="/ui/mfa?method=webauthn">Usa una passkey</a></nav>` }));
  });
  app.get('/ui/mfa/options', async (request, reply) => {
    const key = standaloneKey(request);
    const pending = key ? readPending(key) : undefined;
    if (!pending) return reply.code(401).send({ error: 'login_required' });
    const credentials = await store.listWebauthnCredentials(pending.accountId);
    if (!credentials.length) return reply.code(400).send({ error: 'no_passkeys' });
    const options = await webauthnAuthenticationOptions(config, credentials);
    challenges.set(`webauthn:${key}`, { kind: 'webauthn', value: options.challenge, createdAt: Date.now() });
    return reply.header('Cache-Control', 'no-store').send(options);
  });
  app.post('/ui/mfa', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const key = standaloneKey(request);
    const pending = key ? readPending(key) : undefined;
    if (!pending) return reply.redirect('/ui/login', 303);
    const rate = flowLimiter.checkIp(`mfa:${request.ip}`, 10, 60_000);
    if (!rate.allowed) return reply.code(429).header('Retry-After', rate.retryAfterSeconds).send({ error: 'rate_limited' });
    const body = (request.body ?? {}) as Record<string, unknown>;
    const method = String(body.method ?? 'totp');
    let verified = false;
    let amr: Amr = 'otp';
    if (method === 'totp') verified = await verifyTotpForUser(store, config, pending.accountId, String(body.code ?? ''));
    if (method === 'recovery') { verified = await consumeRecoveryCode(store, recoveryKey, pending.accountId, String(body.code ?? '')); amr = 'recovery_code'; }
    if (method === 'webauthn') {
      verified = await verifyAssertion(body.webauthnResponse, `webauthn:${key}`, pending.accountId);
      amr = 'webauthn';
    }
    if (!verified) return reply.redirect(`/ui/mfa?error=verification&method=${method === 'webauthn' ? 'webauthn' : method === 'recovery' ? 'recovery' : 'totp'}`, 303);
    challenges.delete(key!);
    challenges.delete(`webauthn:${key}`);
    return completeStandalone(request, reply, { ...pending, amr: [...pending.amr, amr] });
  });

  /** Discoverable passkey login; the opaque cookie binds the one-use challenge to this browser. */
  app.get('/ui/passkey', async (request, reply) => reply.header('Cache-Control', 'no-store').type('text/html; charset=utf-8').send(layout({
    title: 'Accedi con una passkey', body: `<h1>Accedi con una passkey</h1><form id="mfa-form" class="stack" method="post" action="/ui/passkey"><input type="hidden" name="${CSRF_FIELD}" value="${esc(ensureCsrf(request, reply))}"><div data-webauthn="auth" data-webauthn-options="/ui/passkey/options"><p id="wa-status" role="status">Segui le istruzioni del dispositivo.</p></div><input type="hidden" name="webauthnResponse"><button type="submit">Accedi con una passkey</button></form><p><a href="/ui/login">Usa la password</a></p>`,
  })));
  app.get('/ui/passkey/options', async (request, reply) => {
    const rate = flowLimiter.checkIp(`passkey:${request.ip}`, 20, 60_000);
    if (!rate.allowed) return reply.code(429).header('Retry-After', rate.retryAfterSeconds).send({ error: 'rate_limited' });
    const previous = request.cookies?.[passkeyCookie];
    if (previous) challenges.delete(`passkey-login:${previous}`);
    const opaque = crypto.randomBytes(32).toString('base64url');
    const options = await webauthnAuthenticationOptions(config, []);
    challenges.set(`passkey-login:${opaque}`, { kind: 'webauthn', value: options.challenge, createdAt: Date.now() });
    reply.setCookie(passkeyCookie, opaque, { ...sessions.cookieOptions(), maxAge: 300 });
    return reply.header('Cache-Control', 'no-store').send(options);
  });
  app.post('/ui/passkey', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const rate = flowLimiter.checkIp(`passkey-verify:${request.ip}`, 20, 60_000);
    if (!rate.allowed) return reply.code(429).header('Retry-After', rate.retryAfterSeconds).send({ error: 'rate_limited' });
    const body = (request.body ?? {}) as Record<string, unknown>;
    const opaque = request.cookies?.[passkeyCookie];
    const parsed = parseAssertion(body.webauthnResponse);
    const credential = parsed && typeof parsed.id === 'string' ? await store.findWebauthnCredential(parsed.id) : undefined;
    reply.clearCookie(passkeyCookie, sessions.cookieOptions());
    if (!opaque || !/^[A-Za-z0-9_-]{43}$/.test(opaque) || !credential
      || !await verifyAssertion(body.webauthnResponse, `passkey-login:${opaque}`, credential.userId, true)) {
      if (opaque) challenges.delete(`passkey-login:${opaque}`);
      return reply.code(401).type('text/html; charset=utf-8').send(layout({ title: 'Accesso passkey non riuscito', flash: { kind: 'error', text: 'Non è stato possibile verificare la passkey. La richiesta potrebbe essere scaduta o non valida. Nessun accesso è stato completato.' }, body: '<h1>Riprova l’accesso.</h1><p>Avvia una nuova richiesta e scegli una passkey registrata su Engine Accounts.</p><div class="row"><a class="button primary" href="/ui/passkey">Riprova con passkey</a><a class="button secondary" href="/ui/login">Usa la password</a></div>' }));
    }
    return completeStandalone(request, reply, { accountId: credential.userId, amr: ['webauthn'] });
  });

  function parseAssertion(raw: unknown): { id?: unknown; response?: { userHandle?: unknown } } | undefined {
    try { const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw; return parsed && typeof parsed === 'object' ? parsed : undefined; } catch { return undefined; }
  }
  async function verifyAssertion(raw: unknown, key: string, userId: string, requireHandle = false): Promise<boolean> {
    const challenge = challenges.take(key);
    const parsed = parseAssertion(raw);
    if (!challenge || challenge.kind !== 'webauthn' || Date.now() - challenge.createdAt > 300_000 || !parsed
      || typeof parsed.id !== 'string' || (requireHandle && !parsed.response?.userHandle)) return false;
    const credential = await store.findWebauthnCredential(parsed.id);
    if (!credential || credential.userId !== userId) return false;
    const result = await verifyWebauthnAuthentication(config, parsed, challenge.value, { id: userId }, credential);
    if (result.verified) await store.updateWebauthnCounter(credential.id, result.newCounter ?? credential.counter);
    return result.verified;
  }

  /**
   * Header di `Set-Cookie` accumulati: `provider.interactionFinished()` scrive
   * la risposta direttamente su `reply.raw`, e da quel momento Fastify non
   * invia piu' i propri header. Quindi il cookie di sessione che creiamo qui
   * deve finire su `raw` **prima** del passaggio di mano, altrimenti non
   * arriverebbe mai al browser e ogni passo dell'interazione ricomincerebbe
   * dal login.
   */
  function setRawCookie(reply: FastifyReply, name: string, value: string, options: Parameters<FastifyInstance['serializeCookie']>[2]): void {
    const raw = reply.raw;
    const current = raw.getHeader('set-cookie');
    const list = current === undefined ? [] : (Array.isArray(current) ? current.map(String) : [String(current)]);
    list.push(app.serializeCookie(name, value, options));
    raw.setHeader('set-cookie', list);
  }

  /**
   * Sposta su `reply.raw` gli header che Fastify tiene in sospeso (CSP e
   * compagnia) prima di lasciar scrivere alla libreria. È la stessa
   * operazione che fa `app.ts` prima di cedere le rotte OIDC al provider:
   * vedi `flushReplyHeadersToRaw` in `security/headers.ts`.
   */
  function handoffToProvider(reply: FastifyReply): void {
    flushReplyHeadersToRaw(reply);
  }

  /**
   * Registra il consenso nel modello `Grant` della libreria.
   *
   * Il provider considera "concesso" **solo** quello che trova nel grant che
   * gli passiamo con `consent.grantId`: al resume ricarica il grant da quell'id
   * e i suoi check (`op_scopes_missing`, `rs_scopes_missing`, `op_claims_missing`)
   * lo confrontano con la richiesta. Se il grant e' vuoto — o assente, come
   * accade alla prima autorizzazione, dove non esiste ancora nessun `grantId` —
   * il prompt di consenso viene riproposto all'infinito.
   *
   * La divisione che facciamo qui e' la stessa che la libreria fa in
   * `ctx.oidc`: gli scope "statici" (core + catalogo dei servizi) vanno nel
   * bucket OIDC, quelli di un resource indicator vanno nel bucket della risorsa.
   */
  async function recordConsent(
    accountId: string,
    clientId: string,
    scope: string[],
    params: Record<string, string>,
  ): Promise<string | undefined> {
    const grant = new provider.Grant({ accountId, clientId });
    const statics = new Set([...CORE_SCOPES, ...serviceScopes.map((s) => s.scope)]);
    grant.addOIDCScope(scope.filter((value) => statics.has(value)));

    // Scope di servizio per ogni resource indicator richiesto (RFC 8707).
    const services = await store.listServices();
    for (const indicator of resourceIndicators(params.resource)) {
      const service = services.find((s) => s.enabled && s.audience === indicator);
      if (!service) continue;
      /*
       * Registriamo **tutti** gli scope approvati, non solo quelli di
       * servizio: il provider ricava da qui lo `scope` dell'access token e
       * `/userinfo` si rifiuta di rispondere a un token senza `openid`. Il
       * bucket del resource server resta comunque limitato agli scope di
       * servizio (`resourceServerFor`), quindi nessun check di consenso
       * richiede piu' di quanto l'utente abbia davvero approvato.
       */
      grant.addResourceScope(indicator, scope);
    }

    // I claim richiesti esplicitamente (`claims`) fanno parte del consenso:
    // ignorarli riproporrebbe il prompt per sempre.
    grant.addOIDCClaims(claimsFromParams(params.claims));

    // Il TTL del grant e' quello di `ttl.Grant` (stessa durata della sessione):
    // scade insieme alla sessione che lo ha concesso.
    return grant.save();
  }

  /** Token CSRF double-submit. */
  function ensureCsrf(request: FastifyRequest, reply: FastifyReply): string {
    const existing = request.cookies?.[csrfCookie];
    if (typeof existing === 'string' && existing.length >= 32) return existing;
    const token = issueCsrfToken();
    reply.setCookie(csrfCookie, token, {
      httpOnly: true,
      secure: config.secureCookies,
      sameSite: 'lax',
      path: '/',
    });
    return token;
  }

  function checkCsrf(request: FastifyRequest): boolean {
    const body = request.body as Record<string, unknown> | undefined;
    const cookie = request.cookies?.[csrfCookie];
    const submitted = body?.[CSRF_FIELD] ?? request.headers['x-csrf-token'];
    return verifyCsrfToken(typeof cookie === 'string' ? cookie : undefined, submitted);
  }

  function csrfFailure(reply: FastifyReply, message = 'Sessione scaduta: ricarica la pagina.'): FastifyReply {
    return reply
      .code(403)
      .type('text/html; charset=utf-8')
      .send(layout({ title: 'Errore', body: `<h1>Richiesta non valida</h1><p class="lede">${esc(message)}</p>` }));
  }

  /** Solo chiavi note e valori stringa entrano nella firma del form. */
  function sanitizedParams(value: unknown): Record<string, string> {
    const out: Record<string, string> = {};
    if (typeof value !== 'object' || value === null) return out;
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      if (typeof raw === 'string') out[key] = raw;
    }
    return out;
  }

  const ctx = (request: FastifyRequest) => ({
    ip: request.ip ?? null,
    userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
  });

  const activeSession = (request: FastifyRequest) => sessions.resolve(request.cookies?.[sessionCookie]);

  async function clientName(clientId: string | undefined): Promise<string> {
    if (!clientId) return 'un\'applicazione';
    const client = await store.findClient(clientId);
    return client?.clientName ?? 'un\'applicazione';
  }

  /** Legge il cookie di sessione del provider appena impostato dal provider. */
  function providerSessionIdFrom(reply: FastifyReply): string | null {
    const header = reply.raw.getHeader('set-cookie');
    const list = Array.isArray(header) ? header : header ? [String(header)] : [];
    for (const entry of list) {
      const [pair] = entry.split(';');
      if (!pair) continue;
      const idx = pair.indexOf('=');
      if (idx === -1) continue;
      if (pair.slice(0, idx).trim() === providerCookie) {
        return decodeURIComponent(pair.slice(idx + 1).trim());
      }
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* pagine di autenticazione                                            */
  /* ------------------------------------------------------------------ */

  app.get('/ui/login', async (request, reply) => {
    const query = request.query as { email?: string; reset?: string; error?: string } | undefined;
    const flash = query?.reset
      ? { kind: 'ok' as const, text: 'Password aggiornata. Accedi con la nuova.' }
      : query?.error === 'interaction_expired'
        ? { kind: 'error' as const, text: 'La richiesta di accesso e\' scaduta. Ricomincia.' }
        : undefined;
    return reply
      .type('text/html; charset=utf-8')
      .send(pages.loginPage({ csrf: ensureCsrf(request, reply), email: query?.email ?? '', flash }));
  });

  app.get('/ui/register', async (request, reply) => {
    const query = request.query as { sent?: string } | undefined;
    return reply.type('text/html; charset=utf-8').send(
      pages.registerPage({
        csrf: ensureCsrf(request, reply),
        email: '',
        flash: query?.sent
          ? { kind: 'ok', text: 'Controlla la posta: se l\'indirizzo e\' libero, ti abbiamo scritto.' }
          : undefined,
      }),
    );
  });

  app.get('/ui/forgot-password', async (request, reply) => {
    const query = request.query as { sent?: string } | undefined;
    return reply.type('text/html; charset=utf-8').send(
      pages.forgotPasswordPage({
        csrf: ensureCsrf(request, reply),
        flash: query?.sent
          ? { kind: 'ok', text: 'Se l\'indirizzo esiste, ti abbiamo scritto un link.' }
          : undefined,
      }),
    );
  });

  app.get('/ui/reset-password', async (request, reply) => {
    const query = request.query as { token?: string } | undefined;
    return reply
      .type('text/html; charset=utf-8')
      .send(pages.resetPasswordPage({ csrf: ensureCsrf(request, reply), token: query?.token ?? '' }));
  });

  app.get('/ui/magic-code', async (request, reply) =>
    reply.type('text/html; charset=utf-8').send(pages.magicCodeRequestPage({ csrf: ensureCsrf(request, reply) })),
  );

  app.get('/ui/verify-email', async (request, reply) => {
    const query = request.query as { token?: string } | undefined;
    if (!query?.token) {
      return reply
        .code(400)
        .type('text/html; charset=utf-8')
        .send(pages.verifyEmailPage({ flash: { kind: 'error', text: 'Link non valido.' } }));
    }
    const result = await accounts.verifyEmailToken(query.token, ctx(request));
    return reply
      .code(result.ok ? 200 : 400)
      .type('text/html; charset=utf-8')
      .send(
        pages.verifyEmailPage({
          flash: result.ok
            ? { kind: 'ok', text: 'Indirizzo verificato. Ora puoi accedere.' }
            : { kind: 'error', text: 'Link non valido, scaduto o gia\' usato.' },
        }),
      );
  });

  /* ------------------------------------------------------------------ */
  /* POST: login, registrazione, reset, codice monouso                   */
  /* ------------------------------------------------------------------ */

  app.post('/ui/login', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    markStart();
    const outcome = await accounts.authenticate(String(body.email ?? ''), String(body.password ?? ''), ctx(request));
    // Tempo uniforme: nessuna risposta arriva prima di `HTTP_LOGIN_SLOW_MS`.
    await holdFor(config.HTTP_LOGIN_SLOW_MS, () => undefined);

    if (outcome.status === 'ok' && outcome.user) {
      return completeStandalone(request, reply, { accountId: outcome.user.id, amr: ['pwd'] });
    }

    const message =
      outcome.status === 'blocked'
        ? 'Questo account e\' stato sospeso. Contatta l\'amministratore.'
        : outcome.retryAfterSeconds && outcome.retryAfterSeconds > 0
          ? `Troppi tentativi. Riprova fra ${outcome.retryAfterSeconds} secondi.`
          : NEUTRAL_LOGIN;
    return reply
      .code(401)
      .type('text/html; charset=utf-8')
      .send(
        pages.loginPage({
          csrf: ensureCsrf(request, reply),
          errors: [message],
          email: String(body.email ?? ''),
        }),
      );
  });

  app.post('/ui/register', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    await accounts.register(
      {
        email: String(body.email ?? ''),
        password: String(body.password ?? ''),
        displayName: body.displayName ? String(body.displayName) : null,
      },
      ctx(request),
    );
    // Risposta identica qualunque cosa sia successo: niente oracoli.
    return reply.redirect('/ui/register?sent=1', 303);
  });

  app.post('/ui/forgot-password', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    await accounts.requestPasswordReset(String(body.email ?? ''), ctx(request));
    return reply.redirect('/ui/forgot-password?sent=1', 303);
  });

  app.post('/ui/reset-password', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const password = String(body.password ?? '');
    const errors: string[] = [];
    if (password !== String(body.confirm ?? '')) errors.push('Le due password non coincidono.');

    if (errors.length) return reply.code(400).type('text/html; charset=utf-8').send(
      pages.resetPasswordPage({ csrf: ensureCsrf(request, reply), token: String(body.token ?? ''), errors }),
    );
    const result = await accounts.resetPassword(String(body.token ?? ''), password, ctx(request));
    if (!result.ok) {
      errors.push(result.message);
      return reply.code(400).type('text/html; charset=utf-8').send(
        pages.resetPasswordPage({ csrf: ensureCsrf(request, reply), token: String(body.token ?? ''), errors }),
      );
    }
    return reply.redirect('/ui/login?reset=1', 303);
  });

  app.post('/ui/magic-code', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const { message } = await accounts.requestMagicCode(String(body.email ?? ''), ctx(request));
    return reply.type('text/html; charset=utf-8').send(
      pages.magicCodeVerifyPage({
        csrf: ensureCsrf(request, reply),
        email: String(body.email ?? ''),
        flash: { kind: 'info', text: message },
      }),
    );
  });

  app.post('/ui/magic-code/verify', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const outcome = await accounts.consumeMagicCode(String(body.email ?? ''), String(body.code ?? ''), ctx(request));
    await holdFor(config.HTTP_LOGIN_SLOW_MS, () => undefined);
    if (outcome.status !== 'ok' || !outcome.user) {
      return reply.code(401).type('text/html; charset=utf-8').send(
        pages.magicCodeVerifyPage({
          csrf: ensureCsrf(request, reply),
          email: String(body.email ?? ''),
          errors: ['Codice non valido o scaduto.'],
        }),
      );
    }
    return completeStandalone(request, reply, { accountId: outcome.user.id, amr: ['magic_code'] });
  });

  /**
   * Chiude la fase di login dell'interazione.
   *
   * Crea la nostra sessione (cookie di sessione), registra il login, e poi
   * consegna il controllo alla libreria: lei scrive il proprio cookie di
   * sessione e fa il 303 verso il passo successivo del flusso OIDC. Dopo aver
   * scritto, leggiamo il suo cookie per collegare le due sessioni: e' il
   * collegamento che permette di revocare davvero il dispositivo.
   */
  async function finishLogin(
    request: FastifyRequest,
    reply: FastifyReply,
    accountId: string,
    amr: Amr[],
  ): Promise<FastifyReply> {
    const current = await store.findUserById(accountId);
    if (!current || current.status !== 'active') return reply.redirect('/ui/login', 303);
    if (current.mustChangePassword) {
      const { uid } = request.params as { uid: string };
      if (!await safeDetails(request, reply, provider)) return reply.redirect('/ui/login', 303);
      savePending(`force:${uid}`, { accountId, amr });
      return reply.redirect(`/ui/interaction/${uid}/force-password-change`, 303);
    }
    const settings = await accounts.effectivePolicy();
    if ((settings.EMAIL_VERIFICATION_REQUIRED && !current.emailVerifiedAt) || (settings.TOTP_REQUIRED && !current.totpEnabled)) {
      return reply.code(403).type('text/html; charset=utf-8').send(layout({ title: 'Account da completare', body:
        '<h1>Completa la sicurezza dell’account</h1><p>Verifica la tua email e attiva TOTP prima di autorizzare questa applicazione.</p><p><a href="/ui/login">Accedi al pannello account</a></p>' }));
    }
    if (current.totpEnabled && !amr.some((m) => ['otp', 'webauthn', 'recovery_code'].includes(m))) {
      const { uid } = request.params as { uid: string };
      challenges.set(`interaction:${uid}`, { kind: 'totp', value: current.id, createdAt: Date.now() });
      return reply.redirect(`/ui/interaction/${uid}/mfa?method=totp`, 303);
    }
    const { record, cookieValue } = await sessions.create({
      userId: accountId,
      amr,
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
    });
    setRawCookie(reply, sessionCookie, cookieValue, {
      ...sessions.cookieOptions(),
      maxAge: Math.max(0, Math.floor((record.expiresAt.getTime() - Date.now()) / 1000)),
    });
    const user = await store.findUserById(accountId);
    if (user) await accounts.onLoginSucceeded(user, amr, ctx(request));

    handoffToProvider(reply);
    await provider.interactionFinished(request.raw, reply.raw, {
      login: { accountId, amr: [...amr] },
    });

    const providerSessionId = providerSessionIdFrom(reply);
    if (providerSessionId) await sessions.linkProviderSession(record.id, providerSessionId);
    return reply;
  }

  /* ------------------------------------------------------------------ */
  /* interazione OIDC                                                     */
  /* ------------------------------------------------------------------ */

  app.get('/ui/interaction/:uid', async (request, reply) => {
    const { uid } = request.params as { uid: string };
    let interaction;
    try {
      interaction = await provider.interactionDetails(request.raw, reply.raw);
      if (interaction.uid !== uid) return reply.redirect('/ui/login?error=interaction_expired', 303);
    } catch (err) {
      if (err instanceof errors.SessionNotFound) {
        return reply.redirect('/ui/login?error=interaction_expired', 303);
      }
      throw err;
    }

    const params = sanitizedParams(interaction.params);
    const csrf = ensureCsrf(request, reply);
    const existing = await activeSession(request);
    if (existing?.user.mustChangePassword) {
      savePending(`force:${uid}`, { accountId: existing.user.id, amr: existing.session.amr as Amr[] });
      return reply.redirect(`/ui/interaction/${uid}/force-password-change`, 303);
    }
    if (interaction.prompt.name === 'consent') {
      const scopes = params.scope ? params.scope.split(' ').filter(Boolean) : [];
      const catalog = scopeCatalog();
      const active = await activeSession(request);
      return reply.type('text/html; charset=utf-8').send(
        pages.consentPage({
          csrf,
          uid,
          clientName: await clientName(params.client_id),
          accountName: active?.user.displayName ?? active?.user.email ?? 'il tuo account',
          scopes: scopes.map((value) => ({ value, description: catalog.get(value) ?? 'Accesso funzionale' })),
        }),
      );
    }

    // Prompt login: se c'e' una sessione attiva, si salta il form (SSO).
    const active = await activeSession(request);
    if (active) {
      return finishLogin(request, reply, active.user.id, active.session.amr as Amr[]);
    }
    return reply.type('text/html; charset=utf-8').send(
      pages.interactionLoginPage({
        csrf,
        uid,
        clientName: await clientName(params.client_id),
        email: params.login_hint ?? '',
      }),
    );
  });

  app.post('/ui/interaction/:uid/login', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    if (!await safeDetails(request, reply, provider)) return reply.redirect('/ui/login?error=interaction_expired', 303);
    const { uid } = request.params as { uid: string };
    const body = (request.body ?? {}) as Record<string, unknown>;
    markStart();

    const outcome = await accounts.authenticate(String(body.email ?? ''), String(body.password ?? ''), ctx(request));
    await holdFor(config.HTTP_LOGIN_SLOW_MS, () => undefined);

    if (outcome.status !== 'ok' || !outcome.user) {
      const details = await safeDetails(request, reply, provider);
      const message =
        outcome.status === 'blocked'
          ? 'Questo account e\' stato sospeso.'
          : outcome.retryAfterSeconds && outcome.retryAfterSeconds > 0
            ? `Troppi tentativi. Riprova fra ${outcome.retryAfterSeconds} secondi.`
            : NEUTRAL_LOGIN;
      return reply.code(401).type('text/html; charset=utf-8').send(
        pages.interactionLoginPage({
          csrf: ensureCsrf(request, reply),
          uid,
          clientName: await clientName(details ? sanitizedParams(details.params).client_id : undefined),
          errors: [message],
          email: String(body.email ?? ''),
        }),
      );
    }

    if (outcome.user.mustChangePassword) return finishLogin(request, reply, outcome.user.id, ['pwd']);
    if (outcome.user.totpEnabled) {
      // Secondo fattore obbligatorio: challenge tenuto in memoria, 5 minuti.
      challenges.set(`interaction:${uid}`, { kind: 'totp', value: outcome.user.id, createdAt: Date.now() });
      return reply.redirect(`/ui/interaction/${uid}/mfa?method=totp`, 303);
    }
    return finishLogin(request, reply, outcome.user.id, ['pwd']);
  });

  app.get('/ui/interaction/:uid/mfa', async (request, reply) => {
    const { uid } = request.params as { uid: string };
    if (!await safeDetails(request, reply, provider)) return reply.redirect('/ui/login?error=interaction_expired', 303);
    const pending = challenges.get(`interaction:${uid}`);
    if (!pending || Date.now() - pending.createdAt > 300_000) return reply.redirect('/ui/login?error=interaction_expired', 303);
    const method = ((request.query as { method?: string } | undefined)?.method ?? 'totp') as
      | 'totp'
      | 'webauthn'
      | 'recovery';
    return reply
      .type('text/html; charset=utf-8')
      .send(
        pages.interactionMfaPage({
          csrf: ensureCsrf(request, reply),
          uid,
          method,
          webauthnOptionsUrl: `/ui/interaction/${uid}/mfa/options`,
        }),
      );
  });

  app.get('/ui/interaction/:uid/mfa/options', async (request, reply) => {
    const { uid } = request.params as { uid: string };
    if (!await safeDetails(request, reply, provider)) return reply.code(401).send({ error: 'interaction_expired' });
    const pending = challenges.get(`interaction:${uid}`);
    if (!pending || Date.now() - pending.createdAt > 300_000) return reply.code(400).send({ error: 'challenge scaduta' });
    const credentials = await store.listWebauthnCredentials(pending.value);
    if (!credentials.length) return reply.code(400).send({ error: 'no_passkeys' });
    const options = await webauthnAuthenticationOptions(
      config,
      credentials.map((c) => ({ credentialId: c.credentialId, transports: c.transports })),
    );
    // In-memory challenge bound to the provider's validated interaction cookie.
    challenges.set(`webauthn:${uid}`, { kind: 'webauthn', value: options.challenge, createdAt: Date.now() });
    return reply.header('Cache-Control', 'no-store').send(options);
  });

  app.post('/ui/interaction/:uid/mfa', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    if (!await safeDetails(request, reply, provider)) return reply.redirect('/ui/login?error=interaction_expired', 303);
    const rate = flowLimiter.checkIp(`mfa:${request.ip}`, 10, 60_000);
    if (!rate.allowed) return reply.code(429).header('Retry-After', rate.retryAfterSeconds).send({ error: 'rate_limited' });
    const { uid } = request.params as { uid: string };
    const body = (request.body ?? {}) as Record<string, unknown>;
    const method = String(body.method ?? 'totp');
    const pending = challenges.take(`interaction:${uid}`);
    if (!pending || Date.now() - pending.createdAt > 300_000) return reply.redirect('/ui/login?error=interaction_expired', 303);

    let verified = false;
    let amr: Amr = 'otp';

    if (method === 'totp') {
      verified = await verifyTotpForUser(store, config, pending.value, String(body.code ?? ''));
      amr = 'otp';
    } else if (method === 'recovery') {
      verified = await consumeRecoveryCode(store, recoveryKey, pending.value, String(body.code ?? ''));
      amr = 'recovery_code';
    } else if (method === 'webauthn') {
      verified = await verifyAssertion(body.webauthnResponse, `webauthn:${uid}`, pending.value);
      amr = 'webauthn';
    }

    if (!verified) {
      challenges.set(`interaction:${uid}`, pending);
      return reply.code(401).type('text/html; charset=utf-8').send(
        pages.interactionMfaPage({
          csrf: ensureCsrf(request, reply),
          uid,
           method: method === 'webauthn' ? 'webauthn' : method === 'recovery' ? 'recovery' : 'totp',
          errors: ['Codice non valido. Riprova.'],
          webauthnOptionsUrl: `/ui/interaction/${uid}/mfa/options`,
        }),
      );
    }

    challenges.delete(`webauthn:${uid}`);
    return finishLogin(request, reply, pending.value, ['pwd', amr]);
  });

  app.post('/ui/interaction/:uid/consent', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const { uid } = request.params as { uid: string };
    const body = (request.body ?? {}) as Record<string, unknown>;
    const active = await activeSession(request);
    if (!active) return reply.redirect('/ui/login', 303);
    if (active.user.mustChangePassword) return reply.redirect(`/ui/interaction/${uid}/force-password-change`, 303);

    const details = await safeDetails(request, reply, provider);
    if (!details) return reply.redirect('/ui/login?error=interaction_expired', 303);

    if (body.decision !== 'allow') {
      await store.appendAudit({
        userId: active.user.id,
        event: 'consent.denied',
        outcome: 'info',
        ip: request.ip ?? null,
        userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
        metadata: {},
      });
      handoffToProvider(reply);
      await provider.interactionFinished(request.raw, reply.raw, { error: 'access_denied' });
      return reply;
    }

    const params = sanitizedParams(details.params);
    const scope = params.scope ? params.scope.split(' ').filter(Boolean) : [];
    const clientId = params.client_id ?? '';
    const grantId = await recordConsent(active.user.id, clientId, scope, params);
    await store.saveConsent({
      userId: active.user.id,
      clientId,
      scope,
      expiresAt: new Date(Date.now() + (await accounts.effectivePolicy()).CONSENT_TTL * 1000),
    });
    await store.appendAudit({
      userId: active.user.id,
      event: 'consent.granted',
      outcome: 'success',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { client_id: clientId, scope: scope.join(' ') },
    });
    void uid;
    handoffToProvider(reply);
    await provider.interactionFinished(request.raw, reply.raw, {
      consent: { grantId },
    });
    return reply;
  });

  /* ------------------------------------------------------------------ */
  /* registrazione passkey dal pannello (l'interaction usa lo store)      */
  /* ------------------------------------------------------------------ */

  app.post('/ui/webauthn/register/options', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const active = await activeSession(request);
    if (!active) return reply.code(401).send({ error: 'non autenticato' });
    if (active.user.mustChangePassword) return reply.code(403).send({ error: 'password_change_required' });
    const options = await webauthnRegistrationOptions(config, active.user, await store.listWebauthnCredentials(active.user.id));
    challenges.set(`webauthn-register:${active.session.id}`, { kind: 'webauthn', value: options.challenge, createdAt: Date.now() });
    reply.header('Cache-Control', 'no-store');
    return reply.send(options);
  });

  app.post('/ui/webauthn/register/verify', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const active = await activeSession(request);
    if (!active) return reply.code(401).send({ error: 'non autenticato' });
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (active.user.mustChangePassword) return reply.code(403).send({ error: 'password_change_required' });
    const challenge = challenges.take(`webauthn-register:${active.session.id}`);
    if (!challenge || challenge.kind !== 'webauthn' || Date.now() - challenge.createdAt > 300_000) return reply.code(400).send({ error: 'challenge scaduta' });
    const result = await completeWebauthnRegistration(
      config,
      body.response ?? body,
      challenge.value,
      { id: active.user.id },
    );
    if (!result.verified || !result.draft) {
      return reply.code(400).send({ error: 'registrazione non riuscita', detail: result.error });
    }
    const draft = result.draft;
    await store.addWebauthnCredential({
      userId: active.user.id,
      credentialId: draft.credentialId,
      publicKey: draft.publicKey,
      transports: draft.transports,
      aaguid: draft.aaguid,
      deviceType: draft.deviceType,
      backedUp: draft.backedUp,
      nickname: typeof body.nickname === 'string' ? body.nickname.slice(0, 64) : null,
    });
    await store.appendAudit({
      userId: active.user.id,
      event: 'webauthn.registered',
      outcome: 'success',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { credential_id: draft.credentialId },
    });
    return reply.send({ ok: true });
  });

  app.post('/ui/webauthn/register/challenge', async (request, reply) => {
    // Old split endpoint generated a different challenge from /options and could never verify.
    return reply.code(410).send({ error: 'use_register_options' });
  });

  /** Ricarica la cache degli scope di servizio (usata dal consenso). */
  async function refreshScopes(): Promise<void> {
    serviceScopes = await store.listServiceScopes();
  }
  void refreshScopes;
}

/** `interactionDetails` può fallire (cookie assente, interazione scaduta). */
async function safeDetails(request: FastifyRequest, reply: FastifyReply, provider: Provider) {
  try {
    const details = await provider.interactionDetails(request.raw, reply.raw);
    const uid = (request.params as { uid?: string } | undefined)?.uid;
    return uid && details.uid !== uid ? undefined : details;
  } catch {
    return undefined;
  }
}
