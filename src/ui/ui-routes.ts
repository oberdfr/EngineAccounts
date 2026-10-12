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
import { esc, layout } from '../ui/layout.js';

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
      const { record, cookieValue } = await sessions.create({
        userId: outcome.user.id,
        amr: ['pwd'],
        ip: request.ip ?? null,
        userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      });
      await accounts.onLoginSucceeded(outcome.user, ['pwd'], ctx(request));
      reply.setCookie(sessionCookie, cookieValue, {
        ...sessions.cookieOptions(),
        maxAge: Math.max(0, Math.floor((record.expiresAt.getTime() - Date.now()) / 1000)),
      });
      return reply.redirect('/account', 303);
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
    const { record, cookieValue } = await sessions.create({
      userId: outcome.user.id,
      amr: ['magic_code'],
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
    });
    await accounts.onLoginSucceeded(outcome.user, ['magic_code'], ctx(request));
    reply.setCookie(sessionCookie, cookieValue, {
      ...sessions.cookieOptions(),
      maxAge: Math.max(0, Math.floor((record.expiresAt.getTime() - Date.now()) / 1000)),
    });
    return reply.redirect('/account', 303);
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
    } catch (err) {
      if (err instanceof errors.SessionNotFound) {
        return reply.redirect('/ui/login?error=interaction_expired', 303);
      }
      throw err;
    }

    const params = sanitizedParams(interaction.params);
    const csrf = ensureCsrf(request, reply);
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

    if (outcome.user.totpEnabled) {
      // Secondo fattore obbligatorio: challenge tenuto in memoria, 5 minuti.
      challenges.set(`interaction:${uid}`, { kind: 'totp', value: outcome.user.id, createdAt: Date.now() });
      return reply.redirect(`/ui/interaction/${uid}/mfa?method=totp`, 303);
    }
    return finishLogin(request, reply, outcome.user.id, ['pwd']);
  });

  app.get('/ui/interaction/:uid/mfa', async (request, reply) => {
    const { uid } = request.params as { uid: string };
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
    const pending = challenges.get(`interaction:${uid}`);
    if (!pending) return reply.code(400).send({ error: 'challenge scaduta' });
    const credentials = await store.listWebauthnCredentials(pending.value);
    const options = await webauthnAuthenticationOptions(
      config,
      credentials.map((c) => ({ credentialId: c.credentialId, transports: c.transports })),
    );
    // La challenge WebAuthn vive in un cookie firmato: nessuno script inline.
    challenges.set(`webauthn:${uid}`, { kind: 'webauthn', value: options.challenge, createdAt: Date.now() });
    return reply.header('Cache-Control', 'no-store').send(options);
  });

  app.post('/ui/interaction/:uid/mfa', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const { uid } = request.params as { uid: string };
    const body = (request.body ?? {}) as Record<string, unknown>;
    const method = String(body.method ?? 'totp');
    const pending = challenges.take(`interaction:${uid}`);
    if (!pending) return reply.redirect('/ui/login?error=interaction_expired', 303);

    let verified = false;
    let amr: Amr = 'otp';

    if (method === 'totp') {
      verified = await verifyTotpForUser(store, config, pending.value, String(body.code ?? ''));
      amr = 'otp';
    } else if (method === 'recovery') {
      verified = await consumeRecoveryCode(store, recoveryKey, pending.value, String(body.code ?? ''));
      amr = 'recovery_code';
    } else if (method === 'webauthn') {
      const raw = String(body.webauthnResponse ?? '');
      if (raw) {
        const parsed = JSON.parse(raw) as { id?: string };
        const credential = parsed.id ? await store.findWebauthnCredential(parsed.id) : undefined;
        const challenge = challenges.take(`webauthn:${uid}`);
        // Isolamento: la credenziale deve appartenere all'utente della challenge.
        if (credential && challenge && credential.userId === pending.value) {
          const result = await verifyWebauthnAuthentication(
            config,
            JSON.parse(raw),
            challenge.value,
            { id: pending.value },
            {
              credentialId: credential.credentialId,
              publicKey: credential.publicKey,
              counter: credential.counter,
              transports: credential.transports,
            },
          );
          verified = result.verified;
          if (verified) {
            await store.updateWebauthnCounter(credential.id, result.newCounter ?? credential.counter + 1);
          }
        }
      }
      amr = 'webauthn';
    }

    if (!verified) {
      challenges.set(`interaction:${uid}`, pending);
      return reply.code(401).type('text/html; charset=utf-8').send(
        pages.interactionMfaPage({
          csrf: ensureCsrf(request, reply),
          uid,
          method: method === 'webauthn' ? 'webauthn' : (method as 'totp' | 'recovery'),
          errors: ['Codice non valido. Riprova.'],
          webauthnOptionsUrl: `/ui/interaction/${uid}/mfa/options`,
        }),
      );
    }

    return finishLogin(request, reply, pending.value, ['pwd', amr]);
  });

  app.post('/ui/interaction/:uid/consent', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const { uid } = request.params as { uid: string };
    const body = (request.body ?? {}) as Record<string, unknown>;
    const active = await activeSession(request);
    if (!active) return reply.redirect('/ui/login', 303);

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
      expiresAt: new Date(Date.now() + config.CONSENT_TTL * 1000),
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
    const active = await activeSession(request);
    if (!active) return reply.code(401).send({ error: 'non autenticato' });
    const options = await webauthnRegistrationOptions(config, active.user);
    // La challenge non finisce in uno script inline: la pagina la chiede.
    reply.header('Cache-Control', 'no-store');
    return reply.send(options);
  });

  app.post('/ui/webauthn/register/verify', async (request, reply) => {
    const active = await activeSession(request);
    if (!active) return reply.code(401).send({ error: 'non autenticato' });
    const body = (request.body ?? {}) as Record<string, unknown>;
    const challenge = challenges.take(`webauthn-register:${active.user.id}`);
    if (!challenge) return reply.code(400).send({ error: 'challenge scaduta' });
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
    const active = await activeSession(request);
    if (!active) return reply.code(401).send({ error: 'non autenticato' });
    const options = await webauthnRegistrationOptions(config, active.user);
    challenges.set(`webauthn-register:${active.user.id}`, {
      kind: 'webauthn',
      value: options.challenge,
      createdAt: Date.now(),
    });
    return reply.send({ ok: true });
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
    return await provider.interactionDetails(request.raw, reply.raw);
  } catch {
    return undefined;
  }
}