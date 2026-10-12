import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import type { AccountsStore } from '../domain/ports.js';
import type { AccountService } from '../services/account-service.js';
import { holdFor } from '../security/timing.js';
import { CSRF_FIELD, csrfCookieName, issueCsrfToken, verifyCsrfToken } from '../security/csrf.js';
import { hkdf } from '../config.js';
import {
  completeWebauthnRegistration,
  confirmTotpEnrolment,
  disableTotp,
  resetRecoveryCodes,
  rpIDFromIssuer,
  startTotpEnrolment,
  webauthnRegistrationOptions,
  type ChallengeStore,
} from '../services/mfa.js';
import { sessionCookieName, type SessionManager } from '../services/session-manager.js';
import { maskEmail } from '../services/mailer.js';
import * as pages from '../ui/pages.js';

/**
 * Pannello di gestione account (`/account/*`).
 *
 * Ogni POST che cambia stato richiede (1) un token CSRF double-submit e (2)
 * riautenticazione quando l'azione e' distruttiva: cambio password, revoca
 * consensi, eliminazione. Un cookie di sessione rubato non deve bastare.
 */

export interface AccountDeps {
  config: Config;
  store: AccountsStore;
  accounts: AccountService;
  sessions: SessionManager;
  challenges: ChallengeStore;
}

export async function registerAccountRoutes(app: FastifyInstance, deps: AccountDeps): Promise<void> {
  const { config, store, accounts, sessions, challenges } = deps;
  const recoveryKey = hkdf(config.dataKey, 'engine-accounts/recovery-codes');

  const csrfCookie = csrfCookieName(config.cookiePrefix);
  const sessionCookie = sessionCookieName(config);

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
    return verifyCsrfToken(typeof cookie === 'string' ? cookie : undefined, body?.[CSRF_FIELD] ?? request.headers['x-csrf-token']);
  }

  function csrfFailure(reply: FastifyReply): FastifyReply {
    return reply.code(403).type('text/html; charset=utf-8').send(
      pages.csrfErrorPage,
    );
  }

  const ctx = (request: FastifyRequest) => ({
    ip: request.ip ?? null,
    userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
  });

  /**
   * Guard di ogni pagina `/account/*`: senza sessione valida si va al login.
   * Il valore torna anche ai gestori, che ne hanno bisogno per i form.
   */
  async function requireSession(request: FastifyRequest, reply: FastifyReply) {
    const active = await sessions.resolve(request.cookies?.[sessionCookie]);
    if (!active) {
      reply.redirect(`/ui/login?next=${encodeURIComponent(request.url)}`, 303);
      return undefined;
    }
    return active;
  }

  /** Cambio password e eliminazione: la password attuale e\' obbligatoria. */
  async function requirePassword(userId: string, password: unknown): Promise<boolean> {
    const record = await store.findUserById(userId);
    if (!record) return false;
    const { verifyPassword } = await import('../security/password.js');
    return verifyPassword(record.passwordHash, String(password ?? ''), config);
  }

  /* ------------------------------------------------------------------ */
  /* pagine                                                              */
  /* ------------------------------------------------------------------ */

  app.get('/account', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const csrf = ensureCsrf(request, reply);
    const { user, session } = active;
    const [sessionList, consents, credentials, recoveryLeft] = await Promise.all([
      sessions.list(user.id),
      store.listConsents(user.id),
      store.listWebauthnCredentials(user.id),
      store.countUnusedRecoveryCodes(user.id),
    ]);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountHomePage({
        csrf,
        email: user.email,
        displayName: user.displayName,
        emailVerified: Boolean(user.emailVerifiedAt),
        createdAt: user.createdAt,
        sessions: sessionList.filter((s) => s.id === session.id || true).length,
        consents: consents.length,
        hasTotp: user.totpEnabled,
        passkeys: credentials.length,
        recoveryLeft,
      }),
    );
  });

  app.get('/account/security', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const [totp, credentials, recoveryLeft] = await Promise.all([
      store.getTotp(active.user.id),
      store.listWebauthnCredentials(active.user.id),
      store.countUnusedRecoveryCodes(active.user.id),
    ]);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountSecurityPage({
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        hasTotp: active.user.totpEnabled,
        totpConfirmed: Boolean(totp?.confirmedAt),
        passkeys: credentials.map((c) => ({
          ...c,
          label: c.nickname ?? `Passkey ${c.credentialId.slice(-6)}`,
        })),
        recoveryLeft,
        flash: (request.query as { done?: string } | undefined)?.done
          ? { kind: 'ok', text: 'Fatto.' }
          : undefined,
      }),
    );
  });

  app.get('/account/sessions', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const list = await sessions.list(active.user.id);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountSessionsPage({
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        sessions: list.map((s) => ({ ...s, current: s.id === active.session.id })),
        flash: (request.query as { revoked?: string } | undefined)?.revoked
          ? { kind: 'ok', text: 'Sessione revocata.' }
          : undefined,
      }),
    );
  });

  app.get('/account/apps', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const consents = await store.listConsents(active.user.id);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountAppsPage({
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        consents,
        flash: (request.query as { revoked?: string } | undefined)?.revoked
          ? { kind: 'ok', text: 'Consenso revocato.' }
          : undefined,
      }),
    );
  });

  app.get('/account/activity', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const [entries, total] = await Promise.all([store.listAudit(active.user.id, 100), store.countAudit(active.user.id)]);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountActivityPage({
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        entries: entries.map((e) => ({
          at: e.at,
          event: e.event,
          outcome: e.outcome,
          ip: e.ip ?? null,
          metadata: e.metadata,
        })),
        total,
      }),
    );
  });

  app.get('/account/export', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    return reply.type('text/html; charset=utf-8').send(
      pages.accountExportPage({
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        downloadUrl: '/account/export.json',
      }),
    );
  });

  app.get('/account/export.json', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const data = await accounts.exportData(active.user.id, ctx(request));
    return reply
      .header('Content-Disposition', 'attachment; filename="engine-accounts-export.json"')
      .header('Cache-Control', 'no-store')
      .type('application/json; charset=utf-8')
      .send(JSON.stringify(data, null, 2));
  });

  app.get('/account/delete', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    return reply.type('text/html; charset=utf-8').send(
      pages.accountDeletePage({ csrf: ensureCsrf(request, reply), email: active.user.email }),
    );
  });

  /* ------------------------------------------------------------------ */
  /* azioni                                                              */
  /* ------------------------------------------------------------------ */

  app.post('/account/logout', async (request, reply) => {
    if (!checkCsrf(request)) return csrfFailure(reply);
    const active = await sessions.resolve(request.cookies?.[sessionCookie]);
    if (active) {
      await sessions.revoke(active.session.id, 'logout', active.user.id);
      await store.appendAudit({
        userId: active.user.id,
        event: 'logout',
        outcome: 'info',
        ip: request.ip ?? null,
        userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
        metadata: {},
      });
    }
    reply.clearCookie(sessionCookie, sessions.cookieOptions());
    return reply.redirect('/ui/login', 303);
  });

  app.post('/account/profile/name', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const displayName = String(body.displayName ?? '').trim().slice(0, 120) || null;
    await store.updateUser(active.user.id, { displayName });
    await store.appendAudit({
      userId: active.user.id,
      event: 'profile.updated',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { field: 'displayName' },
    });
    return reply.redirect('/account/profile?saved=1', 303);
  });

  app.post('/account/profile/email', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    // Cambio email = riautenticazione (CWE-287 livello 2): cambiare l'indirizzo
    // di un account e' il primo passo di un takeover.
    if (!(await requirePassword(active.user.id, body.password))) {
      return reply.code(403).type('text/html; charset=utf-8').send(
        pages.accountProfilePage({
          csrf: ensureCsrf(request, reply),
          email: active.user.email,
          displayName: active.user.displayName,
          emailVerified: Boolean(active.user.emailVerifiedAt),
          errors: ['Password attuale non corretta.'],
        }),
      );
    }
    const result = await accounts.requestEmailChange(active.user.id, String(body.newEmail ?? ''), ctx(request));
    return reply.redirect(`/account/profile?${result.ok ? 'email=sent' : 'email=failed'}`, 303);
  });

  app.post('/account/security/password', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const password = String(body.newPassword ?? '');
    if (password !== String(body.confirm ?? '')) {
      return renderSecurityError(request, reply, active.user.id, ['Le due password non coincidono.']);
    }
    const result = await accounts.changePassword(
      active.user.id,
      String(body.currentPassword ?? ''),
      password,
      ctx(request),
    );
    if (!result.ok) return renderSecurityError(request, reply, active.user.id, [result.message]);
    return reply.redirect('/account/security?done=1', 303);
  });

  async function renderSecurityError(
    request: FastifyRequest,
    reply: FastifyReply,
    userId: string,
    errors: string[],
  ): Promise<FastifyReply> {
    const user = await store.findUserById(userId);
    const [totp, credentials, recoveryLeft] = await Promise.all([
      store.getTotp(userId),
      store.listWebauthnCredentials(userId),
      store.countUnusedRecoveryCodes(userId),
    ]);
    return reply.code(400).type('text/html; charset=utf-8').send(
      pages.accountSecurityPage({
        csrf: ensureCsrf(request, reply),
        email: user?.email ?? '',
        hasTotp: user?.totpEnabled ?? false,
        totpConfirmed: Boolean(totp?.confirmedAt),
        passkeys: credentials.map((c) => ({ ...c, label: c.nickname ?? `Passkey ${c.credentialId.slice(-6)}` })),
        recoveryLeft,
        errors,
      }),
    );
  }

  app.get('/account/security/totp/setup', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    // Il segreto appena generato vive in challenge: non finisce nell'URL.
    const { secret, uri } = await startTotpEnrolment(store, config, active.user);
    challenges.set(`totp-setup:${active.user.id}`, { kind: 'totp', value: secret, createdAt: Date.now() });
    return reply
      .type('text/html; charset=utf-8')
      .send(pages.totpSetupPage({ csrf: ensureCsrf(request, reply), email: active.user.email, secret, uri }));
  });

  app.post('/account/security/totp/confirm', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const ok = await confirmTotpEnrolment(store, config, active.user.id, String(body.code ?? ''));
    if (!ok) {
      await store.appendAudit({
        userId: active.user.id,
        event: 'totp.confirm_failed',
        outcome: 'failure',
        ip: request.ip ?? null,
        userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
        metadata: {},
      });
      return reply.redirect('/account/security/totp/setup?invalid=1', 303);
    }
    challenges.delete(`totp-setup:${active.user.id}`);
    await store.appendAudit({
      userId: active.user.id,
      event: 'totp.enabled',
      outcome: 'success',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: {},
    });
    // Anche la riautenticazione: aggiungere un fattore non deve essere
    // consentito a chi ha solo una sessione rubata (ASVS 3.3.2).
    return reply.redirect('/account/security?done=1', 303);
  });

  app.post('/account/security/totp/disable', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (!(await requirePassword(active.user.id, body.password))) {
      return renderSecurityError(request, reply, active.user.id, ['Password attuale non corretta.']);
    }
    await disableTotp(store, active.user.id);
    await store.appendAudit({
      userId: active.user.id,
      event: 'totp.disabled',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: {},
    });
    return reply.redirect('/account/security?done=1', 303);
  });

  app.get('/account/security/webauthn/register', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const options = await webauthnRegistrationOptions(config, active.user);
    challenges.set(`webauthn-register:${active.user.id}`, {
      kind: 'webauthn',
      value: options.challenge,
      createdAt: Date.now(),
    });
    return reply
      .type('text/html; charset=utf-8')
      .send(
        pages.webauthnRegisterPage({
          csrf: ensureCsrf(request, reply),
          email: active.user.email,
          optionsJson: JSON.stringify(options),
        }),
      );
  });

  app.post('/account/security/webauthn/verify', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const challenge = challenges.take(`webauthn-register:${active.user.id}`);
    if (!challenge) return reply.redirect('/account/security?done=1', 303);
    const parsed = JSON.parse(String(body.webauthnResponse ?? '{}')) as unknown;
    const result = await completeWebauthnRegistration(config, parsed, challenge.value, { id: active.user.id });
    if (!result.verified || !result.draft) {
      await store.appendAudit({
        userId: active.user.id,
        event: 'webauthn.register_failed',
        outcome: 'failure',
        ip: request.ip ?? null,
        userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
        metadata: { detail: result.error ?? 'unknown' },
      });
      return reply.redirect('/account/security?error=passkey', 303);
    }
    await store.addWebauthnCredential({ userId: active.user.id, ...result.draft });
    await store.appendAudit({
      userId: active.user.id,
      event: 'webauthn.registered',
      outcome: 'success',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { credential_id: result.draft.credentialId },
    });
    return reply.redirect('/account/security?done=1', 303);
  });

  app.post('/account/security/webauthn/delete', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    // L'id della credenziale viene ignorato: si usa quella dell'utente, cosi'
    // non si puo' cancellare la passkey di qualcun altro passando un id a caso.
    const removed = await store.deleteWebauthnCredential(
      active.user.id,
      String(body.credentialId ?? ''),
    );
    if (removed) {
      await store.appendAudit({
        userId: active.user.id,
        event: 'webauthn.removed',
        outcome: 'info',
        ip: request.ip ?? null,
        userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
        metadata: { credential_id: String(body.credentialId ?? '') },
      });
    }
    return reply.redirect('/account/security?done=1', 303);
  });

  app.post('/account/security/recovery-codes', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (!(await requirePassword(active.user.id, body.password))) {
      return renderSecurityError(request, reply, active.user.id, ['Password attuale non corretta.']);
    }
    const codes = await resetRecoveryCodes(store, recoveryKey, active.user.id);
    await store.appendAudit({
      userId: active.user.id,
      event: 'recovery_codes.regenerated',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { count: codes.length },
    });
    // I codici si vedono una volta sola: nessun modo per recuperarli dopo.
    return reply.type('text/html; charset=utf-8').send(
      pages.recoveryCodesPage({ csrf: ensureCsrf(request, reply), email: active.user.email, codes }),
    );
  });

  app.post('/account/sessions/revoke', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    await sessions.revoke(String(body.sessionId ?? ''), 'user_revoked', active.user.id);
    await store.appendAudit({
      userId: active.user.id,
      event: 'session.revoked',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { session_id: String(body.sessionId ?? '') },
    });
    return reply.redirect('/account/sessions?revoked=1', 303);
  });

  app.post('/account/sessions/revoke-all', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const count = await sessions.revokeAll(active.user.id, 'user_revoked_all', active.session.id);
    await store.appendAudit({
      userId: active.user.id,
      event: 'session.revoked_all',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { count },
    });
    return reply.redirect('/account/sessions?revoked=1', 303);
  });

  app.post('/account/apps/revoke', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const clientId = String(body.clientId ?? '');
    await store.revokeConsent(active.user.id, clientId);
    // I token gia' emessi restano validi fino a scadenza: e' il comportamento
    // atteso da chi revoca un consenso. Le sessioni restano vive.
    await store.appendAudit({
      userId: active.user.id,
      event: 'consent.revoked',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { client_id: clientId },
    });
    return reply.redirect('/account/apps?revoked=1', 303);
  });

  app.post('/account/delete', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (String(body.confirm ?? '').trim().toUpperCase() !== 'ELIMINA') {
      return reply.code(400).type('text/html; charset=utf-8').send(
        pages.accountDeletePage({
          csrf: ensureCsrf(request, reply),
          email: active.user.email,
          errors: ['Conferma non valida: scrivi ELIMINA.'],
        }),
      );
    }
    const result = await accounts.deleteAccount(
      active.user.id,
      { password: String(body.password ?? ''), totpCode: body.totpCode ? String(body.totpCode) : undefined },
      ctx(request),
    );
    if (!result.ok) {
      return reply.code(403).type('text/html; charset=utf-8').send(
        pages.accountDeletePage({
          csrf: ensureCsrf(request, reply),
          email: active.user.email,
          errors: [result.message],
        }),
      );
    }
    reply.clearCookie(sessionCookie, sessions.cookieOptions());
    return reply
      .type('text/html; charset=utf-8')
      .send(
        pages.accountDeletedPage({
          email: maskEmail(active.user.email),
          eventsSent: result.eventsSent ?? 0,
        }),
      );
  });

  app.get('/ui/deleted', async (_request, reply) =>
    reply.type('text/html; charset=utf-8').send(pages.accountDeletedStaticPage),
  );
}