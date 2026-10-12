import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import type { User } from '../domain/types.js';
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
  renderTotpQrSvg,
  webauthnRegistrationOptions,
  type ChallengeStore,
} from '../services/mfa.js';
import { sessionCookieName, type SessionManager } from '../services/session-manager.js';
import { maskEmail } from '../services/mailer.js';
import * as pages from '../ui/pages.js';
import { csrfInput, esc, layout } from './layout.js';
import type { AdministrationService } from '../services/administration.js';

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
  admin?: Pick<AdministrationService, 'listServices' | 'authorization'>;
  tokens?: OidcTokenStore;
}

export async function registerAccountRoutes(app: FastifyInstance, deps: AccountDeps): Promise<void> {
  const { config, store, accounts, sessions, challenges } = deps;
  const recoveryKey = hkdf(config.dataKey, 'engine-accounts/recovery-codes');

  const csrfCookie = csrfCookieName(config.cookiePrefix);
  const sessionCookie = sessionCookieName(config);

  const accountContext = async (user: User) => ({
    email: user.email,
    displayName: user.displayName,
    isGlobalAdmin: Boolean(user.isGlobalAdmin),
    adminDestinations: user.isGlobalAdmin ? [] : (await serviceRoles(user.id)).map(s => ({ href: `/admin/services/${encodeURIComponent(s.serviceId)}`, label: s.name })),
    userId: user.id,
    status: user.status,
    updatedAt: user.updatedAt,
    account: {
      id: user.id, status: user.status, createdAt: user.createdAt, updatedAt: user.updatedAt,
      lastLoginAt: user.lastLoginAt, emailVerifiedAt: user.emailVerifiedAt,
       mustChangePassword: user.mustChangePassword, isGlobalAdmin: user.isGlobalAdmin,
       totpEnabled: user.totpEnabled, failedLogins: user.failedLogins, lockedUntil: user.lockedUntil, blockedReason: user.blockedReason,
    },
  });

  async function serviceRoles(userId: string) {
    if (!deps.admin) return [];
    const services = await deps.admin.listServices();
    const roles = await Promise.all(services.map(async (service) => ({
      serviceId: service.serviceId, name: service.name,
      admin: (await deps.admin!.authorization(userId, service.serviceId)).admin,
    })));
    return roles.filter((role) => role.admin);
  }

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
    reply.header('Cache-Control', 'no-store');
    if (active.user.mustChangePassword) {
      reply.redirect('/ui/force-password-change', 303);
      return undefined;
    }
    const settings = await accounts.effectivePolicy();
    if (settings.EMAIL_VERIFICATION_REQUIRED && !active.user.emailVerifiedAt) {
      reply.code(403).send({ error: 'email_verification_required' });
      return undefined;
    }
    if (settings.TOTP_REQUIRED && !active.user.totpEnabled && ![
      '/account/security', '/account/security/totp/setup', '/account/security/totp/confirm', '/account/logout',
    ].includes(request.url.split('?')[0]!)) {
      reply.redirect('/account/security/totp/setup', 303);
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
    const [sessionOverview, consents, credentials, recoveryLeft] = await Promise.all([
      sessions.overview(user.id, session.id),
      store.listConsents(user.id),
      store.listWebauthnCredentials(user.id),
      store.countUnusedRecoveryCodes(user.id),
    ]);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountHomePage({
          ...await accountContext(user),
        ...{ sessionOverview, currentSession: sessionOverview.groups.flatMap((g) => g.sessions).find((s) => s.current) },
        csrf,
        email: user.email,
        displayName: user.displayName,
        emailVerified: Boolean(user.emailVerifiedAt),
        createdAt: user.createdAt,
        sessions: sessionOverview.counts.active,
        consents: consents.filter((c) => !c.revokedAt && (!c.expiresAt || c.expiresAt.getTime() > Date.now())).length,
        lastActivity: user.lastLoginAt,
        isGlobalAdmin: Boolean(user.isGlobalAdmin),
        hasTotp: user.totpEnabled,
        passkeys: credentials.length,
        recoveryLeft,
      }),
    );
  });

  app.get('/account/profile', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const query = (request.query ?? {}) as { saved?: string; email?: string };
    return reply.type('text/html; charset=utf-8').send(pages.accountProfilePage({
      ...await accountContext(active.user),
      csrf: ensureCsrf(request, reply),
      emailVerified: Boolean(active.user.emailVerifiedAt),
      flash: query.saved === '1' ? { kind: 'ok', text: 'Nome aggiornato.' }
        : query.email === 'sent' ? { kind: 'info', text: 'Controlla il nuovo indirizzo email per confermare la modifica.' }
        : query.email === 'failed' ? { kind: 'error', text: 'Non è stato possibile richiedere la modifica dell’email.' } : undefined,
    }));
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
        ...await accountContext(active.user),
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        hasTotp: active.user.totpEnabled,
        totpConfirmed: Boolean(totp?.confirmedAt),
        passkeys: credentials.map((c) => ({
          ...c,
          label: c.nickname ?? `Passkey ${c.credentialId.slice(-6)}`,
        })),
        recoveryLeft,
        flash: (request.query as { error?: string } | undefined)?.error === 'passkey'
          ? { kind: 'error', text: 'La passkey non è stata registrata. La richiesta potrebbe essere scaduta, annullata o non valida. Avvia una nuova registrazione dalla sezione Passkey.' }
          : (request.query as { admin?: string } | undefined)?.admin === 'mfa-required'
          ? { kind: 'info', text: 'Per accedere all’Amministrazione devi prima attivare un secondo fattore: TOTP oppure una passkey. Configuralo qui, poi riapri il pannello Amministrazione.' }
          : (request.query as { done?: string } | undefined)?.done
            ? { kind: 'ok', text: 'Fatto.' }
            : undefined,
      }),
    );
  });

  app.get('/account/sessions', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const sessionOverview = await sessions.overview(active.user.id, active.session.id);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountSessionsPage({
        ...await accountContext(active.user),
        ...{ sessionOverview },
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        sessions: sessionOverview.groups.flatMap((g) => g.sessions),
        flash: (request.query as { revoked?: string } | undefined)?.revoked === 'all'
          ? { kind: 'ok', text: 'Tutte le altre sessioni sono state revocate. Questa sessione resta attiva.' }
          : (request.query as { revoked?: string } | undefined)?.revoked
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
        ...await accountContext(active.user),
        csrf: ensureCsrf(request, reply),
        email: active.user.email,
        consents,
        flash: (request.query as { revoked?: string } | undefined)?.revoked
          ? { kind: 'ok', text: 'Consenso revocato.' }
          : undefined,
      }),
    );
  });

  app.get('/account/services', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const csrf = ensureCsrf(request, reply);
    const [services, clients, consents] = await Promise.all([
      deps.admin ? deps.admin.listServices() : store.listServices(), store.listClients(), store.listConsents(active.user.id),
    ]);
    const groups = await Promise.all(services.map(async (service) => {
      const serviceClients = clients.filter((c) => c.audience === service.audience);
      const linked = consents.filter((c) => serviceClients.some((client) => client.clientId === c.clientId));
      const role = deps.admin ? await deps.admin.authorization(active.user.id, service.serviceId) : { admin: false };
      if (!linked.length && !role.admin) return '';
      const adminUrl = 'adminUrl' in service ? service.adminUrl : null;
      const enabled = service.enabled && serviceClients.some((c) => c.enabled);
      return `<section class="panel"><h2>${esc(service.name)} ${role.admin && enabled ? '<span class="badge">Admin</span>' : ''}</h2>
        <p><code>${esc(service.audience)}</code> · ${enabled ? 'Disponibile' : 'Disabilitato'}</p>
        ${role.admin && enabled ? `<p><a href="/admin/services/${encodeURIComponent(service.serviceId)}">Amministra collegamenti</a>${pages.safeExternalUrl(adminUrl) ? ` · <a href="${esc(adminUrl)}">Apri amministrazione servizio</a>` : ''}</p>` : ''}
        ${linked.length ? `<ul class="list">${linked.map((c) => `<li><div><strong>${esc(c.clientName)}</strong><p><code>${esc(c.clientId)}</code></p><p>Scope: ${esc(c.scope.join(' '))}</p><p>Concesso: ${esc(c.grantedAt.toISOString())}${c.revokedAt ? ' · Revocato' : ''}</p></div>${!c.revokedAt ? `<form method="post" action="/account/apps/revoke">${csrfInput(csrf)}<input type="hidden" name="clientId" value="${esc(c.clientId)}"><button class="secondary">Revoca consenso</button></form>` : ''}</li>`).join('')}</ul>` : '<p>Nessun consenso concesso.</p>'}</section>`;
    }));
    return reply.header('Cache-Control', 'no-store').type('text/html; charset=utf-8').send(layout({
      title: 'Servizi collegati', width: 'wide', csrf, userEmail: active.user.email, admin: Boolean(active.user.isGlobalAdmin), adminDestinations: (await accountContext(active.user)).adminDestinations,
      body: `<h1>Servizi collegati</h1><p>I collegamenti usano il normale SSO, senza token amministrativi nell’URL.</p>${groups.join('') || '<p>Nessun servizio collegato.</p>'}`,
    }));
  });

  app.get('/account/activity', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    const [entries, total] = await Promise.all([store.listAudit(active.user.id, 100), store.countAudit(active.user.id)]);
    return reply.type('text/html; charset=utf-8').send(
      pages.accountActivityPage({
        ...await accountContext(active.user),
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
        ...await accountContext(active.user),
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
      pages.accountDeletePage({ ...await accountContext(active.user), csrf: ensureCsrf(request, reply), email: active.user.email }),
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
          ...await accountContext(active.user),
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
        ...(user ? await accountContext(user) : {}),
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
    if (active.user.totpEnabled || (await store.getTotp(active.user.id))?.confirmedAt) return reply.redirect('/account/security', 303);
    // Il segreto appena generato vive in challenge: non finisce nell'URL.
    const { secret, uri } = await startTotpEnrolment(store, config, active.user);
    challenges.set(`totp-setup:${active.user.id}`, { kind: 'totp', value: secret, createdAt: Date.now() });
    return reply
      .type('text/html; charset=utf-8')
      .send(pages.totpSetupPage({ ...await accountContext(active.user), csrf: ensureCsrf(request, reply), email: active.user.email, secret, uri, qrSvg: await renderTotpQrSvg(uri), invalid: (request.query as { invalid?: string }).invalid === '1' }));
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
    if ((await accounts.effectivePolicy()).TOTP_REQUIRED) return reply.code(403).send({ error: 'totp_required' });
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
    const options = await webauthnRegistrationOptions(config, active.user, await store.listWebauthnCredentials(active.user.id));
    challenges.set(`webauthn-register:${active.session.id}`, {
      kind: 'webauthn',
      value: options.challenge,
      createdAt: Date.now(),
    });
    return reply
      .type('text/html; charset=utf-8')
      .send(
        pages.webauthnRegisterPage({
          ...await accountContext(active.user),
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
    const challenge = challenges.take(`webauthn-register:${active.session.id}`);
    if (!challenge || challenge.kind !== 'webauthn') return reply.redirect('/account/security?error=passkey', 303);
    let parsed: unknown;
    try { parsed = JSON.parse(String(body.webauthnResponse ?? '{}')) as unknown; }
    catch { return reply.redirect('/account/security?error=passkey', 303); }
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
    await store.addWebauthnCredential({ userId: active.user.id, ...result.draft, nickname: typeof body.nickname === 'string' ? body.nickname.trim().slice(0, 64) || null : null });
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
      pages.recoveryCodesPage({ ...await accountContext(active.user), csrf: ensureCsrf(request, reply), email: active.user.email, codes }),
    );
  });

  app.post('/account/sessions/revoke', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const sessionId = String(body.sessionId ?? '');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
      return reply.code(400).send({ error: 'invalid_session_id' });
    }
    const revoked = await sessions.revoke(sessionId, 'user_revoked', active.user.id);
    if (!revoked) return reply.code(404).send({ error: 'session_not_found' });
    await store.appendAudit({
      userId: active.user.id,
      event: 'session.revoked',
      outcome: 'info',
      ip: request.ip ?? null,
      userAgent: (request.headers['user-agent'] as string | undefined) ?? null,
      metadata: { session_id: sessionId },
    });
    if (sessionId === active.session.id) {
      reply.clearCookie(sessionCookie, sessions.cookieOptions());
      return reply.redirect('/ui/login', 303);
    }
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
    return reply.redirect('/account/sessions?revoked=all', 303);
  });

  app.post('/account/apps/revoke', async (request, reply) => {
    const active = await requireSession(request, reply);
    if (!active) return reply;
    if (!checkCsrf(request)) return csrfFailure(reply);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const clientId = String(body.clientId ?? '');
    await store.revokeConsent(active.user.id, clientId);
    if (deps.tokens) {
      const tokens = await deps.tokens.listUserTokens(active.user.id);
      const grantIds = new Set(tokens.filter((t) => t.clientId === clientId && t.grantId).map((t) => t.grantId!));
      for (const grantId of grantIds) await deps.tokens.revokeByGrantId(grantId);
    }
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
