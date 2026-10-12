import crypto from 'node:crypto';
import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import type { Amr, User } from '../domain/types.js';
import { hkdf } from '../config.js';
import { hmacSha256 } from '../security/crypto.js';
import {
  NEUTRAL_DELIVERY,
  NEUTRAL_REGISTRATION,
  formatMagicCode,
} from '../security/timing.js';
import { decoyVerify, hashPassword, verifyPassword } from '../security/password.js';
import type { RateLimiter } from '../security/rate-limit.js';
import type { BreachedChecker } from '../security/breached-passwords.js';
import type { Mailer, MailMessage } from './mailer.js';
import { emailChangeTemplate, magicCodeTemplate, passwordResetTemplate, verifyEmailTemplate } from './templates.js';
import type { EventEmitter } from './account-deleted-event.js';
import { createLogger } from '../logger.js';

const logger = createLogger((process.env.LOG_LEVEL as never) ?? 'info', { svc: 'engine-accounts' });

/**
 * Flussi account: registrazione, verifica email, login, reset, cambio email,
 * cambio password con riautenticazione, cancellazione.
 *
 * Due regole ovunque:
 *  - **anti-enumerazione**: la risposta non distingue mai "non esiste" da
 *    "esiste", e il tempo di risposta e' uniformato (vedi `security/timing.ts`);
 *  - **audit**: ogni evento di sicurezza finisce in `audit_log`, che e' append-only.
 */

export interface PasswordPolicyResult {
  ok: boolean;
  reason?: 'too_short' | 'too_long' | 'compromised' | 'common' | 'empty';
  detail?: string;
  /** Da registrare in audit: `hibp` o `local` quando la password e' compromessa. */
  source?: string;
}

export interface AuthOutcome {
  status: 'ok' | 'invalid' | 'blocked' | 'locked' | 'unverified';
  user?: User;
  retryAfterSeconds?: number;
}

export interface RequestContext {
  ip: string | null;
  userAgent: string | null;
}

export class AccountService {
  /** Chiave per i digest HMAC dei token monouso: scope separato dagli altri usi. */
  private readonly tokenKey: Buffer;

  constructor(
    private readonly deps: {
      config: Config;
      db: Db;
      store: AccountsStore;
      tokens: OidcTokenStore;
      mailer: Mailer;
      breached: BreachedChecker;
      limiter: RateLimiter;
      events: EventEmitter;
      now?: () => Date;
    },
  ) {
    this.tokenKey = hkdf(deps.config.dataKey, 'engine-accounts/one-time-tokens');
  }

  private get config(): Config {
    return this.deps.config;
  }
  private get store(): AccountsStore {
    return this.deps.store;
  }
  private now(): Date {
    return this.deps.now?.() ?? new Date();
  }

  /* ------------------------------------------------------------------ */
  /* normalizzazione                                                      */
  /* ------------------------------------------------------------------ */

  /** L'email e' identificatore di accesso: normalizzata e minuscola. */
  static normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  digest(token: string): string {
    return hmacSha256(this.tokenKey, token);
  }

  /* ------------------------------------------------------------------ */
  /* politica password                                                    */
  /* ------------------------------------------------------------------ */

  async checkPassword(password: string): Promise<PasswordPolicyResult> {
    if (!password || password.length === 0) return { ok: false, reason: 'empty' };
    // Limite inferiore 12: sotto, la forza e' piu\' una barriera d'ingresso che
    // una protezione. Limite superiore = tetto anti-DoS (vedi security/password.ts).
    if (password.length < this.config.PASSWORD_MIN_LENGTH) return { ok: false, reason: 'too_short' };
    if (Buffer.byteLength(password, 'utf8') > this.config.PASSWORD_MAX_LENGTH * 4) {
      return { ok: false, reason: 'too_long' };
    }
    const verdict = await this.deps.breached.check(password);
    if (verdict.breached) return { ok: false, reason: 'compromised', source: verdict.source };
    return { ok: true };
  }

  /* ------------------------------------------------------------------ */
  /* registrazione                                                        */
  /* ------------------------------------------------------------------ */

  /**
   * Registrazione. Risposta **neutra** sempre: se l'email esiste gia' non si
   * dice nulla (l'utente riceve comunque la stessa email di verifica, cosicome
   * non puo' capire se l'indirizzo e' libero). Il tempo e' uniformato dal
   * chiamante e dal fatto che l'hash argon2 gira comunque.
   */
  async register(
    input: { email: string; password: string; displayName?: string | null },
    ctx: RequestContext,
  ): Promise<{ accepted: true; message: string; createdUserId?: string }> {
    const email = AccountService.normalizeEmail(input.email);
    const ipKey = ctx.ip ?? 'unknown';

    if (!this.deps.limiter.checkIp(`register:ip:${ipKey}`).allowed) {
      await this.store.appendAudit({
        event: 'register.rate_limited',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      // Risposta identica: il rate limit non deve diventare un oracolo.
      return { accepted: true, message: NEUTRAL_REGISTRATION };
    }

    const policy = await this.checkPassword(input.password);
    const existing = await this.store.findUserByEmailAnyStatus(email);

    if (existing?.status === 'deleted') {
      // Tombstone: l'email resta occupata per sempre, cosi' nessuno puo'
      // riaccapitolare un account cancellato ri-registrandolo.
      await this.store.appendAudit({
        event: 'register.rejected_deleted_email',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { email_domain: email.split('@')[1] ?? '' },
      });
      return { accepted: true, message: NEUTRAL_REGISTRATION };
    }

    if (!policy.ok) {
      await this.store.appendAudit({
        userId: existing?.id ?? null,
        event: 'register.rejected_policy',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { reason: policy.reason, source: policy.source ?? null },
      });
      return { accepted: true, message: NEUTRAL_REGISTRATION, ...(policy.reason === 'compromised' ? {} : {}) };
    }

    if (existing) {
      // Email gia' registrata: si rispedia il token di verifica a chi chiede,
      // cosi' la risposta resta identica. Nessuna hint di esistenza.
      await this.sendVerificationEmail(existing, ctx);
      await this.store.appendAudit({
        userId: existing.id,
        event: 'register.duplicate_resent',
        outcome: 'info',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { accepted: true, message: NEUTRAL_REGISTRATION };
    }

    const passwordHash = await hashPassword(input.password, this.config);
    const user = await this.store.createUser({
      email,
      passwordHash,
      displayName: input.displayName?.trim() || null,
      emailVerifiedAt: null,
    });

    await this.sendVerificationEmail(user, ctx);
    await this.store.appendAudit({
      userId: user.id,
      event: 'register.created',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { email_verified: false },
    });

    return { accepted: true, message: NEUTRAL_REGISTRATION, createdUserId: user.id };
  }

  /**
   * Crea il token monouso di verifica e manda l'email.
   *
   * **Un errore di posta non è un errore di registrazione.** Se l'SMTP non
   * risponde, l'utente è già nel database e il token è già valido: far
   * fallire la richiesta restituirebbe un 500 su un account che esiste,
   * renderebbe la risposta diversa da quella del caso "email già registrata" e
   * romperebbe la promessa di risposta neutra. L'invio passa quindi da
   * `sendMail`, che registra e va avanti.
   */
  private async sendVerificationEmail(user: User, _ctx: RequestContext): Promise<void> {
    const token = crypto.randomBytes(32).toString('base64url');
    const ttl = this.config.EMAIL_VERIFICATION_TTL;
    await this.store.invalidateAccountTokens(user.id, 'email_verification');
    await this.store.createAccountToken({
      userId: user.id,
      purpose: 'email_verification',
      tokenDigest: this.digest(token),
      expiresAt: new Date(this.now().getTime() + ttl * 1000),
      targetEmail: user.email,
      payload: {},
    });
    const minutes = Math.round(ttl / 60);
    const actionUrl = `${this.config.baseUrl}/ui/verify-email?token=${encodeURIComponent(token)}`;
    const template = verifyEmailTemplate({ config: this.config, actionUrl, minutes });
    await this.sendMail(user.id, { to: user.email, ...template }, 'email_verification');
  }

  /**
   * Invio di un'email transazionale che **non deve mai far fallire** la
   * richiesta che l'ha generata.
   *
   * In tutti e quattro i casi (verifica, reset, cambio email, magic code) il
   * token e' gia' stato scritto in tabella e l'utente puo' chiedere una nuova
   * email. Se l'SMTP non risponde e l'errore esce, la risposta diventa un 500
   * diverso dal caso normale — il che rompe due cose: la promessa di risposta
   * neutra (l'unica traccia di esistenza dell'account) e la promessa che
   * registrare un account non dipenda dalla posta.
   *
   * Quindi: si registra l'insuccesso dove si vede (log + audit) e si risponde
   * come se fosse andato tutto bene. Il token scadera e l'utente riprova.
   */
  private async sendMail(userId: string | null, message: MailMessage, purpose: string): Promise<boolean> {
    try {
      await this.deps.mailer.send(message);
      return true;
    } catch (err) {
      logger.warn('invio email fallito', {
        user_id: userId,
        purpose,
        err: (err as Error).message.slice(0, 160),
      });
      await this.store
        .appendAudit({
          userId,
          event: 'email.send_failed',
          outcome: 'failure',
          metadata: { purpose },
        })
        .catch(() => undefined);
      return false;
    }
  }

  /* ------------------------------------------------------------------ */
  /* verifica email                                                       */
  /* ------------------------------------------------------------------ */

  async verifyEmailToken(token: string, ctx: RequestContext): Promise<{ ok: boolean; email?: string }> {
    const record = await this.store.findAccountToken('email_verification', this.digest(token));
    if (!record || record.consumedAt || record.expiresAt <= this.now()) {
      await this.store.appendAudit({
        event: 'email_verify.failed',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { reason: !record ? 'unknown_token' : record.consumedAt ? 'already_used' : 'expired' },
      });
      return { ok: false };
    }
    // Monouso: il consumo avviene prima dell'aggiornamento, in modo che un
    // doppio click non ri-applichi il cambiamento.
    await this.store.consumeAccountToken(record.id);
    await this.store.updateUser(record.userId, { emailVerifiedAt: this.now() });
    await this.store.appendAudit({
      userId: record.userId,
      event: 'email_verify.success',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: {},
    });
    return { ok: true, email: record.targetEmail };
  }

  /* ------------------------------------------------------------------ */
  /* login                                                               */
  /* ------------------------------------------------------------------ */

  /**
   * Verifica password con tempi uniformi.
   *
   * - utente inesistente   -> verifica argon2 su hash "morto" (stesso costo)
   * - utente bloccato      -> verifica comunque, poi rifiuto esplicito
   * - lockout progressivo -> applicato dal limiter, non dal DB (il DB tiene il
   *   contatore per l'operatore e per il riavvio del servizio)
   */
  async authenticate(email: string, password: string, ctx: RequestContext): Promise<AuthOutcome> {
    const normalized = AccountService.normalizeEmail(email);
    const user = await this.store.findUserByEmail(normalized);
    const accountKey = normalized;

    if (!user) {
      await decoyVerify(password, this.config);
      this.deps.limiter.registerAccountFailure(accountKey);
      await this.store.appendAudit({
        event: 'login.unknown_user',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { email_domain: normalized.split('@')[1] ?? '' },
      });
      return { status: 'invalid' };
    }

    const ok = await verifyPassword(user.passwordHash, password, this.config);
    if (!ok) {
      const verdict = this.deps.limiter.registerAccountFailure(accountKey);
      const failed = user.failedLogins + 1;
      const lockedUntil = verdict.lockMs > 0 ? new Date(this.now().getTime() + verdict.lockMs) : null;
      await this.store.recordLoginFailure(user.id, lockedUntil, failed);
      await this.store.appendAudit({
        userId: user.id,
        event: 'login.bad_password',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { failed_logins: failed, locked: Boolean(lockedUntil), retry_after_s: verdict.retryAfterSeconds },
      });
      if (user.status === 'blocked') return { status: 'blocked', retryAfterSeconds: verdict.retryAfterSeconds };
      return { status: 'invalid', retryAfterSeconds: verdict.retryAfterSeconds };
    }

    if (user.status === 'blocked') {
      await this.store.appendAudit({
        userId: user.id,
        event: 'login.blocked_account',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { reason: user.blockedReason },
      });
      return { status: 'blocked' };
    }

    if (user.status === 'deleted') {
      return { status: 'invalid' };
    }

    // Lockout scaduto e password corretta: si azzera il contatore.
    this.deps.limiter.registerAccountSuccess(accountKey);
    if (user.failedLogins > 0 || user.lockedUntil) {
      await this.store.recordLoginFailure(user.id, null, 0);
    }

    return { status: 'ok', user };
  }

  /** Segna il login riuscito (usata dal flusso di interazione, dopo l'MFA). */
  async onLoginSucceeded(user: User, amr: Amr[], ctx: RequestContext, providerSessionId?: string, providerSessionUid?: string): Promise<void> {
    await this.store.updateUser(user.id, { lastLoginAt: this.now() });
    await this.store.appendAudit({
      userId: user.id,
      event: 'login.success',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { amr },
    });
    void providerSessionId;
    void providerSessionUid;
  }

  /* ------------------------------------------------------------------ */
  /* reset password                                                       */
  /* ------------------------------------------------------------------ */

  /** Richiesta di reset: risposta neutra sempre (CWE-203). */
  async requestPasswordReset(email: string, ctx: RequestContext): Promise<{ message: string }> {
    const normalized = AccountService.normalizeEmail(email);
    const rate = this.deps.limiter.checkIp(`reset:ip:${ctx.ip ?? 'unknown'}`);
    if (!rate.allowed) return { message: NEUTRAL_DELIVERY };

    const user = await this.store.findUserByEmail(normalized);
    if (!user || user.status === 'blocked') {
      // Nessun account (o bloccato): non si invia e non si dice.
      await this.store.appendAudit({
        event: 'password_reset.requested_unknown',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { message: NEUTRAL_DELIVERY };
    }

    const token = crypto.randomBytes(32).toString('base64url');
    const ttl = this.config.PASSWORD_RESET_TTL;
    await this.store.invalidateAccountTokens(user.id, 'password_reset');
    await this.store.createAccountToken({
      userId: user.id,
      purpose: 'password_reset',
      tokenDigest: this.digest(token),
      expiresAt: new Date(this.now().getTime() + ttl * 1000),
      targetEmail: user.email,
      payload: {},
    });
    const minutes = Math.round(ttl / 60);
    const actionUrl = `${this.config.baseUrl}/ui/reset-password?token=${encodeURIComponent(token)}`;
    const template = passwordResetTemplate({ config: this.config, actionUrl, minutes });
    await this.sendMail(user.id, { to: user.email, ...template }, 'password_reset');
    await this.store.appendAudit({
      userId: user.id,
      event: 'password_reset.requested',
      outcome: 'info',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: {},
    });
    return { message: NEUTRAL_DELIVERY };
  }

  /** Reset col token monouso. Al successo: sessioni e token di refresh revocati. */
  async resetPassword(token: string, newPassword: string, ctx: RequestContext): Promise<{ ok: boolean; message: string }> {
    const record = await this.store.findAccountToken('password_reset', this.digest(token));
    if (!record || record.consumedAt || record.expiresAt <= this.now()) {
      await this.store.appendAudit({
        event: 'password_reset.failed',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { reason: !record ? 'unknown_token' : record.consumedAt ? 'already_used' : 'expired' },
      });
      return { ok: false, message: 'Link non valido o scaduto. Richiedine uno nuovo.' };
    }

    const policy = await this.checkPassword(newPassword);
    if (!policy.ok) {
      await this.store.appendAudit({
        userId: record.userId,
        event: 'password_reset.rejected_policy',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { reason: policy.reason },
      });
      return { ok: false, message: 'Password non accettata.' };
    }

    await this.store.consumeAccountToken(record.id);
    const passwordHash = await hashPassword(newPassword, this.config);
    await this.store.updateUser(record.userId, { passwordHash, failedLogins: 0, lockedUntil: null });
    // Cambiamento di password = revoca di tutto quello che era gia' stato emesso.
    const revokedSessions = await this.store.revokeAllSessions(record.userId, 'password_reset');
    const revokedTokens = await this.deps.tokens.revokeUserGrants(record.userId);
    this.deps.limiter.reset(record.targetEmail);
    await this.store.appendAudit({
      userId: record.userId,
      event: 'password_reset.success',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { sessions_revoked: revokedSessions.length, tokens_revoked: revokedTokens },
    });
    return { ok: true, message: 'Password aggiornata. Puoi accedere con la nuova.' };
  }

  /* ------------------------------------------------------------------ */
  /* cambio password (con riautenticazione)                               */
  /* ------------------------------------------------------------------ */

  /**
   * Cambio password: richiede la **password attuale** (riautenticazione).
   * Un furto di sessione senza la password non deve poter cambiare la password
   * e bloccare il proprietario fuori (ASVS 3.3.2 / V6).
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ctx: RequestContext,
  ): Promise<{ ok: boolean; message: string; reason?: string }> {
    const user = await this.store.findUserById(userId);
    if (!user) return { ok: false, message: 'Account non trovato.' };

    const currentOk = await verifyPassword(user.passwordHash, currentPassword, this.config);
    if (!currentOk) {
      await this.store.appendAudit({
        userId,
        event: 'password_change.rejected_reauth',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { ok: false, message: 'Password attuale non corretta.', reason: 'reauth_failed' };
    }

    const policy = await this.checkPassword(newPassword);
    if (!policy.ok) {
      await this.store.appendAudit({
        userId,
        event: 'password_change.rejected_policy',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { reason: policy.reason },
      });
      const messages: Record<string, string> = {
        too_short: `La password deve avere almeno ${this.config.PASSWORD_MIN_LENGTH} caratteri.`,
        too_long: 'Password troppo lunga.',
        compromised: 'Questa password compare in elenchi di password compromesse: scegline un\'altra.',
        common: 'Questa password e\' troppo comune: scegline un\'altra.',
        empty: 'Password obbligatoria.',
      };
      return { ok: false, message: messages[policy.reason ?? 'empty'] ?? 'Password non accettata.', reason: policy.reason };
    }

    if (await verifyPassword(user.passwordHash, newPassword, this.config)) {
      return { ok: false, message: 'La nuova password deve essere diversa da quella attuale.', reason: 'same_password' };
    }

    const passwordHash = await hashPassword(newPassword, this.config);
    await this.store.updateUser(userId, { passwordHash, failedLogins: 0, lockedUntil: null });
    const revokedTokens = await this.deps.tokens.revokeUserGrants(userId);
    await this.store.appendAudit({
      userId,
      event: 'password_change.success',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { tokens_revoked: revokedTokens },
    });
    return { ok: true, message: 'Password aggiornata.' };
  }

  /* ------------------------------------------------------------------ */
  /* cambio email                                                         */
  /* ------------------------------------------------------------------ */

  /** Richiesta di cambio email: il token va al NUOVO indirizzo (prova di possesso). */
  async requestEmailChange(userId: string, newEmail: string, ctx: RequestContext): Promise<{ ok: boolean; message: string }> {
    const normalized = AccountService.normalizeEmail(newEmail);
    const user = await this.store.findUserById(userId);
    if (!user) return { ok: false, message: 'Account non trovato.' };
    if (normalized === user.email) return { ok: false, message: 'Il nuovo indirizzo e\' uguale a quello attuale.' };

    const taken = await this.store.findUserByEmailAnyStatus(normalized);
    if (taken && taken.id !== userId) {
      await this.store.appendAudit({
        userId,
        event: 'email_change.rejected_taken',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { ok: false, message: 'Indirizzo non disponibile.' };
    }

    const token = crypto.randomBytes(32).toString('base64url');
    const ttl = this.config.EMAIL_CHANGE_TTL;
    await this.store.invalidateAccountTokens(userId, 'email_change');
    await this.store.createAccountToken({
      userId,
      purpose: 'email_change',
      tokenDigest: this.digest(token),
      payload: { newEmail: normalized },
      expiresAt: new Date(this.now().getTime() + ttl * 1000),
      targetEmail: normalized,
    });
    const minutes = Math.round(ttl / 60);
    const actionUrl = `${this.config.baseUrl}/account/confirm-email?token=${encodeURIComponent(token)}`;
    const template = emailChangeTemplate({ config: this.config, actionUrl, minutes });
    await this.sendMail(userId, { to: normalized, ...template }, 'email_change');
    await this.store.appendAudit({
      userId,
      event: 'email_change.requested',
      outcome: 'info',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: {},
    });
    return { ok: true, message: `Ti abbiamo scritto all\'indirizzo nuovo per confermarlo.` };
  }

  async confirmEmailChange(token: string, ctx: RequestContext): Promise<{ ok: boolean; message: string }> {
    const record = await this.store.findAccountToken('email_change', this.digest(token));
    if (!record || record.consumedAt || record.expiresAt <= this.now()) {
      await this.store.appendAudit({
        event: 'email_change.failed',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { ok: false, message: 'Link non valido o scaduto.' };
    }
    const newEmail = String(record.payload.newEmail ?? record.targetEmail);
    const taken = await this.store.findUserByEmailAnyStatus(newEmail);
    if (taken && taken.id !== record.userId) {
      return { ok: false, message: 'Indirizzo non disponibile.' };
    }
    await this.store.consumeAccountToken(record.id);
    // Il nuovo indirizzo non e' verificato finche' non si conferma... ma il token
    // *è* la conferma di possesso: l'indirizzo e' verificato per costruzione.
    await this.store.updateUserEmail(record.userId, newEmail, this.now());
    await this.store.appendAudit({
      userId: record.userId,
      event: 'email_change.success',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: {},
    });
    return { ok: true, message: 'Indirizzo email aggiornato.' };
  }

  /* ------------------------------------------------------------------ */
  /* codice di accesso (magic link)                                       */
  /* ------------------------------------------------------------------ */

  /**
   * Codice di accesso monouso al posto della password: utile per TV e per
   * accesso a dispositivo sconosciuto. Stessa enfasi anti-enumerazione del reset.
   */
  async requestMagicCode(email: string, ctx: RequestContext): Promise<{ message: string }> {
    const normalized = AccountService.normalizeEmail(email);
    const rate = this.deps.limiter.checkIp(`magic:ip:${ctx.ip ?? 'unknown'}`);
    if (!rate.allowed) return { message: NEUTRAL_DELIVERY };

    const user = await this.store.findUserByEmail(normalized);
    if (!user || user.status !== 'active') {
      await this.store.appendAudit({
        event: 'magic_code.requested_unknown',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { message: NEUTRAL_DELIVERY };
    }

    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    await this.store.createAccountToken({
      userId: user.id,
      purpose: 'magic_code',
      tokenDigest: this.digest(code),
      expiresAt: new Date(this.now().getTime() + this.config.MAGIC_CODE_TTL * 1000),
      targetEmail: user.email,
      payload: {},
    });
    const minutes = Math.round(this.config.MAGIC_CODE_TTL / 60);
    const template = magicCodeTemplate({ config: this.config, code: formatMagicCode(code), minutes });
    await this.sendMail(user.id, { to: user.email, ...template }, 'magic_code');
    await this.store.appendAudit({
      userId: user.id,
      event: 'magic_code.requested',
      outcome: 'info',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: {},
    });
    return { message: NEUTRAL_DELIVERY };
  }

  async consumeMagicCode(email: string, code: string, ctx: RequestContext): Promise<AuthOutcome> {
    const normalized = AccountService.normalizeEmail(email);
    const user = await this.store.findUserByEmail(normalized);
    if (!user) {
      await this.store.appendAudit({
        event: 'magic_code.unknown_user',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { status: 'invalid' };
    }
    const record = await this.store.findAccountToken('magic_code', this.digest(code));
    if (!record || record.consumedAt || record.expiresAt <= this.now() || record.userId !== user.id) {
      const verdict = this.deps.limiter.registerAccountFailure(normalized);
      await this.store.appendAudit({
        userId: user.id,
        event: 'magic_code.invalid',
        outcome: 'failure',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { retry_after_s: verdict.retryAfterSeconds },
      });
      return { status: 'invalid', retryAfterSeconds: verdict.retryAfterSeconds };
    }
    if (user.status === 'blocked') return { status: 'blocked' };
    await this.store.consumeAccountToken(record.id);
    this.deps.limiter.registerAccountSuccess(normalized);
    return { status: 'ok', user };
  }

  /* ------------------------------------------------------------------ */
  /* cancellazione account (C11)                                          */
  /* ------------------------------------------------------------------ */

  /**
   * Cancellazione account con riautenticazione. Ordine deliberato:
   *  1. reautentica (password o TOTP);
   *  2. revoca sessioni, token, consensi, MFA;
   *  3. anonimizza l'utente (l'`sub` resta: e' l'identificatore stabile e non
   *     deve mai essere riusato, vedi contratto 5);
   *  4. emette `account.deleted` a ogni client con backchannel (C11).
   *
   * L'anonimizzazione avviene **prima** dell'evento, cosi' l'evento viaggia con
   * il `sub` vero ma senza che i dati personali restino nel nostro DB.
   */
  async deleteAccount(
    userId: string,
    reauth: { password: string; totpCode?: string },
    ctx: RequestContext,
  ): Promise<{ ok: boolean; message: string; reason?: string; eventsSent?: number }> {
    const user = await this.store.findUserById(userId);
    if (!user || user.status === 'deleted') return { ok: false, message: 'Account non trovato.' };

    const passwordOk = await verifyPassword(user.passwordHash, reauth.password, this.config);
    if (!passwordOk) {
      await this.store.appendAudit({
        userId,
        event: 'account_delete.rejected_reauth',
        outcome: 'denied',
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: {},
      });
      return { ok: false, message: 'Password non corretta.', reason: 'reauth_failed' };
    }

    // Client che hanno ottenuto un consenso: ricevono l'evento.
    const clients = (await this.store.listClients()).filter(
      (c) => c.enabled && c.backchannelEventsUri,
    );

    // 1. revoca di tutto il materiale autenticativo
    await this.store.revokeAllSessions(userId, 'account_deleted');
    const revokedTokens = await this.deps.tokens.revokeUserGrants(userId);
    await this.store.revokeAllConsents(userId);
    await this.store.deleteTotp(userId);
    await this.store.deleteRecoveryCodes(userId);
    for (const credential of await this.store.listWebauthnCredentials(userId)) {
      await this.store.deleteWebauthnCredential(userId, credential.credentialId);
    }
    await this.store.invalidateAccountTokens(userId, 'password_reset');
    await this.store.invalidateAccountTokens(userId, 'magic_code');
    await this.store.invalidateAccountTokens(userId, 'email_change');

    // 2. anonimizzazione: la riga resta (sub stabile), i dati no.
    //    L'hash della password diventa casuale: nessun login e' possibile.
    const tombstoneEmail = `deleted+${userId.replace(/-/g, '')}@deleted.invalid`;
    const randomHash = await hashPassword(crypto.randomBytes(32).toString('base64url'), this.config);
    await this.store.updateUser(userId, {
      email: tombstoneEmail,
      passwordHash: randomHash,
      displayName: null,
      emailVerifiedAt: null,
      totpEnabled: false,
      status: 'deleted',
      deletedAt: this.now(),
      failedLogins: 0,
      lockedUntil: null,
    });

    await this.store.appendAudit({
      userId,
      subjectId: userId,
      event: 'account_delete.success',
      outcome: 'success',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { tokens_revoked: revokedTokens, clients_notified: clients.length },
    });

    // 3. evento back-channel (C11)
    const result = await this.deps.events.emitForClients(userId, clients);
    return { ok: true, message: 'Account eliminato.', eventsSent: result.delivered };
  }

  /* ------------------------------------------------------------------ */
  /* esportazione dati                                                    */
  /* ------------------------------------------------------------------ */

  async exportData(userId: string, ctx: RequestContext) {
    const data = await this.store.exportAccountData(userId, 1000);
    await this.store.appendAudit({
      userId,
      event: 'data_export.requested',
      outcome: 'info',
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { audit_entries: data.auditLog.length },
    });
    return data;
  }
}