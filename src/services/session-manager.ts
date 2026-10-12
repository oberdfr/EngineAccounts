import crypto from 'node:crypto';
import { hkdf } from '../config.js';
import { hmacSha256 } from '../security/crypto.js';
import type { Amr, SessionRecord, User } from '../domain/types.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import type { Config } from '../config.js';

/**
 * Sessioni di login: una riga per dispositivo, con revoca che uccide davvero
 * l'accesso — cookie di sessione **e** token.
 *
 * Il cookie `__Host-ea_sid` porta un token opaco; nel DB c'e' solo il digest
 * HMAC. Un dump del database non permette di rubare una sessione.
 *
 * Nota sul doppio stato: il provider ha il proprio modello `Session` (necessario
 * a `/end-session` e al resume dell'interazione), noi abbiamo il nostro (serve a
 * elencare i dispositivi e a revocarli per device). Sono collegati dalla colonna
 * `provider_session_id`, valorizzata dopo l'interazione.
 */

/**
 * Nomi dei cookie.
 *
 * `__Host-` richiede `Secure`: su https (produzione) e' sempre applicabile, su
 * http (sviluppo in locale) il prefisso viene omesso perche' il browser
 * rifiuterebbe il cookie. La scelta e' centralizzata in `config.cookiePrefix`.
 */
export function sessionCookieName(config: Config): string {
  return `${config.cookiePrefix}ea_sid`;
}

/** Cookie di sessione del provider: nome impostato in `oidc/provider.ts`. */
export function providerSessionCookieName(config: Config): string {
  return `${config.cookiePrefix}ea_oidc`;
}

export function csrfCookieName(config: Config): string {
  return `${config.cookiePrefix}ea_csrf`;
}

export class SessionManager {
  private readonly digestKey: Buffer;

  constructor(
    private readonly deps: { config: Config; store: AccountsStore; tokens: OidcTokenStore },
  ) {
    this.digestKey = hkdf(deps.config.dataKey, 'engine-accounts/session-cookie');
  }

  digest(token: string): string {
    return hmacSha256(this.digestKey, token);
  }

  async create(input: {
    userId: string;
    providerSessionId?: string | null;
    providerSessionUid?: string | null;
    amr: string[];
    ip: string | null;
    userAgent: string | null;
  }): Promise<{ record: SessionRecord; cookieValue: string; maxAgeSeconds: number }> {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    const record = await this.deps.store.createSession({
      id: crypto.randomUUID(),
      userId: input.userId,
      tokenDigest: this.digest(token),
      providerSessionId: input.providerSessionId ?? null,
      providerSessionUid: input.providerSessionUid ?? null,
      deviceLabel: deviceLabel(input.userAgent, input.ip),
      ip: input.ip,
      userAgent: input.userAgent,
      amr: input.amr,
      createdAt: new Date(now),
      expiresAt: new Date(now + this.deps.config.SESSION_TTL * 1000),
    });
    return { record, cookieValue: token, maxAgeSeconds: this.deps.config.SESSION_TTL };
  }

  /** Sessione attiva per questo token, con `last_seen` aggiornato. */
  async resolve(cookieValue: string | undefined): Promise<{ user: User; session: SessionRecord } | undefined> {
    if (!cookieValue) return undefined;
    const record = await this.deps.store.findSessionByTokenDigest(this.digest(cookieValue));
    if (!record) return undefined;
    if (record.revokedAt || record.expiresAt.getTime() <= Date.now()) return undefined;
    const user = await this.deps.store.findUserById(record.userId);
    if (!user || user.status === 'deleted') return undefined;
    await this.deps.store.touchSession(record.id);
    return { user, session: record };
  }

  /**
   * Revoca. Oltre alla riga, uccide il materiale lato provider: la sessione del
   * provider (cookie) e i grant emessi da *quel* dispositivo.
   */
  async revoke(sessionId: string, reason: string, userId?: string): Promise<boolean> {
    const record = await this.deps.store.findSession(sessionId);
    if (!record || record.revokedAt) return false;
    if (userId && record.userId !== userId) return false; // isolamento per utente
    await this.deps.store.revokeSession(sessionId, reason);
    if (record.providerSessionId) {
      await this.deps.tokens.destroyProviderSession(record.providerSessionId);
    }
    if (record.providerSessionUid) {
      await this.deps.tokens.revokeUserGrants(record.userId, record.providerSessionUid);
    }
    return true;
  }

  async revokeAll(userId: string, reason: string, exceptSessionId?: string): Promise<number> {
    const ids = await this.deps.store.revokeAllSessions(userId, reason, exceptSessionId);
    for (const id of ids) {
      const record = await this.deps.store.findSession(id);
      if (!record) continue;
      if (record.providerSessionId) await this.deps.tokens.destroyProviderSession(record.providerSessionId);
      if (record.providerSessionUid) await this.deps.tokens.revokeUserGrants(userId, record.providerSessionUid);
    }
    return ids.length;
  }

  async list(userId: string): Promise<SessionRecord[]> {
    return this.deps.store.listSessions(userId);
  }

  /**
  /** Collega la riga nostra alla `Session` del provider, dopo l'interazione. */
  async linkProviderSession(sessionId: string, providerSessionId: string): Promise<void> {
    const payload = await this.deps.tokens.find('sessions', providerSessionId);
    await this.deps.store.linkProviderSession(sessionId, providerSessionId, providerSessionUidFrom(payload));
  }

  cookieOptions() {
    return {
      httpOnly: true,
      secure: this.deps.config.secureCookies,
      sameSite: 'lax' as const,
      path: '/',
    };
  }
}

function deviceLabel(userAgent: string | null, ip: string | null): string {
  const ua = (userAgent ?? '').toLowerCase();
  let browser = 'Browser';
  if (/edg\//.test(ua)) browser = 'Edge';
  else if (/opr\/|opera/.test(ua)) browser = 'Opera';
  else if (/chrome\//.test(ua)) browser = 'Chrome';
  else if (/firefox\//.test(ua)) browser = 'Firefox';
  else if (/safari\//.test(ua)) browser = 'Safari';
  if (/smart-tv|smarttv|appletv|googletv|hbbtv|netcast|web0s/.test(ua)) browser = 'TV';

  let os = 'Sistema sconosciuto';
  if (/windows/.test(ua)) os = 'Windows';
  else if (/android/.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/.test(ua)) os = 'iOS';
  else if (/mac os x/.test(ua)) os = 'macOS';
  else if (/linux/.test(ua)) os = 'Linux';

  const ipPart = ip?.startsWith('::ffff:') ? ip.slice(7) : ip;
  return `${browser} su ${os}${ipPart ? ` · ${ipPart}` : ''}`;
}

function providerSessionUidFrom(payload: unknown): string | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const uid = (payload as { uid?: unknown }).uid;
  return typeof uid === 'string' ? uid : null;
}