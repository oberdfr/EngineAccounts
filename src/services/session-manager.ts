import crypto from 'node:crypto';
import { hkdf } from '../config.js';
import { hmacSha256 } from '../security/crypto.js';
import type { SessionRecord, User } from '../domain/types.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import { effectiveSetting } from './administration.js';

/**
 * Sessioni di login: una riga per credenziale di login, non per dispositivo, con revoca che uccide davvero
 * l'accesso — cookie di sessione **e** token.
 *
 * Il cookie `__Host-ea_sid` porta un token opaco; nel DB c'e' solo il digest
 * HMAC. Un dump del database non permette di rubare una sessione.
 *
 * Nota sul doppio stato: il provider ha il proprio modello `Session` (necessario
 * a `/end-session` e al resume dell'interazione), noi abbiamo il nostro (serve a
 * elencare gli accessi e revocarli singolarmente). Sono collegati dalla colonna
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

export type PresentedSession = Pick<SessionRecord, 'id' | 'createdAt' | 'lastSeenAt' | 'expiresAt' | 'revokedAt' | 'revokeReason' | 'ip' | 'amr'> & {
  current: boolean;
  status: 'active' | 'expired' | 'revoked';
  browser: string;
  platform: string;
  label: string;
};

export interface SessionOverview {
  currentSessionId: string;
  counts: { total: number; active: number; expired: number; revoked: number; browserGroups: number };
  groups: { key: string; label: string; browser: string; platform: string; current: boolean; activeCount: number; sessions: PresentedSession[] }[];
  history: PresentedSession[];
}

/** Browser/OS labels are descriptive hints, never device identity or a deduplication key. */
export function presentSessions(records: SessionRecord[], currentSessionId: string, now = Date.now(), ttlSeconds?: number): SessionOverview {
  const overview: SessionOverview = {
    currentSessionId,
    counts: { total: records.length, active: 0, expired: 0, revoked: 0, browserGroups: 0 },
    groups: [], history: [],
  };
  const groups = new Map<string, SessionOverview['groups'][number]>();
  for (const record of records) {
    const { browser, platform, label } = browserDescription(record.userAgent);
    const expiresAt = new Date(Math.min(record.expiresAt.getTime(), ttlSeconds === undefined ? Infinity : record.createdAt.getTime() + ttlSeconds * 1000));
    const status = record.revokedAt ? 'revoked' : expiresAt.getTime() <= now ? 'expired' : 'active';
    const session: PresentedSession = {
      id: record.id, createdAt: record.createdAt, lastSeenAt: record.lastSeenAt, expiresAt,
      revokedAt: record.revokedAt, revokeReason: record.revokeReason, ip: record.ip,
      amr: [...record.amr], current: record.id === currentSessionId, status, browser, platform, label,
    };
    overview.counts[status]++;
    if (status !== 'active') { overview.history.push(session); continue; }
    const key = `${browser}:${platform}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, label, browser, platform, current: false, activeCount: 0, sessions: [] };
      groups.set(key, group);
    }
    group.sessions.push(session);
    group.activeCount++;
    group.current ||= session.current;
  }
  const byActivity = (a: PresentedSession, b: PresentedSession) => Number(b.current) - Number(a.current) || b.lastSeenAt.getTime() - a.lastSeenAt.getTime() || a.id.localeCompare(b.id);
  overview.groups = [...groups.values()].sort((a, b) => Number(b.current) - Number(a.current) || Math.max(...b.sessions.map((s) => s.lastSeenAt.getTime())) - Math.max(...a.sessions.map((s) => s.lastSeenAt.getTime())));
  for (const group of overview.groups) group.sessions.sort(byActivity);
  overview.history.sort(byActivity);
  overview.counts.browserGroups = overview.groups.length;
  return overview;
}

export class SessionManager {
  private readonly digestKey: Buffer;

  constructor(
    private readonly deps: { config: Config; store: AccountsStore; tokens: OidcTokenStore; db?: Db },
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
    const user = await this.deps.store.findUserById(input.userId);
    if (!user || user.status !== 'active' || user.mustChangePassword) throw new Error('Account non attivo o cambio password richiesto');
    const token = crypto.randomBytes(32).toString('base64url');
    const ttl = this.deps.db ? Number(await effectiveSetting(this.deps.db, this.deps.config, 'SESSION_TTL')) : this.deps.config.SESSION_TTL;
    const now = Date.now();
    const record = await this.deps.store.createSession({
      id: crypto.randomUUID(),
      userId: input.userId,
      tokenDigest: this.digest(token),
      providerSessionId: input.providerSessionId ?? null,
      providerSessionUid: input.providerSessionUid ?? null,
      deviceLabel: browserDescription(input.userAgent).label,
      ip: input.ip,
      userAgent: input.userAgent,
      amr: input.amr,
      createdAt: new Date(now),
      expiresAt: new Date(now + ttl * 1000),
    });
    return { record, cookieValue: token, maxAgeSeconds: ttl };
  }

  /** Sessione attiva per questo token, con `last_seen` aggiornato. */
  async resolve(cookieValue: string | undefined): Promise<{ user: User; session: SessionRecord } | undefined> {
    if (!cookieValue) return undefined;
    const record = await this.deps.store.findSessionByTokenDigest(this.digest(cookieValue));
    if (!record) return undefined;
    if (record.revokedAt || record.expiresAt.getTime() <= Date.now()) return undefined;
    if (this.deps.db) {
      const ttl = Number(await effectiveSetting(this.deps.db, this.deps.config, 'SESSION_TTL'));
      if (record.createdAt.getTime() + ttl * 1000 <= Date.now()) return undefined;
    }
    const user = await this.deps.store.findUserById(record.userId);
    if (!user || user.status !== 'active') return undefined;
    await this.deps.store.touchSession(record.id);
    return { user, session: { ...record, lastSeenAt: new Date() } };
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
    const retained = exceptSessionId ? await this.deps.store.findSession(exceptSessionId) : undefined;
    const keep = retained?.userId === userId && !retained.revokedAt && retained.expiresAt.getTime() > Date.now() ? retained : undefined;
    const ids = await this.deps.store.revokeAllSessions(userId, reason, exceptSessionId);
    for (const id of ids) {
      const record = await this.deps.store.findSession(id);
      if (!record) continue;
      // Repeated OIDC logins can link multiple local credentials to the same
      // provider session. "All other" must not destroy the retained login.
      if (record.providerSessionId && record.providerSessionId !== keep?.providerSessionId) await this.deps.tokens.destroyProviderSession(record.providerSessionId);
      if (record.providerSessionUid && record.providerSessionUid !== keep?.providerSessionUid) await this.deps.tokens.revokeUserGrants(userId, record.providerSessionUid);
    }
    return ids.length;
  }

  async list(userId: string): Promise<SessionRecord[]> {
    return this.deps.store.listSessions(userId);
  }

  async overview(userId: string, currentSessionId: string): Promise<SessionOverview> {
    const records = await this.deps.store.listSessions(userId, true);
    const ttl = this.deps.db ? Number(await effectiveSetting(this.deps.db, this.deps.config, 'SESSION_TTL')) : undefined;
    return presentSessions(records, currentSessionId, Date.now(), ttl);
  }

  /** Reuse only the same authenticated standalone credential with identical assurance.
   * Never use this for OIDC interaction completion, which owns provider linkage. */
  async reusableStandalone(cookieValue: string | undefined, userId: string, amr: string[]): Promise<SessionRecord | undefined> {
    const active = await this.resolve(cookieValue);
    if (!active || active.user.id !== userId || active.user.mustChangePassword) return undefined;
    const existing = new Set(active.session.amr);
    const requested = new Set(amr);
    if (existing.size !== requested.size || [...requested].some((method) => !existing.has(method))) return undefined;
    return active.session;
  }

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

export function browserDescription(userAgent: string | null): { browser: string; platform: string; label: string } {
  const ua = (userAgent ?? '').toLowerCase();
  let browser = 'Browser';
  if (/edg\/|edgios\/|edga\//.test(ua)) browser = 'Edge';
  else if (/opr\/|opera/.test(ua)) browser = 'Opera';
  else if (/chrome\/|crios\//.test(ua)) browser = 'Chrome';
  else if (/firefox\/|fxios\//.test(ua)) browser = 'Firefox';
  else if (/safari\//.test(ua)) browser = 'Safari';
  if (/smart-tv|smarttv|appletv|googletv|hbbtv|netcast|web0s/.test(ua)) browser = 'TV';

  let os = 'Sistema sconosciuto';
  if (/windows/.test(ua)) os = 'Windows';
  else if (/android/.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/.test(ua)) os = 'iOS';
  else if (/mac os x/.test(ua)) os = 'macOS';
  else if (/linux/.test(ua)) os = 'Linux';

  return { browser, platform: os, label: `${browser} su ${os}` };
}

function providerSessionUidFrom(payload: unknown): string | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const uid = (payload as { uid?: unknown }).uid;
  return typeof uid === 'string' ? uid : null;
}
