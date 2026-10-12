import type { PoolClient, QueryResultRow } from 'pg';
import type { Config } from '../config.js';
import { table, type Db } from '../db/pool.js';
import type { AccountsStore, OidcTokenStore } from '../domain/ports.js';
import type { AuditLogEntry, UserStatus } from '../domain/types.js';
import type { AccountService, RequestContext } from './account-service.js';
import type { SessionManager } from './session-manager.js';
import { isAllowedBackchannelUri } from '../config.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import nodemailer from 'nodemailer';

/** Route contract: mutations enforce authorization here, not only in the UI.
 * `admin:cli` is reserved for the trusted CLI; never derive actorSub from form data.
 * Deletion delegates to AccountService OUTSIDE a Db.tx; the DB trigger enforces
 * last-admin protection even for its independent updateUser transaction.
 */
export class AdministrationError extends Error {
  constructor(public readonly code: 'forbidden' | 'not_found' | 'last_active_global_admin' | 'invalid_input' | 'bootstrap_cli_only', public readonly statusCode = 400) { super(code); }
}
export interface AdminServiceRecord {
  serviceId: string; audience: string; name: string; enabled: boolean;
  description: string; adminUrl: string | null; adminApiUrl: string | null; origin: 'env' | 'cli';
  clients: { clientId: string; name: string; enabled: boolean; origin: 'env' | 'cli' }[];
  scopes: { scope: string; description: string }[];
  connectedUsers: number;
  delivery: { pending: number; failed: number; lastDeliveredAt: Date | null };
}
export interface AdminAccount extends QueryResultRow {
  id: string; email: string; displayName: string | null; status: UserStatus;
  emailVerifiedAt: Date | null; totpEnabled: boolean; mfa: boolean;
  isGlobalAdmin: boolean; mustChangePassword: boolean;
  createdAt: Date; updatedAt: Date; lastLoginAt: Date | null; lockedUntil: Date | null; hasServiceRole?: boolean; failedLogins: number; blockedReason: string | null; deletedAt: Date | null;
}
export interface AccountFilters {
  q?: string; status?: UserStatus; mfa?: boolean | 'enabled' | 'disabled';
  role?: 'global' | 'service' | 'none'; service?: string; serviceId?: string; page?: number; pageSize?: number;
}
export interface AuditFilters {
  q?: string; userId?: string; subjectId?: string; actor?: string; event?: string;
  outcome?: string; serviceId?: string; from?: Date | string; to?: Date | string; page?: number; pageSize?: number;
}
export type AccountAction = 'block' | 'ban' | 'unblock' | 'unban' | 'unlock' | 'revoke_sessions' | 'revoke-sessions' | 'require_password_change' | 'force-password-change' | 'force-password' | 'reset_mfa' | 'reset-mfa' | 'delete' | 'purge' | 'revoke-consent';
export interface MutationOptions {
  force?: boolean; reason?: string; context?: RequestContext;
  serviceId?: string;
  accountService?: Pick<AccountService, 'deleteAccountAsAdmin'>; reauth?: { password: string; totpCode?: string };
  /** Purge owns its own transaction; its owner must use the shared guard/DB trigger. */
  purge?: (sub: string) => Promise<unknown>;
}
const CLI = 'admin:cli';
const contextDefault: RequestContext = { ip: null, userAgent: null };
const accountSelect = `u.id,u.email,u.display_name AS "displayName",u.status,
  u.email_verified_at AS "emailVerifiedAt",u.totp_enabled AS "totpEnabled",
  (u.totp_enabled OR EXISTS(SELECT 1 FROM %WEBAUTHN% w WHERE w.user_id=u.id)) AS mfa,
  u.is_global_admin AS "isGlobalAdmin",u.must_change_password AS "mustChangePassword",
  u.created_at AS "createdAt",u.updated_at AS "updatedAt",u.last_login_at AS "lastLoginAt",u.locked_until AS "lockedUntil",u.failed_logins AS "failedLogins",u.blocked_reason AS "blockedReason",u.deleted_at AS "deletedAt"`;

/** MUST call from an existing transaction and perform the protected write on
 * that same client. A standalone check cannot protect concurrent mutations. */
export async function guardLastGlobalAdmin(db: Db, sub: string, opts: { force?: boolean; client?: PoolClient } = {}): Promise<void> {
  if (!opts.client) throw new Error('guardLastGlobalAdmin requires the mutation transaction client');
  const client = opts.client;
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${db.schema}:global-admin`]);
  if (opts.force) {
    await client.query("SELECT set_config('engine_accounts.force_admin','on',true)");
    return;
  }
  const result = await client.query(`SELECT id FROM ${table(db, 'users')} WHERE id=$1 AND is_global_admin AND status='active'
    AND NOT EXISTS(SELECT 1 FROM ${table(db, 'users')} WHERE id<>$1 AND is_global_admin AND status='active')`, [sub]);
  if (result.rows.length) throw new AdministrationError('last_active_global_admin', 409);
}
export async function withGlobalAdminProtection<T>(db: Db, sub: string, fn: (client: PoolClient) => Promise<T>, opts: { force?: boolean } = {}): Promise<T> {
  return db.tx(async (client) => { await guardLastGlobalAdmin(db, sub, { ...opts, client }); return fn(client); });
}

export const SETTING_DEFAULTS = {
  EMAIL_VERIFICATION_REQUIRED: false, TOTP_REQUIRED: false, ADMIN_MFA_REQUIRED: true, REGISTRATION_MODE: 'open',
  PASSWORD_MIN_LENGTH: 12, SESSION_TTL: 1_209_600, CONSENT_TTL: 31_536_000,
  PASSWORD_RESET_TTL: 900, EMAIL_VERIFICATION_TTL: 900, EMAIL_CHANGE_TTL: 900, MAGIC_CODE_TTL: 300,
} as const;
export type SettingKey = keyof typeof SETTING_DEFAULTS;
export interface EffectiveSetting { key: SettingKey; value: boolean | number | string; source: 'env' | 'db' | 'default'; editable: boolean }
const ranges: Partial<Record<SettingKey, [number, number]>> = {
  PASSWORD_MIN_LENGTH: [8, 128], SESSION_TTL: [300, 31_536_000], CONSENT_TTL: [3600, 315_360_000],
  PASSWORD_RESET_TTL: [60, 86400], EMAIL_VERIFICATION_TTL: [60, 86400], EMAIL_CHANGE_TTL: [60, 86400], MAGIC_CODE_TTL: [60, 3600],
};
export function validateSetting(key: string, value: unknown): asserts key is SettingKey {
  if (!Object.hasOwn(SETTING_DEFAULTS, key)) throw new AdministrationError('invalid_input');
  if (key === 'REGISTRATION_MODE') {
    if (!['open', 'closed', 'invite'].includes(String(value))) throw new AdministrationError('invalid_input');
    return;
  }
  if (typeof SETTING_DEFAULTS[key as SettingKey] === 'boolean') {
    if (typeof value !== 'boolean') throw new AdministrationError('invalid_input');
  } else {
    const [min, max] = ranges[key as SettingKey]!;
    if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) throw new AdministrationError('invalid_input');
  }
}
/** Exported for account/provider agents; no config mutation and no secrets. */
export async function getEffectiveSettings(db: Db, config: Config): Promise<EffectiveSetting[]> {
  const rows = await db.query<{ key: string; value: unknown }>(`SELECT key,value FROM ${table(db, 'administration_settings')}`);
  return (Object.keys(SETTING_DEFAULTS) as SettingKey[]).map((key) => {
    if (key === 'ADMIN_MFA_REQUIRED') return { key, value: true, source: config.explicitEnvKeys.includes(key) ? 'env' : 'default', editable: false };
    const configured = (config as unknown as Record<string, unknown>)[key];
    if (config.explicitEnvKeys.includes(key)) {
      const value = configured;
      validateSetting(key, value);
      return { key, value: value as boolean | number | string, source: 'env', editable: false };
    }
    const saved = rows.find((row) => row.key === key);
    if (saved) { validateSetting(key, saved.value); return { key, value: saved.value as boolean | number, source: 'db', editable: true }; }
    return { key, value: SETTING_DEFAULTS[key], source: 'default', editable: true };
  });
}
export async function effectiveSetting(db: Db, config: Config, key: SettingKey): Promise<boolean | number | string> {
  return (await getEffectiveSettings(db, config)).find((item) => item.key === key)!.value;
}

export class AdministrationService {
  constructor(private readonly deps: { db: Db; config: Config; store: AccountsStore; tokens: OidcTokenStore; sessions: SessionManager }) {}
  private get db() { return this.deps.db; }
  async isGlobalAdmin(sub: string): Promise<boolean> {
    return Boolean(await this.db.one(`SELECT id FROM ${table(this.db, 'users')} WHERE id=$1 AND status='active' AND is_global_admin`, [sub]));
  }
  async authorization(sub: string, serviceId: string): Promise<{ admin: boolean; global: boolean; status: UserStatus | null }> {
    const user = await this.db.one<{ status: UserStatus; global: boolean }>(`SELECT status,is_global_admin AS global FROM ${table(this.db, 'users')} WHERE id=$1`, [sub]);
    if (!user || user.status !== 'active') return { admin: false, global: false, status: user?.status ?? null };
    const assignment = await this.db.one(`SELECT user_id FROM ${table(this.db, 'service_admin_assignments')} WHERE service_id=$1 AND user_id=$2`, [serviceId, sub]);
    return { admin: user.global || Boolean(assignment), global: user.global, status: user.status };
  }
  private async requireGlobal(actor: string) {
    if (actor !== CLI && !await this.isGlobalAdmin(actor)) throw new AdministrationError('forbidden', 403);
  }
  private async audit(actor: string, target: string | null, event: string, ctx = contextDefault, serviceId?: string) {
    await this.deps.store.appendAudit({ actor: actor === CLI ? CLI : `admin:${actor}`, userId: target, subjectId: target,
      event, outcome: 'success', ip: ctx.ip, userAgent: ctx.userAgent, metadata: serviceId ? { serviceId } : {} });
  }
  async listServices(): Promise<AdminServiceRecord[]> {
    const services = await this.db.query<Omit<AdminServiceRecord, 'clients' | 'scopes' | 'connectedUsers' | 'delivery'>>(`SELECT service_id AS "serviceId",audience,name,enabled,description,
      admin_url AS "adminUrl",admin_api_url AS "adminApiUrl",origin FROM ${table(this.db, 'services')} ORDER BY name,service_id`);
    const clients = await this.deps.store.listClients();
    const scopes = await this.deps.store.listServiceScopes();
    const stats = await this.db.query<{ audience: string; users: string }>(`SELECT c.audience,count(DISTINCT cc.user_id) AS users FROM ${table(this.db, 'client_consents')} cc JOIN ${table(this.db, 'clients')} c ON cc.client_id=c.client_id WHERE cc.revoked_at IS NULL AND (cc.expires_at IS NULL OR cc.expires_at>now()) GROUP BY c.audience`);
    const deliveries = await this.db.query<{ audience: string; pending: string; failed: string; delivered: Date | null }>(`SELECT audience,count(*) FILTER(WHERE delivered_at IS NULL) AS pending,count(*) FILTER(WHERE delivered_at IS NULL AND attempts>0) AS failed,max(delivered_at) AS delivered FROM ${table(this.db, 'outbox_events')} GROUP BY audience`);
    return services.map((service) => ({ ...service,
      clients: clients.filter((c) => c.audience === service.audience).map((c) => ({ clientId: c.clientId, name: c.clientName, enabled: c.enabled,
        origin: this.deps.config.OIDC_CLIENTS_JSON.some((item) => item.clientId === c.clientId) ? 'env' as const : 'cli' as const })),
      scopes: scopes.filter((s) => s.serviceId === service.serviceId).map((s) => ({ scope: s.scope, description: s.description })),
      connectedUsers: Number(stats.find((item) => item.audience === service.audience)?.users ?? 0),
      delivery: { pending: Number(deliveries.find((item) => item.audience === service.audience)?.pending ?? 0),
        failed: Number(deliveries.find((item) => item.audience === service.audience)?.failed ?? 0),
        lastDeliveredAt: deliveries.find((item) => item.audience === service.audience)?.delivered ?? null },
    }));
  }
  async findService(serviceId: string): Promise<AdminServiceRecord | undefined> { return (await this.listServices()).find((s) => s.serviceId === serviceId); }
  async assignments(serviceId: string) {
    return this.db.query<{ userId: string; email: string; displayName: string | null; status: UserStatus; grantedAt: Date; grantedBy: string }>(`SELECT a.user_id AS "userId",u.email,u.display_name AS "displayName",u.status,
      a.granted_at AS "grantedAt",a.granted_by AS "grantedBy" FROM ${table(this.db, 'service_admin_assignments')} a
      JOIN ${table(this.db, 'users')} u ON u.id=a.user_id WHERE a.service_id=$1 ORDER BY u.email`, [serviceId]);
  }
  async accounts(filters: AccountFilters = {}): Promise<{ items: AdminAccount[]; total: number; page: number; pageSize: number }> {
    const params: unknown[] = []; const where: string[] = [];
    const add = (value: unknown) => { params.push(value); return `$${params.length}`; };
    if (filters.q) { const p = add(`%${filters.q.slice(0, 200)}%`); where.push(`(u.email ILIKE ${p} OR u.display_name ILIKE ${p} OR u.id::text ILIKE ${p})`); }
    if (filters.status) where.push(`u.status=${add(filters.status)}`);
    const mfa = `(u.totp_enabled OR EXISTS(SELECT 1 FROM ${table(this.db, 'webauthn_credentials')} w WHERE w.user_id=u.id))`;
    if (filters.mfa !== undefined) where.push(`${mfa}=${add(filters.mfa === true || filters.mfa === 'enabled')}`);
    const service = filters.serviceId ?? filters.service;
    const serviceParameter = service ? add(service) : undefined;
    const assignment = `EXISTS(SELECT 1 FROM ${table(this.db, 'service_admin_assignments')} a WHERE a.user_id=u.id${service && (filters.role === 'service' || filters.role === 'none') ? ` AND a.service_id=${serviceParameter}` : ''})`;
    if (service) where.push(`EXISTS(SELECT 1 FROM ${table(this.db, 'client_consents')} cc JOIN ${table(this.db, 'clients')} c ON c.client_id=cc.client_id
      JOIN ${table(this.db, 'services')} s ON s.audience=c.audience WHERE cc.user_id=u.id AND cc.revoked_at IS NULL AND s.service_id=${serviceParameter})`);
    if (filters.role === 'global') where.push('u.is_global_admin');
    if (filters.role === 'service') where.push(assignment);
    if (filters.role === 'none') where.push(`NOT u.is_global_admin AND NOT ${assignment}`);
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const count = await this.db.one<{ total: string }>(`SELECT count(*) AS total FROM ${table(this.db, 'users')} u ${clause}`, params);
    const { page, pageSize } = pagination(filters);
    const items = await this.db.query<AdminAccount>(`SELECT ${accountSelect.replace('%WEBAUTHN%', table(this.db, 'webauthn_credentials'))}, EXISTS(SELECT 1 FROM ${table(this.db, 'service_admin_assignments')} roles WHERE roles.user_id=u.id${service ? ` AND roles.service_id=${serviceParameter}` : ''}) AS "hasServiceRole" FROM ${table(this.db, 'users')} u ${clause}
      ORDER BY u.created_at DESC,u.id LIMIT ${add(pageSize)} OFFSET ${add((page - 1) * pageSize)}`, params);
    return { items, total: Number(count?.total ?? 0), page, pageSize };
  }
  async accountDetail(sub: string) {
    const account = await this.db.one<AdminAccount>(`SELECT ${accountSelect.replace('%WEBAUTHN%', table(this.db, 'webauthn_credentials'))} FROM ${table(this.db, 'users')} u WHERE u.id=$1`, [sub]);
    if (!account) return undefined;
    const [sessions, consents, assignments, audit, credentials, recoveryCodesRemaining] = await Promise.all([
      this.deps.store.listSessions(sub, true), this.deps.store.listConsents(sub),
      this.db.query<{ serviceId: string }>(`SELECT service_id AS "serviceId" FROM ${table(this.db, 'service_admin_assignments')} WHERE user_id=$1`, [sub]),
      this.deps.store.listAudit(sub, 50),
      this.deps.store.listWebauthnCredentials(sub), this.deps.store.countUnusedRecoveryCodes(sub),
    ]);
    // Never return cookie digests, public keys, password hashes or OIDC payloads.
    const clients = await this.deps.store.listClients();
    const services = (await this.listServices()).filter((service) => consents.some((consent) => !consent.revokedAt && clients.some((client) => client.clientId === consent.clientId && client.audience === service.audience)));
    return { account, mfa: { webauthnCount: credentials.length, recoveryCodesRemaining }, sessions: sessions.map(({ tokenDigest: _digest, ...safe }) => safe), consents, assignments, services, audit };
  }
  async setGlobalRole(actorSub: string, targetSub: string, enabled: boolean, opts: { force?: boolean; context?: RequestContext } = {}): Promise<void> {
    await this.requireGlobal(actorSub);
    if (actorSub === targetSub) throw new AdministrationError('forbidden', 403);
    if (opts.force && actorSub !== CLI) throw new AdministrationError('forbidden', 403);
    await this.db.tx(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${this.db.schema}:global-admin`]);
      const user = (await client.query(`SELECT status FROM ${table(this.db, 'users')} WHERE id=$1 FOR UPDATE`, [targetSub])).rows[0];
      if (!user) throw new AdministrationError('not_found', 404);
      if (enabled && user.status !== 'active') throw new AdministrationError('invalid_input');
      const existing = await client.query(`SELECT id FROM ${table(this.db, 'users')} WHERE is_global_admin LIMIT 1`);
      if (enabled && !existing.rows.length && actorSub !== CLI) throw new AdministrationError('bootstrap_cli_only', 403);
      if (!enabled) await guardLastGlobalAdmin(this.db, targetSub, { client, force: opts.force });
      await client.query(`UPDATE ${table(this.db, 'users')} SET is_global_admin=$2,updated_at=now() WHERE id=$1`, [targetSub, enabled]);
    });
    await this.audit(actorSub, targetSub, enabled ? 'admin.global_role.granted' : 'admin.global_role.revoked', opts.context);
  }
  async grantAssignment(actorSub: string, targetSub: string, serviceId: string, ctx?: RequestContext): Promise<void> {
    await this.requireGlobal(actorSub);
    if (actorSub === targetSub) throw new AdministrationError('forbidden', 403);
    if (!await this.findService(serviceId)) throw new AdministrationError('not_found', 404);
    const user = await this.deps.store.findUserById(targetSub);
    if (!user || user.status !== 'active') throw new AdministrationError('invalid_input');
    await this.db.query(`INSERT INTO ${table(this.db, 'service_admin_assignments')}(service_id,user_id,granted_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, [serviceId, targetSub, actorSub]);
    await this.audit(actorSub, targetSub, 'admin.service_role.granted', ctx, serviceId);
  }
  async revokeAssignment(actorSub: string, targetSub: string, serviceId: string, ctx?: RequestContext): Promise<void> {
    await this.requireGlobal(actorSub);
    if (actorSub === targetSub) throw new AdministrationError('forbidden', 403);
    await this.db.query(`DELETE FROM ${table(this.db, 'service_admin_assignments')} WHERE service_id=$1 AND user_id=$2`, [serviceId, targetSub]);
    await this.audit(actorSub, targetSub, 'admin.service_role.revoked', ctx, serviceId);
  }
  grant(actorSub: string, serviceId: string, targetSub: string, ctx?: RequestContext) { return this.grantAssignment(actorSub, targetSub, serviceId, ctx); }
  revoke(actorSub: string, serviceId: string, targetSub: string, ctx?: RequestContext) { return this.revokeAssignment(actorSub, targetSub, serviceId, ctx); }
  async setServiceEnabled(actorSub: string, serviceId: string, enabled: boolean, ctx?: RequestContext): Promise<void> {
    await this.requireGlobal(actorSub);
    const changed = await this.db.query(`UPDATE ${table(this.db, 'services')} SET enabled=$2 WHERE service_id=$1 RETURNING service_id`, [serviceId, enabled]);
    if (!changed.length) throw new AdministrationError('not_found', 404);
    await this.audit(actorSub, null, enabled ? 'admin.service.enabled' : 'admin.service.disabled', ctx, serviceId);
  }
  /** Registry IDs are existing IDs, audience is the unique service identity.
   * No outbound request is made to these metadata URLs. */
  async upsertService(actorSub: string, input: { serviceId: string; audience: string; name: string; description?: string; adminUrl?: string | null; adminApiUrl?: string | null; origin?: 'env' | 'cli' }): Promise<void> {
    if (actorSub !== CLI) throw new AdministrationError('forbidden', 403);
    if (!input.serviceId || !input.name) throw new AdministrationError('invalid_input');
    for (const value of [input.audience, input.adminUrl, input.adminApiUrl]) if (value) {
      let url: URL; try { url = new URL(value); } catch { throw new AdministrationError('invalid_input'); }
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.hash || value.includes('*')) throw new AdministrationError('invalid_input');
    }
    for (const url of [input.adminUrl, input.adminApiUrl]) if (url && !isAllowedBackchannelUri(url, this.deps.config.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) throw new AdministrationError('invalid_input');
    await this.db.query(`INSERT INTO ${table(this.db, 'services')}(service_id,audience,name,description,admin_url,admin_api_url,origin)
      VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(audience) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,
      admin_url=EXCLUDED.admin_url,admin_api_url=EXCLUDED.admin_api_url,origin=EXCLUDED.origin`,
    [input.serviceId, input.audience, input.name, input.description ?? '', input.adminUrl ?? null, input.adminApiUrl ?? null, input.origin ?? 'cli']);
    await this.audit(actorSub, null, 'admin.service.registered', undefined, input.serviceId);
  }
  async mutateAccount(actorSub: string, targetSub: string, action: AccountAction, opts: MutationOptions = {}, context?: RequestContext): Promise<{ ok: boolean; message?: string }> {
    if (action === 'purge') {
      if (!opts.serviceId || !opts.purge || opts.force) throw new AdministrationError('invalid_input');
      const auth = actorSub === CLI ? { admin: true } : await this.authorization(actorSub, opts.serviceId);
      const service = await this.findService(opts.serviceId);
      if (!auth.admin) throw new AdministrationError('forbidden', 404);
      if (!service?.enabled || !service.adminApiUrl) throw new AdministrationError('not_found', 404);
      const connected = (await this.accountDetail(targetSub))?.services.some((item) => item.serviceId === service.serviceId);
      if (!connected) throw new AdministrationError('not_found', 404);
      await opts.purge(targetSub);
      await this.audit(actorSub, targetSub, 'admin.service.data_purge', context ?? opts.context, opts.serviceId);
      return { ok: true };
    }
    if (action === 'revoke-consent') {
      if (!opts.serviceId) throw new AdministrationError('invalid_input');
      const auth = actorSub === CLI ? { admin: true } : await this.authorization(actorSub, opts.serviceId);
      if (!auth.admin) throw new AdministrationError('forbidden', 403);
      const service = await this.findService(opts.serviceId);
      if (!service) throw new AdministrationError('not_found', 404);
      for (const client of await this.deps.store.listClients()) if (client.audience === service.audience) {
        await this.deps.store.revokeConsent(targetSub, client.clientId);
        // Revoke only grants belonging to this service, never another audience.
        const grants = await this.db.query<{ id: string }>(`SELECT grant_id AS id FROM ${table(this.db, 'oidc_grants')} WHERE account_id=$1 AND client_id=$2`, [targetSub, client.clientId]);
        for (const grant of grants) await this.deps.tokens.revokeByGrantId(grant.id);
      }
      await this.audit(actorSub, targetSub, 'admin.service.consent_revoked', context ?? opts.context, opts.serviceId);
      return { ok: true };
    }
    await this.requireGlobal(actorSub);
    if (opts.force && actorSub !== CLI) throw new AdministrationError('forbidden', 403);
    const user = await this.deps.store.findUserById(targetSub);
    if (!user) throw new AdministrationError('not_found', 404);
    const ctx = context ?? opts.context ?? contextDefault;
    if (action === 'delete') {
      if (opts.force) throw new AdministrationError('invalid_input'); // delegated transactions cannot inherit a local force flag
      // Early guard for useful error; trigger remains the atomic authority.
      await withGlobalAdminProtection(this.db, targetSub, async () => undefined);
        if (!opts.accountService || !opts.reauth) throw new AdministrationError('invalid_input');
        const result = await opts.accountService.deleteAccountAsAdmin(actorSub, targetSub, opts.reauth, ctx);
        if (!result.ok) {
          await this.deps.store.appendAudit({ actor: `admin:${actorSub}`, userId: targetSub, subjectId: targetSub,
            event: 'admin.account.delete', outcome: 'denied', ip: ctx.ip, metadata: {} });
          return result;
        }
      await this.db.query(`DELETE FROM ${table(this.db, 'service_admin_assignments')} WHERE user_id=$1`, [targetSub]);
    } else if (action === 'block' || action === 'ban') {
      await withGlobalAdminProtection(this.db, targetSub, async (client) => {
        await client.query(`UPDATE ${table(this.db, 'users')} SET status='blocked',blocked_reason=$2,updated_at=now() WHERE id=$1 AND status<>'deleted'`, [targetSub, opts.reason?.slice(0, 500) ?? 'amministrazione']);
      }, { force: opts.force });
      await this.deps.sessions.revokeAll(targetSub, 'admin_block');
      await this.deps.tokens.revokeUserGrants(targetSub);
    } else if (action === 'unblock' || action === 'unban' || action === 'unlock') {
      if (user.status === 'deleted') throw new AdministrationError('invalid_input');
      await this.db.query(`UPDATE ${table(this.db, 'users')} SET status='active',blocked_reason=NULL,failed_logins=0,locked_until=NULL,updated_at=now() WHERE id=$1 AND status<>'deleted'`, [targetSub]);
    } else if (action === 'revoke_sessions' || action === 'revoke-sessions') {
      await this.deps.sessions.revokeAll(targetSub, 'admin_revoke');
      await this.deps.tokens.revokeUserGrants(targetSub);
    } else if (action === 'require_password_change' || action === 'force-password-change' || action === 'force-password') {
      await this.db.query(`UPDATE ${table(this.db, 'users')} SET must_change_password=true,updated_at=now() WHERE id=$1`, [targetSub]);
      await this.deps.sessions.revokeAll(targetSub, 'admin_password_change');
      await this.deps.tokens.revokeUserGrants(targetSub);
    } else if (action === 'reset_mfa' || action === 'reset-mfa') {
      await this.deps.store.deleteTotp(targetSub);
      await this.deps.store.deleteRecoveryCodes(targetSub);
      for (const credential of await this.deps.store.listWebauthnCredentials(targetSub)) await this.deps.store.deleteWebauthnCredential(targetSub, credential.credentialId);
      await this.deps.store.updateUser(targetSub, { totpEnabled: false });
      await this.deps.sessions.revokeAll(targetSub, 'admin_mfa_reset');
      await this.deps.tokens.revokeUserGrants(targetSub);
    } else throw new AdministrationError('invalid_input');
    await this.audit(actorSub, targetSub, `admin.account.${action}`, ctx);
    return { ok: true };
  }
  async listAudit(filters: AuditFilters = {}): Promise<{ items: AuditLogEntry[]; total: number; page: number; pageSize: number }> {
    const params: unknown[] = []; const where: string[] = [];
    const add = (value: unknown) => { params.push(value); return `$${params.length}`; };
    for (const [key, column] of [['userId', 'user_id'], ['subjectId', 'subject_id'], ['actor', 'actor'], ['event', 'event'], ['outcome', 'outcome']] as const)
      if (filters[key]) where.push(`${column}=${add(filters[key])}`);
    if (filters.serviceId) where.push(`metadata->>'serviceId'=${add(filters.serviceId)}`);
    if (filters.from) where.push(`at>=${add(filters.from)}`);
    if (filters.to) where.push(`at<=${add(filters.to)}`);
    if (filters.q) { const p = add(`%${filters.q.slice(0, 200)}%`); where.push(`(event ILIKE ${p} OR actor ILIKE ${p})`); }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const count = await this.db.one<{ total: string }>(`SELECT count(*) AS total FROM ${table(this.db, 'audit_log')} ${clause}`, params);
    const { page, pageSize } = pagination(filters);
    const items = await this.db.query<AuditLogEntry>(`SELECT id::text,at,user_id AS "userId",subject_id AS "subjectId",actor,event,outcome,
      ip,user_agent AS "userAgent",metadata,prev_hash AS "prevHash",hash FROM ${table(this.db, 'audit_log')} ${clause} ORDER BY at DESC,id DESC LIMIT ${add(pageSize)} OFFSET ${add((page-1)*pageSize)}`, params);
    return { items, total: Number(count?.total ?? 0), page, pageSize };
  }
  getSettings() { return getEffectiveSettings(this.db, this.deps.config); }
  async setSetting(actorSub: string, key: string, value: unknown, ctx?: RequestContext): Promise<void> {
    await this.requireGlobal(actorSub); validateSetting(key, value);
    if (key === 'ADMIN_MFA_REQUIRED' && value !== true) throw new AdministrationError('invalid_input');
    if (key === 'PASSWORD_MIN_LENGTH' && Number(value) > this.deps.config.PASSWORD_MAX_LENGTH) throw new AdministrationError('invalid_input');
    if (this.deps.config.explicitEnvKeys.includes(key)) throw new AdministrationError('invalid_input', 409);
    await this.db.query(`INSERT INTO ${table(this.db, 'administration_settings')}(key,value,updated_by) VALUES($1,$2::jsonb,$3)
      ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()`, [key, JSON.stringify(value), actorSub]);
    await this.deps.store.appendAudit({ actor: `admin:${actorSub}`, event: 'admin.settings.updated', outcome: 'success',
      ip: ctx?.ip ?? null, metadata: { setting: key } });
  }
  async diagnostics() {
    const [database, pending] = await Promise.all([
      this.db.one<{ ok: number }>('SELECT 1 AS ok'),
       this.db.one<{ count: string; failed: string }>(`SELECT count(*) AS count,count(*) FILTER(WHERE attempts>0) AS failed FROM ${table(this.db, 'outbox_events')} WHERE delivered_at IS NULL`),
    ]);
    const config = this.deps.config;
    let smtp: 'available' | 'unavailable' | 'disabled' = 'disabled';
    if (config.MAIL_ENABLED) {
      const transport = nodemailer.createTransport({ host: config.SMTP_HOST, port: config.SMTP_PORT,
        secure: config.SMTP_SECURE, connectionTimeout: 3000, greetingTimeout: 3000, socketTimeout: 3000,
        auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined });
      try { smtp = await transport.verify() ? 'available' : 'unavailable'; } catch { smtp = 'unavailable'; } finally { transport.close(); }
    }
    let jwks: { status: string; fileAgeSeconds?: number; keys?: { kid: string; alg: string }[] } = { status: 'unavailable' };
    try {
      const file = path.resolve(config.ENGINE_ACCOUNTS_JWKS_PATH);
      const [bytes, info] = await Promise.all([fs.readFile(file, 'utf8'), fs.stat(file)]);
      const parsed = JSON.parse(bytes) as { keys: { kid?: string; alg?: string }[] };
      jwks = { status: 'available', fileAgeSeconds: Math.max(0, Math.floor((Date.now() - info.mtimeMs) / 1000)),
        keys: parsed.keys.map((key) => ({ kid: key.kid ?? 'non disponibile', alg: key.alg ?? 'non disponibile' })) };
    } catch { /* Do not create keys or expose filesystem/error details. */ }
    return { database: database?.ok === 1, smtp, jwks, mailEnabled: config.MAIL_ENABLED,
      secureCookies: config.secureCookies, pendingEvents: Number(pending?.count ?? 0), failedEvents: Number(pending?.failed ?? 0) };
  }
}
function pagination(filters: { page?: number; pageSize?: number }) {
  return { page: Math.max(1, Math.min(1_000_000, Math.trunc(filters.page || 1))), pageSize: Math.max(1, Math.min(100, Math.trunc(filters.pageSize || 25))) };
}
