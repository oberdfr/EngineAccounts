import crypto from 'node:crypto';
import { validateClientApplication } from '../oidc/native-client.js';
import type { PoolClient } from 'pg';
import { table, type Db } from './pool.js';
import type { AccountsStore, OidcEntry, OidcModelKind, OidcTokenStore } from '../domain/ports.js';
import type {
  AccountDataExport,
  AccountToken,
  AuditEntry,
  AuditLogEntry,
  ClientRecord,
  ConsentRecord,
  ScopeRecord,
  ServiceRecord,
  SessionRecord,
  TokenPurpose,
  TotpRecord,
  User,
  UserStatus,
  WebauthnCredential,
} from '../domain/types.js';

/* -------------------------------------------------------------------------- */
/* mapping riga -> dominio                                                     */
/* -------------------------------------------------------------------------- */

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  display_name: string | null;
  email_verified_at: Date | null;
  status: UserStatus;
  blocked_reason: string | null;
  totp_enabled: boolean;
  is_global_admin: boolean;
  must_change_password: boolean;
  created_at: Date;
  updated_at: Date;
  last_login_at: Date | null;
  deleted_at: Date | null;
  failed_logins: number;
  locked_until: Date | null;
}

const toUser = (r: UserRow): User => ({
  id: r.id,
  email: r.email,
  passwordHash: r.password_hash,
  displayName: r.display_name,
  emailVerifiedAt: r.email_verified_at,
  status: r.status,
  blockedReason: r.blocked_reason,
  totpEnabled: r.totp_enabled,
  isGlobalAdmin: r.is_global_admin,
  mustChangePassword: r.must_change_password,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
  lastLoginAt: r.last_login_at,
  deletedAt: r.deleted_at,
  failedLogins: r.failed_logins,
  lockedUntil: r.locked_until,
});

interface SessionRow {
  id: string;
  user_id: string;
  token_digest: string;
  provider_session_id: string | null;
  provider_session_uid: string | null;
  device_label: string;
  ip: string | null;
  user_agent: string | null;
  amr: string[];
  created_at: Date;
  last_seen_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  revoke_reason: string | null;
}

const toSession = (r: SessionRow): SessionRecord => ({
  id: r.id,
  userId: r.user_id,
  tokenDigest: r.token_digest,
  providerSessionId: r.provider_session_id,
  providerSessionUid: r.provider_session_uid,
  deviceLabel: r.device_label,
  ip: r.ip,
  userAgent: r.user_agent,
  amr: r.amr ?? [],
  createdAt: r.created_at,
  lastSeenAt: r.last_seen_at,
  expiresAt: r.expires_at,
  revokedAt: r.revoked_at,
  revokeReason: r.revoke_reason,
});

interface ClientRow {
  application_type: 'web' | 'native';
  cors_origins: string[];
  client_id: string;
  client_name: string;
  client_type: 'public' | 'confidential';
  client_secret_hash: string | null;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  scope: string[];
  audience: string;
  backchannel_events_uri: string | null;
  token_endpoint_auth_method: string;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

const toClient = (r: ClientRow): ClientRecord => ({
  applicationType: r.application_type ?? 'web',
  corsOrigins: r.cors_origins ?? [],
  clientId: r.client_id,
  clientName: r.client_name,
  clientType: r.client_type,
  clientSecretHash: r.client_secret_hash,
  redirectUris: r.redirect_uris ?? [],
  postLogoutRedirectUris: r.post_logout_redirect_uris ?? [],
  grantTypes: r.grant_types ?? [],
  responseTypes: r.response_types ?? [],
  scope: r.scope ?? [],
  audience: r.audience,
  backchannelEventsUri: r.backchannel_events_uri,
  tokenEndpointAuthMethod: r.token_endpoint_auth_method,
  enabled: r.enabled,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

interface ConsentRow {
  id: string;
  user_id: string;
  client_id: string;
  scope: string[];
  granted_at: Date;
  expires_at: Date | null;
  revoked_at: Date | null;
}

const toConsent = (r: ConsentRow): ConsentRecord => ({
  id: r.id,
  userId: r.user_id,
  clientId: r.client_id,
  scope: r.scope ?? [],
  grantedAt: r.granted_at,
  expiresAt: r.expires_at,
  revokedAt: r.revoked_at,
});

interface WebauthnRow {
  id: string;
  user_id: string;
  credential_id: string;
  public_key: Buffer;
  counter: string | number;
  transports: string[];
  aaguid: string | null;
  device_type: string;
  backed_up: boolean;
  nickname: string | null;
  created_at: Date;
  last_used_at: Date | null;
}

const toWebauthn = (r: WebauthnRow): WebauthnCredential => ({
  id: r.id,
  userId: r.user_id,
  credentialId: r.credential_id,
  publicKey: r.public_key,
  counter: Number(r.counter),
  transports: r.transports ?? [],
  aaguid: r.aaguid,
  deviceType: r.device_type,
  backedUp: r.backed_up,
  nickname: r.nickname,
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
});

/* -------------------------------------------------------------------------- */
/* AccountsStore                                                               */
/* -------------------------------------------------------------------------- */

const USER_COLS = `id, email, password_hash, display_name, email_verified_at, status,
  blocked_reason, totp_enabled, created_at, updated_at, last_login_at, deleted_at,
  failed_logins, locked_until, is_global_admin, must_change_password`;
const SESSION_COLS = `id, user_id, token_digest, provider_session_id, provider_session_uid, device_label,
  ip, user_agent, amr, created_at, last_seen_at, expires_at, revoked_at, revoke_reason`;
const CLIENT_COLS = `client_id, client_name, client_type, client_secret_hash, redirect_uris,
  post_logout_redirect_uris, grant_types, response_types, scope, audience,
  backchannel_events_uri, token_endpoint_auth_method, enabled, created_at, updated_at, application_type, cors_origins`;
const CONSENT_COLS = `id, user_id, client_id, scope, granted_at, expires_at, revoked_at`;
const WEBAUTHN_COLS = `id, user_id, credential_id, public_key, counter, transports, aaguid,
  device_type, backed_up, nickname, created_at, last_used_at`;

export function createAccountsStore(db: Db): AccountsStore {
  const users = () => table(db, 'users');
  const sessions = () => table(db, 'sessions');
  const accountTokens = () => table(db, 'account_tokens');
  const clients = () => table(db, 'clients');
  const consents = () => table(db, 'client_consents');
  const services = () => table(db, 'services');
  const serviceScopes = () => table(db, 'streaming_scopes');
  const totp = () => table(db, 'totp_secrets');
  const webauthn = () => table(db, 'webauthn_credentials');
  const recovery = () => table(db, 'recovery_codes');
  const audit = () => table(db, 'audit_log');

  /** Esegue una funzione su una transazione, usando lo stesso schema. */
  const tx = <T>(fn: (client: PoolClient) => Promise<T>): Promise<T> => db.tx(fn);
  const q = <R extends Record<string, unknown>>(
    client: PoolClient,
    sql: string,
    params: unknown[] = [],
  ): Promise<R[]> => client.query(sql, params).then((res) => res.rows as R[]);

  return {
    async findUserById(id) {
      const r = await db.one<UserRow>(`SELECT ${USER_COLS} FROM ${users()} WHERE id = $1`, [id]);
      return r ? toUser(r) : undefined;
    },
    async findUserByEmail(email) {
      const r = await db.one<UserRow>(
        `SELECT ${USER_COLS} FROM ${users()} WHERE email = $1 AND status <> 'deleted'`,
        [email],
      );
      return r ? toUser(r) : undefined;
    },
    async findUserByEmailAnyStatus(email) {
      const r = await db.one<UserRow>(`SELECT ${USER_COLS} FROM ${users()} WHERE email = $1`, [email]);
      return r ? toUser(r) : undefined;
    },
    async createUser({ email, passwordHash, displayName, emailVerifiedAt }) {
      const rows = await db.query<UserRow>(
        `INSERT INTO ${users()} (id, email, password_hash, display_name, email_verified_at, status)
         VALUES ($1, $2, $3, $4, $5, 'active')
         RETURNING ${USER_COLS}`,
        [crypto.randomUUID(), email, passwordHash, displayName, emailVerifiedAt],
      );
      return toUser(rows[0]!);
    },
    async updateUser(id, patch) {
      // `status` e `blockedReason` devono stare qui: senza, una cancellazione
      // account anonimizzava i dati ma lasciava `status = 'active'`, e
      // `findAccount` continuava a servire quel `sub` (perche' filtra solo su
      // `status = 'deleted'`).
      const allowed: Record<string, string> = {
        passwordHash: 'password_hash',
        mustChangePassword: 'must_change_password',
        displayName: 'display_name',
        email: 'email',
        emailVerifiedAt: 'email_verified_at',
        totpEnabled: 'totp_enabled',
        lastLoginAt: 'last_login_at',
        deletedAt: 'deleted_at',
        failedLogins: 'failed_logins',
        lockedUntil: 'locked_until',
        status: 'status',
        blockedReason: 'blocked_reason',
      };
      const sets: string[] = [];
      const params: unknown[] = [id];
      for (const [key, value] of Object.entries(patch)) {
        const column = allowed[key];
        if (!column || value === undefined) continue;
        params.push(value);
        sets.push(`${column} = $${params.length}`);
      }
      if (!sets.length) return this.findUserById(id);
      sets.push('updated_at = now()');
      const r = await db.one<UserRow>(
        `UPDATE ${users()} SET ${sets.join(', ')} WHERE id = $1 RETURNING ${USER_COLS}`,
        params,
      );
      return r ? toUser(r) : undefined;
    },
    async setUserStatus(id, status, reason, actor) {
      await db.query(
        `UPDATE ${users()} SET status = $2, blocked_reason = $3, updated_at = now() WHERE id = $1`,
        [id, status, reason],
      );
      await this.appendAudit({
        userId: id,
        actor,
        event: `user.${status === 'blocked' ? 'blocked' : status === 'deleted' ? 'deleted' : 'unblocked'}`,
        outcome: 'info',
        metadata: reason ? { reason } : {},
      });
    },
    async recordLoginFailure(id, lockedUntil, failedLogins) {
      await db.query(
        `UPDATE ${users()} SET failed_logins = $2, locked_until = $3, updated_at = now() WHERE id = $1`,
        [id, failedLogins, lockedUntil],
      );
    },
    async countUsers() {
      const r = await db.one<{ n: string }>(`SELECT count(*)::text AS n FROM ${users()} WHERE status = 'active'`);
      return Number(r?.n ?? 0);
    },

    /* --- sessioni ------------------------------------------------------- */
    async createSession(input) {
      const rows = await db.query<SessionRow>(
        `INSERT INTO ${sessions()}
           (id, user_id, token_digest, provider_session_id, provider_session_uid, device_label, ip, user_agent, amr, created_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10)
         RETURNING ${SESSION_COLS}`,
        [
          input.id,
          input.userId,
          input.tokenDigest,
          input.providerSessionId,
          input.providerSessionUid,
          input.deviceLabel,
          input.ip,
          input.userAgent,
          input.amr,
          input.expiresAt,
        ],
      );
      return toSession(rows[0]!);
    },
    async findSession(id) {
      const r = await db.one<SessionRow>(`SELECT ${SESSION_COLS} FROM ${sessions()} WHERE id = $1`, [id]);
      return r ? toSession(r) : undefined;
    },
    async findSessionByTokenDigest(digest) {
      const r = await db.one<SessionRow>(`SELECT ${SESSION_COLS} FROM ${sessions()} WHERE token_digest = $1`, [
        digest,
      ]);
      return r ? toSession(r) : undefined;
    },
    async touchSession(id) {
      await db.query(`UPDATE ${sessions()} SET last_seen_at = now() WHERE id = $1 AND revoked_at IS NULL`, [id]);
    },
    async linkProviderSession(id, providerSessionId, providerSessionUid) {
      await db.query(
        `UPDATE ${sessions()} SET provider_session_id = $2, provider_session_uid = $3 WHERE id = $1`,
        [id, providerSessionId, providerSessionUid],
      );
    },
    async listSessions(userId, includeInactive = false) {
      const rows = await db.query<SessionRow>(
        `SELECT ${SESSION_COLS} FROM ${sessions()}
         WHERE user_id = $1 AND ($2::boolean OR (revoked_at IS NULL AND expires_at > now()))
         ORDER BY last_seen_at DESC, id`,
        [userId, includeInactive],
      );
      return rows.map(toSession);
    },
    async revokeSession(id, reason) {
      const r = await db.one<SessionRow>(
        `UPDATE ${sessions()} SET revoked_at = now(), revoke_reason = $2
         WHERE id = $1 AND revoked_at IS NULL RETURNING ${SESSION_COLS}`,
        [id, reason],
      );
      return r ? toSession(r) : undefined;
    },
    async revokeAllSessions(userId, reason, exceptId) {
      const rows = await db.query<{ id: string }>(
        `UPDATE ${sessions()} SET revoked_at = now(), revoke_reason = $2
         WHERE user_id = $1 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id <> $3::uuid)
         RETURNING id`,
        [userId, reason, exceptId ?? null],
      );
      return rows.map((r) => r.id);
    },

    /* --- token monouso --------------------------------------------------- */
    async createAccountToken(input) {
      const rows = await db.query<{
        id: string;
        user_id: string;
        purpose: TokenPurpose;
        token_digest: string;
        payload: Record<string, unknown>;
        created_at: Date;
        expires_at: Date;
        consumed_at: Date | null;
        target_email: string;
      }>(
        `INSERT INTO ${accountTokens()} (id, user_id, purpose, token_digest, payload, expires_at, target_email)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [
          crypto.randomUUID(),
          input.userId,
          input.purpose,
          input.tokenDigest,
          JSON.stringify(input.payload ?? {}),
          input.expiresAt,
          input.targetEmail,
        ],
      );
      const r = rows[0]!;
      return {
        id: r.id,
        userId: r.user_id,
        purpose: r.purpose,
        tokenDigest: r.token_digest,
        payload: r.payload,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
        consumedAt: r.consumed_at,
        targetEmail: r.target_email,
      } satisfies AccountToken;
    },
    async findAccountToken(purpose, tokenDigest) {
      const r = await db.one<{
        id: string;
        user_id: string;
        purpose: TokenPurpose;
        token_digest: string;
        payload: Record<string, unknown>;
        created_at: Date;
        expires_at: Date;
        consumed_at: Date | null;
        target_email: string;
      }>(`SELECT * FROM ${accountTokens()} WHERE purpose = $1 AND token_digest = $2`, [purpose, tokenDigest]);
      if (!r) return undefined;
      return {
        id: r.id,
        userId: r.user_id,
        purpose: r.purpose,
        tokenDigest: r.token_digest,
        payload: r.payload,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
        consumedAt: r.consumed_at,
        targetEmail: r.target_email,
      } satisfies AccountToken;
    },
    async consumeAccountToken(id) {
      await db.query(`UPDATE ${accountTokens()} SET consumed_at = now() WHERE id = $1`, [id]);
    },
    async invalidateAccountTokens(userId, purpose) {
      const rows = await db.query(
        `UPDATE ${accountTokens()} SET consumed_at = now()
         WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
        [userId, purpose],
      );
      return rows.length;
    },
    async updateUserEmail(id, email, verifiedAt) {
      const r = await db.one<UserRow>(
        `UPDATE ${users()} SET email = $2, email_verified_at = $3, updated_at = now()
         WHERE id = $1 RETURNING ${USER_COLS}`,
        [id, email, verifiedAt],
      );
      if (!r) throw new Error('utente non trovato');
      return toUser(r);
    },

    /* --- client e consensi ----------------------------------------------- */
    async findClient(clientId) {
      const r = await db.one<ClientRow>(`SELECT ${CLIENT_COLS} FROM ${clients()} WHERE client_id = $1`, [clientId]);
      return r ? toClient(r) : undefined;
    },
    async listClients() {
      const rows = await db.query<ClientRow>(`SELECT ${CLIENT_COLS} FROM ${clients()} ORDER BY client_id`);
      return rows.map(toClient);
    },
    async upsertClient(input) {
      validateClientApplication(input);
      const rows = await db.query<ClientRow>(
        `INSERT INTO ${clients()}
           (client_id, client_name, client_type, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, response_types, scope, audience, backchannel_events_uri, token_endpoint_auth_method, enabled, application_type, cors_origins)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         ON CONFLICT (client_id) DO UPDATE SET
           client_name = EXCLUDED.client_name,
           client_type = EXCLUDED.client_type,
           client_secret_hash = EXCLUDED.client_secret_hash,
           redirect_uris = EXCLUDED.redirect_uris,
           post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
           grant_types = EXCLUDED.grant_types,
           response_types = EXCLUDED.response_types,
           scope = EXCLUDED.scope,
           audience = EXCLUDED.audience,
           backchannel_events_uri = EXCLUDED.backchannel_events_uri,
           token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
           enabled = EXCLUDED.enabled,
           application_type = EXCLUDED.application_type,
           cors_origins = EXCLUDED.cors_origins,
           updated_at = now()
         RETURNING ${CLIENT_COLS}`,
        [
          input.clientId,
          input.clientName,
          input.clientType,
          input.clientSecretHash,
          input.redirectUris,
          input.postLogoutRedirectUris,
          input.grantTypes,
          input.responseTypes,
          input.scope,
          input.audience,
          input.backchannelEventsUri,
          input.tokenEndpointAuthMethod,
          input.enabled,
          input.applicationType ?? 'web',
          input.corsOrigins ?? [],
        ],
      );
      return toClient(rows[0]!);
    },
    async listServices() {
      const rows = await db.query<{ service_id: string; audience: string; name: string; enabled: boolean }>(
        `SELECT service_id, audience, name, enabled FROM ${services()} ORDER BY service_id`,
      );
      return rows.map<ServiceRecord>((r) => ({
        serviceId: r.service_id,
        audience: r.audience,
        name: r.name,
        enabled: r.enabled,
      }));
    },
    async listServiceScopes() {
      const rows = await db.query<{ scope: string; service_id: string; description: string }>(
        `SELECT scope, service_id, description FROM ${serviceScopes()} ORDER BY scope`,
      );
      return rows.map<ScopeRecord>((r) => ({ scope: r.scope, serviceId: r.service_id, description: r.description }));
    },
    async getConsent(userId, clientId) {
      const r = await db.one<ConsentRow>(
        `SELECT ${CONSENT_COLS} FROM ${consents()} WHERE user_id = $1 AND client_id = $2`,
        [userId, clientId],
      );
      return r ? toConsent(r) : undefined;
    },
    async saveConsent({ userId, clientId, scope, expiresAt }) {
      const rows = await db.query<ConsentRow>(
        `INSERT INTO ${consents()} (id, user_id, client_id, scope, expires_at)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (user_id, client_id) DO UPDATE
           SET scope = EXCLUDED.scope, granted_at = now(), expires_at = EXCLUDED.expires_at, revoked_at = NULL
         RETURNING ${CONSENT_COLS}`,
        [crypto.randomUUID(), userId, clientId, scope, expiresAt],
      );
      return toConsent(rows[0]!);
    },
    async revokeConsent(userId, clientId) {
      const rows = await db.query(
        `UPDATE ${consents()} SET revoked_at = now() WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
        [userId, clientId],
      );
      return rows.length > 0;
    },
    async revokeAllConsents(userId) {
      const rows = await db.query(
        `UPDATE ${consents()} SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
        [userId],
      );
      return rows.length;
    },
    async listConsents(userId) {
      const rows = await db.query<ConsentRow & { client_name: string }>(
        `SELECT c.id, c.user_id, c.client_id, c.scope, c.granted_at, c.expires_at, c.revoked_at, cl.client_name
         FROM ${consents()} c JOIN ${clients()} cl ON cl.client_id = c.client_id
         WHERE c.user_id = $1 AND c.revoked_at IS NULL
         ORDER BY c.granted_at DESC`,
        [userId],
      );
      return rows.map((r) => ({ ...toConsent(r), clientName: r.client_name }));
    },

    /* --- MFA -------------------------------------------------------------- */
    async getTotp(userId) {
      const r = await db.one<{
        user_id: string;
        secret_ct: string;
        confirmed_at: Date | null;
        created_at: Date;
        last_used_at: Date | null;
      }>(`SELECT * FROM ${totp()} WHERE user_id = $1`, [userId]);
      if (!r) return undefined;
      return {
        userId: r.user_id,
        secretCt: r.secret_ct,
        confirmedAt: r.confirmed_at,
        createdAt: r.created_at,
        lastUsedAt: r.last_used_at,
      } satisfies TotpRecord;
    },
    async saveTotp(userId, secretCt) {
      const r = await db.one<{
        user_id: string;
        secret_ct: string;
        confirmed_at: Date | null;
        created_at: Date;
        last_used_at: Date | null;
      }>(
        `INSERT INTO ${totp()} (user_id, secret_ct) VALUES ($1,$2)
         ON CONFLICT (user_id) DO UPDATE SET secret_ct = EXCLUDED.secret_ct, confirmed_at = NULL
         RETURNING *`,
        [userId, secretCt],
      );
      return {
        userId: r!.user_id,
        secretCt: r!.secret_ct,
        confirmedAt: r!.confirmed_at,
        createdAt: r!.created_at,
        lastUsedAt: r!.last_used_at,
      } satisfies TotpRecord;
    },
    async confirmTotp(userId) {
      await tx(async (client) => {
        await q(client, `UPDATE ${totp()} SET confirmed_at = now() WHERE user_id = $1`, [userId]);
        await q(client, `UPDATE ${users()} SET totp_enabled = true, updated_at = now() WHERE id = $1`, [userId]);
      });
    },
    async setTotpEnabled(userId, enabled) {
      await db.query(`UPDATE ${users()} SET totp_enabled = $2, updated_at = now() WHERE id = $1`, [userId, enabled]);
    },
    async touchTotp(userId) {
      await db.query(`UPDATE ${totp()} SET last_used_at = now() WHERE user_id = $1`, [userId]);
    },
    async deleteTotp(userId) {
      await db.query(`DELETE FROM ${totp()} WHERE user_id = $1`, [userId]);
    },

    async listWebauthnCredentials(userId) {
      const rows = await db.query<WebauthnRow>(
        `SELECT ${WEBAUTHN_COLS} FROM ${webauthn()} WHERE user_id = $1 ORDER BY created_at`,
        [userId],
      );
      return rows.map(toWebauthn);
    },
    async findWebauthnCredential(credentialId) {
      const r = await db.one<WebauthnRow>(`SELECT ${WEBAUTHN_COLS} FROM ${webauthn()} WHERE credential_id = $1`, [
        credentialId,
      ]);
      return r ? toWebauthn(r) : undefined;
    },
    async addWebauthnCredential(input) {
      const r = await db.one<WebauthnRow>(
        `INSERT INTO ${webauthn()} (id, user_id, credential_id, public_key, transports, aaguid, device_type, backed_up, nickname)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING ${WEBAUTHN_COLS}`,
        [
          crypto.randomUUID(),
          input.userId,
          input.credentialId,
          input.publicKey,
          input.transports,
          input.aaguid,
          input.deviceType,
          input.backedUp,
          input.nickname,
        ],
      );
      return toWebauthn(r!);
    },
    async updateWebauthnCounter(id, counter) {
      await db.query(`UPDATE ${webauthn()} SET counter = $2, last_used_at = now() WHERE id = $1`, [id, counter]);
    },
    async touchWebauthnCredential(id) {
      await db.query(`UPDATE ${webauthn()} SET last_used_at = now() WHERE id = $1`, [id]);
    },
    async deleteWebauthnCredential(userId, credentialId) {
      const rows = await db.query(`DELETE FROM ${webauthn()} WHERE user_id = $1 AND credential_id = $2`, [
        userId,
        credentialId,
      ]);
      return rows.length > 0;
    },
    async renameWebauthnCredential(userId, credentialId, nickname) {
      const rows = await db.query(
        `UPDATE ${webauthn()} SET nickname = $3 WHERE user_id = $1 AND credential_id = $2`,
        [userId, credentialId, nickname],
      );
      return rows.length > 0;
    },

    async replaceRecoveryCodes(userId, digests) {
      return tx(async (client) => {
        await q(client, `DELETE FROM ${recovery()} WHERE user_id = $1`, [userId]);
        for (const digest of digests) {
          await q(client, `INSERT INTO ${recovery()} (id, user_id, digest) VALUES ($1,$2,$3)`, [
            crypto.randomUUID(),
            userId,
            digest,
          ]);
        }
        return digests.length;
      });
    },
    async consumeRecoveryCode(userId, digest) {
      // Una sola transazione: il check-and-consume deve essere atomico, altrimenti
      // lo stesso codice di recupero si riusa in concorrenza.
      return tx(async (client) => {
        const rows = await q<{ id: string }>(
          client,
          `UPDATE ${recovery()} SET used_at = now()
           WHERE user_id = $1 AND digest = $2 AND used_at IS NULL RETURNING id`,
          [userId, digest],
        );
        return rows.length > 0;
      });
    },
    async countUnusedRecoveryCodes(userId) {
      const r = await db.one<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${recovery()} WHERE user_id = $1 AND used_at IS NULL`,
        [userId],
      );
      return Number(r?.n ?? 0);
    },
    async deleteRecoveryCodes(userId) {
      const rows = await db.query(`DELETE FROM ${recovery()} WHERE user_id = $1`, [userId]);
      return rows.length;
    },

    /* --- audit ------------------------------------------------------------ */
    async appendAudit(entry) {
      // Catena di hash: l'advisory lock serializza gli append, cosi' `prev_hash`
      // e' sempre l'ultima riga. Un UPDATE/DELETE su audit_log e' impossibile
      // (trigger) e una riga mancante rompe la catena.
      return tx(async (client) => {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['engine_accounts:audit']);
        const prev = await client.query<{ hash: string }>(
          `SELECT hash FROM ${audit()} ORDER BY id DESC LIMIT 1`,
        );
        const prevHash = prev.rows[0]?.hash ?? null;
        const at = entry.at ?? new Date();
        const actor = entry.actor ?? 'user';
        const metadata = entry.metadata ?? {};
        const canonical = JSON.stringify([at.toISOString(), entry.userId ?? null, entry.subjectId ?? null, actor, entry.event, entry.outcome, entry.ip ?? null, entry.userAgent ?? null, metadata]);
        const hash = crypto.createHash('sha256').update(`${prevHash ?? ''}\n${canonical}`).digest('hex');
        const rows = await client.query(
          `INSERT INTO ${audit()} (at, user_id, subject_id, actor, event, outcome, ip, user_agent, metadata, prev_hash, hash)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id, at, prev_hash`,
          [
            at,
            entry.userId ?? null,
            entry.subjectId ?? null,
            actor,
            entry.event,
            entry.outcome,
            entry.ip ?? null,
            entry.userAgent ?? null,
            JSON.stringify(metadata),
            prevHash,
            hash,
          ],
        );
        const r = rows.rows[0] as { id: string; at: Date; prev_hash: string | null };
        return {
          id: String(r.id),
          at: r.at,
          userId: entry.userId ?? null,
          subjectId: entry.subjectId ?? null,
          actor,
          event: entry.event,
          outcome: entry.outcome,
          ip: entry.ip ?? null,
          userAgent: entry.userAgent ?? null,
          metadata,
          prevHash: r.prev_hash,
          hash,
        } satisfies AuditLogEntry;
      });
    },
    async listAudit(userId, limit, offset = 0) {
      const rows = await db.query<{
        id: string;
        at: Date;
        user_id: string | null;
        subject_id: string | null;
        actor: string;
        event: string;
        outcome: string;
        ip: string | null;
        user_agent: string | null;
        metadata: Record<string, unknown>;
        prev_hash: string | null;
        hash: string;
      }>(
        `SELECT id, at, user_id, subject_id, actor, event, outcome, ip, user_agent, metadata, prev_hash, hash
         FROM ${audit()} WHERE user_id = $1 ORDER BY id DESC LIMIT $2 OFFSET $3`,
        [userId, limit, offset],
      );
      return rows.map((r) => ({
        id: String(r.id),
        at: r.at,
        userId: r.user_id,
        subjectId: r.subject_id,
        actor: r.actor,
        event: r.event,
        outcome: r.outcome as AuditEntry['outcome'],
        ip: r.ip,
        userAgent: r.user_agent,
        metadata: r.metadata,
        prevHash: r.prev_hash,
        hash: r.hash,
      }));
    },
    async countAudit(userId) {
      const r = await db.one<{ n: string }>(`SELECT count(*)::text AS n FROM ${audit()} WHERE user_id = $1`, [userId]);
      return Number(r?.n ?? 0);
    },

    /* --- esportazione / cancellazione -------------------------------------- */
    async exportAccountData(userId, auditLimit) {
      const user = await this.findUserById(userId);
      if (!user) throw new Error('utente non trovato');
      const credentials = await this.listWebauthnCredentials(userId);
      const data: AccountDataExport = {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          emailVerifiedAt: user.emailVerifiedAt,
          createdAt: user.createdAt,
          lastLoginAt: user.lastLoginAt,
          status: user.status,
        },
        sessions: await this.listSessions(userId),
        consents: await this.listConsents(userId),
        webauthnCredentials: credentials.map(({ publicKey: _publicKey, ...rest }) => rest),
        totpEnabled: user.totpEnabled,
        auditLog: await this.listAudit(userId, auditLimit),
      };
      return data;
    },
  };
}

/* -------------------------------------------------------------------------- */
/* OidcTokenStore                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Store dei modelli della libreria. `payload` e' JSON grezzo: la libreria lo
 * consegna e lo riprende identico, noi non lo interpretiamo. Le colonne
 * denormalizzate (grant_id, account_id, client_id, session_uid, ...) servono a
 * revocare per famiglia, per utente o per dispositivo senza scansionare JSON.
 */
export function createOidcTokenStore(db: Db): OidcTokenStore {
  const T = {
    codes: table(db, 'oidc_codes'),
    tokens: table(db, 'oidc_tokens'),
    grants: table(db, 'oidc_grants'),
    sessions: table(db, 'oidc_sessions'),
    interactions: table(db, 'oidc_interactions'),
    replay: table(db, 'jti_replay'),
  } as const;

  const expiresAt = (payload: OidcEntry, expiresIn?: number): Date | null => {
    if (typeof payload.exp === 'number') return new Date(payload.exp * 1000);
    if (typeof expiresIn === 'number') return new Date(Date.now() + expiresIn * 1000);
    return null;
  };
  const str = (value: unknown): string | null => (typeof value === 'string' ? value : null);
  const num = (value: unknown): number | null => (typeof value === 'number' ? value : null);

  /** Estrae i campi che ci servono per indicizzare, senza assumere nulla sul resto. */
  const index = (payload: OidcEntry) => ({
    grantId: str(payload.grantId),
    accountId: str(payload.accountId),
    clientId: str(payload.clientId),
    sessionUid: str(payload.sessionUid),
    scope: str(payload.scope),
    audience: Array.isArray(payload.aud) ? undefined : str(payload.aud),
    userCode: str(payload.userCode),
    rotations: num(payload.rotations) ?? 0,
    iss: str(payload.iss),
    uid: str(payload.uid),
  });

  return {
    async upsert(kind, id, payload, expiresIn) {
      const exp = expiresAt(payload, expiresIn);
      const ix = index(payload);
      const json = JSON.stringify(payload);
      switch (kind) {
        case 'codes': {
          await db.query(
            `INSERT INTO ${T.codes} (id, kind, grant_id, account_id, client_id, user_code, payload, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, grant_id = EXCLUDED.grant_id,
               account_id = EXCLUDED.account_id, client_id = EXCLUDED.client_id,
               user_code = EXCLUDED.user_code, payload = EXCLUDED.payload,
               expires_at = EXCLUDED.expires_at, revoked_at = NULL`,
            [id, str(payload.kind) ?? kind, ix.grantId, ix.accountId, ix.clientId, ix.userCode, json, exp],
          );
          return;
        }
        case 'tokens': {
          await db.query(
            `INSERT INTO ${T.tokens} (id, kind, grant_id, account_id, client_id, session_uid, scope, audience, payload, expires_at, rotations)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, grant_id = EXCLUDED.grant_id,
               account_id = EXCLUDED.account_id, client_id = EXCLUDED.client_id,
               session_uid = EXCLUDED.session_uid, scope = EXCLUDED.scope,
               audience = EXCLUDED.audience, payload = EXCLUDED.payload,
               expires_at = EXCLUDED.expires_at, rotations = EXCLUDED.rotations, revoked_at = NULL`,
            [
              id,
              str(payload.kind) ?? kind,
              ix.grantId,
              ix.accountId,
              ix.clientId,
              ix.sessionUid,
              ix.scope,
              ix.audience,
              json,
              exp,
              ix.rotations,
            ],
          );
          return;
        }
        case 'grants': {
          await db.query(
            `INSERT INTO ${T.grants} (grant_id, account_id, client_id, payload, expires_at)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (grant_id) DO UPDATE SET account_id = EXCLUDED.account_id,
               client_id = EXCLUDED.client_id, payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at`,
            [id, ix.accountId, ix.clientId, json, exp],
          );
          return;
        }
        case 'sessions': {
          if (!ix.uid) return; // Session senza uid: la libreria non lo usa come indice
          await db.query(
            `INSERT INTO ${T.sessions} (id, uid, account_id, payload, expires_at)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (id) DO UPDATE SET uid = EXCLUDED.uid, account_id = EXCLUDED.account_id,
               payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at, revoked_at = NULL`,
            [id, ix.uid, ix.accountId, json, exp],
          );
          return;
        }
        case 'interactions': {
          await db.query(
            `INSERT INTO ${T.interactions} (id, kind, payload, expires_at)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at`,
            [id, str(payload.kind) ?? 'Interaction', json, exp],
          );
          return;
        }
        case 'replay': {
          await db.query(
            `INSERT INTO ${T.replay} (jti, kind, iss, expires_at) VALUES ($1,$2,$3,$4)
             ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
            [id, str(payload.kind) ?? 'ReplayDetection', ix.iss, exp],
          );
          return;
        }
      }
    },

    async find(kind, id) {
      const sql = {
        codes: `SELECT payload FROM ${T.codes} WHERE id = $1 AND revoked_at IS NULL`,
        tokens: `SELECT payload FROM ${T.tokens} WHERE id = $1 AND revoked_at IS NULL`,
        grants: `SELECT payload FROM ${T.grants} WHERE grant_id = $1`,
        sessions: `SELECT payload FROM ${T.sessions} WHERE id = $1 AND revoked_at IS NULL`,
        interactions: `SELECT payload FROM ${T.interactions} WHERE id = $1`,
        replay: `SELECT payload FROM ${T.replay} WHERE jti = $1`,
      }[kind];
      const r = await db.one<{ payload: OidcEntry }>(sql, [id]);
      return r?.payload;
    },

    async findByUid(kind, uid) {
      if (kind !== 'sessions') return undefined;
      const r = await db.one<{ payload: OidcEntry }>(
        `SELECT payload FROM ${T.sessions} WHERE uid = $1 AND revoked_at IS NULL`,
        [uid],
      );
      return r?.payload;
    },

    async findByUserCode(kind, userCode) {
      if (kind !== 'codes') return undefined;
      const r = await db.one<{ payload: OidcEntry }>(
        `SELECT payload FROM ${T.codes} WHERE user_code = $1 AND revoked_at IS NULL`,
        [userCode],
      );
      return r?.payload;
    },

    async consume(kind, id) {
      const consumed = Math.floor(Date.now() / 1000);
      const payload = await this.find(kind, id);
      if (!payload) return;
      const next = { ...payload, consumed };
      // `consumed` sta nel payload: la libreria lo riliede al momento del find.
      await this.upsert(kind, id, next);
      if (kind === 'codes' || kind === 'tokens') {
        const column = kind === 'codes' ? T.codes : T.tokens;
        await db.query(`UPDATE ${column} SET consumed_at = now() WHERE id = $1`, [id]);
      } else if (kind === 'interactions') {
        await db.query(`UPDATE ${T.interactions} SET consumed_at = now() WHERE id = $1`, [id]);
      }
    },

    async destroy(kind, id) {
      const column = {
        codes: T.codes,
        tokens: T.tokens,
        grants: T.grants,
        sessions: T.sessions,
        interactions: T.interactions,
        replay: T.replay,
      }[kind];
      const key = kind === 'grants' ? 'grant_id' : kind === 'replay' ? 'jti' : 'id';
      if (kind === 'tokens' || kind === 'codes') {
        // Non cancelliamo: la riga resta come evidenza (test e audit) e `find`
        // smette di restituire il token, che e' il comportamento richiesto.
        await db.query(`UPDATE ${column} SET revoked_at = now() WHERE ${key} = $1 AND revoked_at IS NULL`, [id]);
        return;
      }
      await db.query(`DELETE FROM ${column} WHERE ${key} = $1`, [id]);
    },

    async revokeByGrantId(grantId) {
      // L'intera famiglia: authorization code, access token e refresh token di
      // quel grant. E' il comportamento richiesto dal contratto quando un
      // refresh token viene riusato.
      const res = await db.query(
        `UPDATE ${T.tokens} SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL`,
        [grantId],
      );
      await db.query(`UPDATE ${T.codes} SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL`, [grantId]);
      return res.length;
    },

    async listGrantTokens(grantId) {
      const rows = await db.query<{
        id: string;
        kind: string;
        rotations: number;
        consumed_at: Date | null;
        revoked_at: Date | null;
        expires_at: Date | null;
      }>(
        `SELECT id, kind, rotations, consumed_at, revoked_at, expires_at FROM ${T.tokens}
         WHERE grant_id = $1 ORDER BY created_at`,
        [grantId],
      );
      return rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        rotations: r.rotations,
        consumedAt: r.consumed_at,
        revokedAt: r.revoked_at,
        expiresAt: r.expires_at,
      }));
    },

    async listUserTokens(userId) {
      const rows = await db.query<{
        id: string;
        kind: string;
        grant_id: string | null;
        client_id: string | null;
        session_uid: string | null;
        revoked_at: Date | null;
        expires_at: Date | null;
      }>(
        `SELECT id, kind, grant_id, client_id, session_uid, revoked_at, expires_at FROM ${T.tokens}
         WHERE account_id = $1 ORDER BY created_at DESC LIMIT 500`,
        [userId],
      );
      return rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        grantId: r.grant_id,
        clientId: r.client_id,
        sessionUid: r.session_uid,
        revokedAt: r.revoked_at,
        expiresAt: r.expires_at,
      }));
    },

    async revokeUserGrants(userId, sessionUid) {
      const rows = await db.query<{ grant_id: string }>(
        sessionUid
          ? `SELECT DISTINCT grant_id FROM ${T.tokens} WHERE account_id = $1 AND session_uid = $2 AND grant_id IS NOT NULL`
          : `SELECT DISTINCT grant_id FROM ${T.tokens} WHERE account_id = $1 AND grant_id IS NOT NULL`,
        sessionUid ? [userId, sessionUid] : [userId],
      );
      let count = 0;
      for (const row of rows) {
        count += await this.revokeByGrantId(row.grant_id);
      }
      return count;
    },

    async destroyProviderSession(sessionId) {
      await db.query(`UPDATE ${T.sessions} SET revoked_at = now() WHERE id = $1`, [sessionId]);
    },

    async findProviderSessionByUid(uid) {
      return db.one<{ id: string; account_id: string | null }>(
        `SELECT id, account_id FROM ${T.sessions} WHERE uid = $1 AND revoked_at IS NULL`,
        [uid],
      ).then((r) => (r ? { id: r.id, accountId: r.account_id } : undefined));
    },
  };
}
