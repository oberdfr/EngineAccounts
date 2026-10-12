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
} from './types.js';

/**
 * Interfacce di persistenza: il "porto" che vede il resto del servizio.
 *
 * L'implementazione Postgres (`db/repositories.ts`) e' un dettaglio: i test
 * possono sostituirla, e il dominio non dipende da `pg` ne' da oidc-provider.
 */

export interface AccountsStore {
  findUserById(id: string): Promise<User | undefined>;
  findUserByEmail(email: string): Promise<User | undefined>;
  findUserByEmailAnyStatus(email: string): Promise<User | undefined>;
  createUser(input: {
    email: string;
    passwordHash: string;
    displayName: string | null;
    emailVerifiedAt: Date | null;
  }): Promise<User>;
  updateUser(id: string, patch: Partial<Record<keyof User, unknown>>): Promise<User | undefined>;
  setUserStatus(id: string, status: UserStatus, reason: string | null, actor: string): Promise<void>;
  recordLoginFailure(id: string, lockedUntil: Date | null, failedLogins: number): Promise<void>;
  countUsers(): Promise<number>;

  // --- sessioni ------------------------------------------------------------
  createSession(input: Omit<SessionRecord, 'lastSeenAt' | 'revokedAt' | 'revokeReason'>): Promise<SessionRecord>;
  findSession(id: string): Promise<SessionRecord | undefined>;
  findSessionByTokenDigest(digest: string): Promise<SessionRecord | undefined>;
  touchSession(id: string): Promise<void>;
  linkProviderSession(id: string, providerSessionId: string, providerSessionUid: string | null): Promise<void>;
  listSessions(userId: string): Promise<SessionRecord[]>;
  revokeSession(id: string, reason: string): Promise<SessionRecord | undefined>;
  revokeAllSessions(userId: string, reason: string, exceptId?: string): Promise<string[]>;

  // --- token monouso -------------------------------------------------------
  createAccountToken(input: {
    userId: string;
    purpose: TokenPurpose;
    tokenDigest: string;
    payload?: Record<string, unknown>;
    expiresAt: Date;
    targetEmail: string;
  }): Promise<AccountToken>;
  findAccountToken(purpose: TokenPurpose, tokenDigest: string): Promise<AccountToken | undefined>;
  consumeAccountToken(id: string): Promise<void>;
  invalidateAccountTokens(userId: string, purpose: TokenPurpose): Promise<number>;
  updateUserEmail(id: string, email: string, verifiedAt: Date): Promise<User>;

  // --- client e consensi ---------------------------------------------------
  findClient(clientId: string): Promise<ClientRecord | undefined>;
  listClients(): Promise<ClientRecord[]>;
  upsertClient(input: Omit<ClientRecord, 'createdAt' | 'updatedAt'>): Promise<ClientRecord>;
  listServices(): Promise<ServiceRecord[]>;
  listServiceScopes(): Promise<ScopeRecord[]>;
  getConsent(userId: string, clientId: string): Promise<ConsentRecord | undefined>;
  saveConsent(input: {
    userId: string;
    clientId: string;
    scope: string[];
    expiresAt: Date | null;
  }): Promise<ConsentRecord>;
  revokeConsent(userId: string, clientId: string): Promise<boolean>;
  revokeAllConsents(userId: string): Promise<number>;
  listConsents(userId: string): Promise<(ConsentRecord & { clientName: string })[]>;

  // --- MFA -----------------------------------------------------------------
  getTotp(userId: string): Promise<TotpRecord | undefined>;
  saveTotp(userId: string, secretCt: string): Promise<TotpRecord>;
  confirmTotp(userId: string): Promise<void>;
  setTotpEnabled(userId: string, enabled: boolean): Promise<void>;
  touchTotp(userId: string): Promise<void>;
  deleteTotp(userId: string): Promise<void>;

  listWebauthnCredentials(userId: string): Promise<WebauthnCredential[]>;
  findWebauthnCredential(credentialId: string): Promise<WebauthnCredential | undefined>;
  addWebauthnCredential(input: Omit<WebauthnCredential, 'id' | 'createdAt' | 'lastUsedAt' | 'counter'>): Promise<WebauthnCredential>;
  updateWebauthnCounter(id: string, counter: number): Promise<void>;
  touchWebauthnCredential(id: string): Promise<void>;
  deleteWebauthnCredential(userId: string, credentialId: string): Promise<boolean>;
  renameWebauthnCredential(userId: string, credentialId: string, nickname: string): Promise<boolean>;

  replaceRecoveryCodes(userId: string, digests: string[]): Promise<number>;
  consumeRecoveryCode(userId: string, digest: string): Promise<boolean>;
  countUnusedRecoveryCodes(userId: string): Promise<number>;
  deleteRecoveryCodes(userId: string): Promise<number>;

  // --- audit ---------------------------------------------------------------
  appendAudit(entry: AuditEntry): Promise<AuditLogEntry>;
  listAudit(userId: string, limit: number, offset?: number): Promise<AuditLogEntry[]>;
  countAudit(userId: string): Promise<number>;

  // --- esportazione / cancellazione ---------------------------------------
  exportAccountData(userId: string, auditLimit: number): Promise<AccountDataExport>;
}

/**
 * Store dei token OIDC. `OidcEntry` e' un tipo **nostro**: e' il payload JSON
 * che la libreria ci consegna e che le restituiamo identico. Non importiamo
 * nulla da oidc-provider, cosi' questo file non puo' rompersi al cambio di
 * versione della libreria.
 */
export interface OidcEntry {
  [key: string]: unknown;
}

export type OidcModelKind = 'codes' | 'tokens' | 'grants' | 'sessions' | 'interactions' | 'replay';

export interface OidcTokenStore {
  upsert(kind: OidcModelKind, id: string, payload: OidcEntry, expiresIn?: number): Promise<void>;
  find(kind: OidcModelKind, id: string): Promise<OidcEntry | undefined>;
  findByUid(kind: OidcModelKind, uid: string): Promise<OidcEntry | undefined>;
  findByUserCode(kind: OidcModelKind, userCode: string): Promise<OidcEntry | undefined>;
  consume(kind: OidcModelKind, id: string): Promise<void>;
  destroy(kind: OidcModelKind, id: string): Promise<void>;
  revokeByGrantId(grantId: string): Promise<number>;
  /** Evidenza di famiglia per i test e per il pannello account. */
  listGrantTokens(grantId: string): Promise<
    {
      id: string;
      kind: string;
      rotations: number;
      consumedAt: Date | null;
      revokedAt: Date | null;
      expiresAt: Date | null;
    }[]
  >;
  listUserTokens(userId: string): Promise<
    { id: string; kind: string; grantId: string | null; clientId: string | null; sessionUid: string | null; revokedAt: Date | null; expiresAt: Date | null }[]
  >;
  revokeUserGrants(userId: string, sessionUid?: string): Promise<number>;
  destroyProviderSession(sessionId: string): Promise<void>;
  findProviderSessionByUid(uid: string): Promise<{ id: string; accountId: string | null } | undefined>;
}