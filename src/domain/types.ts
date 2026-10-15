/**
 * Tipi di dominio nostri.
 *
 * Regola (ADR-0008, "conseguenze"): i tipi di `oidc-provider` **non** escono dagli
 * adapter. Qui dentro ci sono solo i nostri concetti — utente, sessione, client —
 * e non una riga di codice della libreria. L'adapter di persistenza implementa
 * `AccountsStore` etc. e parla solo con questi tipi.
 */

export type UserStatus = 'active' | 'blocked' | 'deleted';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  displayName: string | null;
  emailVerifiedAt: Date | null;
  status: UserStatus;
  isGlobalAdmin?: boolean;
  mustChangePassword?: boolean;
  blockedReason: string | null;
  totpEnabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
  deletedAt: Date | null;
  failedLogins: number;
  lockedUntil: Date | null;
}

export type TokenPurpose = 'email_verification' | 'password_reset' | 'email_change' | 'magic_code';

export interface AccountToken {
  id: string;
  userId: string;
  purpose: TokenPurpose;
  tokenDigest: string;
  payload: Record<string, unknown>;
  createdAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  targetEmail: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  tokenDigest: string;
  providerSessionId: string | null;
  providerSessionUid: string | null;
  deviceLabel: string;
  ip: string | null;
  userAgent: string | null;
  amr: string[];
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  revokeReason: string | null;
}

export type ClientType = 'public' | 'confidential';

export interface ClientRecord {
  applicationType?: 'web' | 'native';
  corsOrigins?: string[];
  clientId: string;
  clientName: string;
  clientType: ClientType;
  clientSecretHash: string | null;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scope: string[];
  audience: string;
  backchannelEventsUri: string | null;
  tokenEndpointAuthMethod: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConsentRecord {
  id: string;
  userId: string;
  clientId: string;
  scope: string[];
  grantedAt: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
}

export interface ServiceRecord {
  serviceId: string;
  audience: string;
  name: string;
  enabled: boolean;
}

export interface ScopeRecord {
  scope: string;
  serviceId: string;
  description: string;
}

export interface TotpRecord {
  userId: string;
  secretCt: string;
  confirmedAt: Date | null;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export interface WebauthnCredential {
  id: string;
  userId: string;
  credentialId: string;
  publicKey: Buffer;
  counter: number;
  transports: string[];
  aaguid: string | null;
  deviceType: string;
  backedUp: boolean;
  nickname: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export type AuditOutcome = 'success' | 'failure' | 'denied' | 'info';

export interface AuditEntry {
  at?: Date;
  userId?: string | null;
  subjectId?: string | null;
  actor?: string;
  event: string;
  outcome: AuditOutcome;
  ip?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

export interface AuditLogEntry extends AuditEntry {
  id: string;
  at: Date;
  actor: string;
  metadata: Record<string, unknown>;
  prevHash: string | null;
  hash: string;
}

export interface AccountDataExport {
  user: {
    id: string;
    email: string;
    displayName: string | null;
    emailVerifiedAt: Date | null;
    createdAt: Date;
    lastLoginAt: Date | null;
    status: UserStatus;
  };
  sessions: SessionRecord[];
  consents: (ConsentRecord & { clientName: string })[];
  webauthnCredentials: Omit<WebauthnCredential, 'publicKey'>[];
  totpEnabled: boolean;
  auditLog: AuditLogEntry[];
}

export type Amr = 'pwd' | 'otp' | 'mfa' | 'webauthn' | 'recovery_code' | 'magic_code';
