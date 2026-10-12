import crypto from 'node:crypto';
import QRCode from 'qrcode';
import { generateTOTP, getTOTPAuthUri, verifyTOTP } from '@epic-web/totp';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { Config } from '../config.js';
import type { AccountsStore } from '../domain/ports.js';
import type { Amr, User } from '../domain/types.js';
import { decrypt, encrypt } from '../security/crypto.js';

/**
 * Secondo fattore: TOTP (RFC 6238) e passkey WebAuthn (RPID = il nostro host).
 *
 * I segreti TOTP sono cifrati a riposo con AES-256-GCM (D4 per questa coda di
 * segreti utente); i codici di recupero sono memorizzati come digest HMAC e sono
 * monouso.
 */

const RECOVERY_CODE_COUNT = 10;

/** Local-only QR encoding: never send the enrollment secret to an external service. */
export async function renderTotpQrSvg(uri: string): Promise<string> {
  if (!uri.startsWith('otpauth://totp/')) throw new Error('Invalid TOTP enrollment URI');
  return QRCode.toString(uri, { type: 'svg', errorCorrectionLevel: 'M', margin: 4, width: 256 });
}

export async function renderTotpQrDataUrl(uri: string): Promise<string> {
  return `data:image/svg+xml;base64,${Buffer.from(await renderTotpQrSvg(uri)).toString('base64')}`;
}

/* ------------------------------ TOTP -------------------------------------- */

export async function startTotpEnrolment(
  store: AccountsStore,
  config: Config,
  user: Pick<User, 'id' | 'email'>,
): Promise<{ secret: string; uri: string }> {
  const existing = await store.getTotp(user.id);
  if (existing?.confirmedAt) throw new Error('TOTP is already enrolled');
  const secret = existing ? decrypt(config.dataKey, existing.secretCt) : (await generateTOTP({ ...TOTP_DEFAULTS })).secret;
  if (!existing) await store.saveTotp(user.id, encrypt(config.dataKey, secret));
  const uri = getTOTPAuthUri({
    ...TOTP_DEFAULTS,
    secret,
    issuer: 'Engine Accounts',
    accountName: user.email,
  });
  return { secret, uri };
}

export async function confirmTotpEnrolment(
  store: AccountsStore,
  config: Config,
  userId: string,
  code: string,
): Promise<boolean> {
  const record = await store.getTotp(userId);
  if (!record) return false;
  const secret = decrypt(config.dataKey, record.secretCt);
  const ok = await verifyTotpCode(secret, code);
  if (!ok) return false;
  await store.confirmTotp(userId);
  return true;
}

/**
 * Parametri TOTP: period 30s, 6 cifre, SHA-1. Sono i default di ogni app
 * authenticator (Google Authenticator, Aegis, 1Password): devono coincidere,
 * altrimenti il codice non viene mai accettato.
 *
 * La finestra di tolleranza e' di 1 periodo (30s): copre l'orologio del telefono
 * sfasato di qualche secondo, e niente di piu' — un codice vale 30 secondi, non
 * un minuto.
 */
const TOTP_DEFAULTS = {
  period: 30,
  digits: 6,
  algorithm: 'SHA-1',
} as const;

/** Verifica un codice TOTP. Tolleranza 1 periodo. */
export async function verifyTotpCode(secret: string, code: string): Promise<boolean> {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  try {
    const result = await verifyTOTP({ otp: normalized, secret, window: 1 });
    return result !== null;
  } catch {
    return false;
  }
}

/** Codice TOTP corrente: serve ai test e al flusso di verifica. */
export async function currentTotpCode(secret: string): Promise<string> {
  const { otp } = await generateTOTP({ ...TOTP_DEFAULTS, secret });
  return otp;
}

export async function verifyTotpForUser(
  store: AccountsStore,
  config: Config,
  userId: string,
  code: string,
): Promise<boolean> {
  const record = await store.getTotp(userId);
  if (!record || !record.confirmedAt) return false;
  const secret = decrypt(config.dataKey, record.secretCt);
  const ok = await verifyTotpCode(secret, code);
  if (ok) await store.touchTotp(userId);
  return ok;
}

export async function disableTotp(store: AccountsStore, userId: string): Promise<void> {
  await store.deleteTotp(userId);
  await store.setTotpEnabled(userId, false);
}

/* --------------------------- codici recupero ------------------------------- */

/** Genera codici di recupero casuali: 10 codici da 10 caratteri, mostrati una volta. */
export function generateRecoveryCodes(): string[] {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // niente I, O, 0, 1
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const bytes = crypto.randomBytes(10);
    let code = '';
    for (const byte of bytes) code += alphabet[byte % alphabet.length];
    codes.push(`${code.slice(0, 5)}-${code.slice(5)}`);
  }
  return codes;
}

export function recoveryCodeDigest(key: Buffer, code: string): string {
  return crypto.createHmac('sha256', key).update(normalizeRecoveryCode(code), 'utf8').digest('base64url');
}

export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/**
 * Un codice di recupero vale come secondo fattore **una volta sola**: viene
 * consumato atomicamente e, se era l'ultimo, l'utente resta con la passkey/TOTP
 * come unica opzione (il pannello lo dice).
 */
export async function consumeRecoveryCode(
  store: AccountsStore,
  key: Buffer,
  userId: string,
  code: string,
): Promise<boolean> {
  return store.consumeRecoveryCode(userId, recoveryCodeDigest(key, code));
}

export async function resetRecoveryCodes(store: AccountsStore, key: Buffer, userId: string): Promise<string[]> {
  const codes = generateRecoveryCodes();
  await store.replaceRecoveryCodes(userId, codes.map((code) => recoveryCodeDigest(key, code)));
  return codes;
}

export async function unusedRecoveryCodeCount(store: AccountsStore, userId: string): Promise<number> {
  return store.countUnusedRecoveryCodes(userId);
}

/* ------------------------------ WebAuthn ----------------------------------- */

/**
 * `rpID` = l'host dell'issuer (contratto: la UI e' servita dallo stesso origin,
 * niente cross-site). Per localhost il browser accetta `localhost` come
 * sicuro; nessun dominio esterno viene accettato.
 */
export function rpIDFromIssuer(issuer: string): string {
  return new URL(issuer).hostname;
}

export async function webauthnRegistrationOptions(
  config: Config,
  user: Pick<User, 'id' | 'email' | 'displayName'>,
  credentials: { credentialId: string; transports: string[] }[] = [],
) {
  return generateRegistrationOptions({
    rpName: 'Engine Accounts',
    rpID: rpIDFromIssuer(config.issuer),
    userID: new TextEncoder().encode(user.id),
    userName: user.email,
    userDisplayName: user.displayName ?? user.email,
    attestationType: 'none',
    excludeCredentials: credentials.map((c) => ({ id: c.credentialId, transports: c.transports })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
  });
}

export interface WebauthnCredentialDraft {
  credentialId: string;
  /** COSE (CBOR) decodificato: la verifica lo ri-codifica per la libreria. */
  publicKey: Buffer;
  counter: number;
  transports: string[];
  aaguid: string | null;
  deviceType: string;
  backedUp: boolean;
  nickname: string | null;
}

export async function completeWebauthnRegistration(
  config: Config,
  response: unknown,
  expectedChallenge: string,
  _user: Pick<User, 'id'>,
): Promise<{ verified: boolean; draft: WebauthnCredentialDraft | null; error?: string }> {
  try {
    const verification = await verifyRegistrationResponse({
      response: response as never,
      expectedChallenge,
      // Solo il nostro origin: una passkey vale solo sul sito che l'ha creata.
      expectedOrigin: [new URL(config.baseUrl).origin, new URL(config.issuer).origin],
      expectedRPID: rpIDFromIssuer(config.issuer),
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo) {
      return { verified: false, draft: null, error: 'verifica fallita' };
    }
    const info = verification.registrationInfo;
    const credential = info.credential as {
      id: string;
      publicKey: Uint8Array;
      counter: number;
      transports?: string[];
    };
    return {
      verified: true,
      draft: {
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey),
        counter: credential.counter ?? 0,
        transports: credential.transports ?? [],
        aaguid: info.aaguid ?? null,
        deviceType: info.credentialDeviceType ?? 'single_device',
        backedUp: info.credentialBackedUp ?? false,
        nickname: null,
      },
    };
  } catch (err) {
    return { verified: false, draft: null, error: (err as Error).message };
  }
}

export async function webauthnAuthenticationOptions(
  config: Config,
  credentials: { credentialId: string; transports: string[] }[],
) {
  return generateAuthenticationOptions({
    rpID: rpIDFromIssuer(config.issuer),
    userVerification: 'required',
    // Senza elenco di credenziali si usa la passkey *discoverable*: l'utente
    // sceglie l'account sul dispositivo e non serve sapere in anticipo quale e'.
    ...(credentials.length
      ? { allowCredentials: credentials.map((c) => ({ id: c.credentialId, transports: c.transports })) }
      : {}),
  });
}

export interface StoredCredentialForVerification {
  credentialId: string;
  publicKey: Buffer;
  counter: number;
  transports: string[];
}

export async function verifyWebauthnAuthentication(
  config: Config,
  response: unknown,
  expectedChallenge: string,
  user: Pick<User, 'id'>,
  credential: StoredCredentialForVerification,
): Promise<{ verified: boolean; newCounter?: number; error?: string }> {
  try {
    const assertion = response as { id?: unknown; response?: { userHandle?: unknown } } | null;
    if (!assertion || assertion.id !== credential.credentialId) return { verified: false, error: 'credenziale non valida' };
    const handle = assertion.response?.userHandle;
    if (handle != null && (typeof handle !== 'string' || !/^[A-Za-z0-9_-]+$/.test(handle)
      || !Buffer.from(handle, 'base64url').equals(Buffer.from(user.id, 'utf8')))) {
      return { verified: false, error: 'account non valido' };
    }
    const verification = await verifyAuthenticationResponse({
      response: response as never,
      expectedChallenge,
      expectedOrigin: [new URL(config.baseUrl).origin, new URL(config.issuer).origin],
      expectedRPID: rpIDFromIssuer(config.issuer),
      credential: {
        id: credential.credentialId,
        publicKey: new Uint8Array(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports,
      },
      requireUserVerification: true,
    });
    return {
      verified: verification.verified,
      ...(verification.authenticationInfo ? { newCounter: verification.authenticationInfo.newCounter } : {}),
      ...(verification.verified ? {} : { error: 'asserzione non verificata' }),
    };
  } catch (err) {
    return { verified: false, error: (err as Error).message };
  }
}

/* --------------------------- Challenge ------------------------------------ */

export interface PendingChallenge {
  kind: 'totp' | 'webauthn' | 'recovery';
  value: string;
  createdAt: number;
}

/** Challenge in corso per una sessione/utente: Challenge non serializza, quindi in memoria. */
export class ChallengeStore {
  private readonly pending = new Map<string, PendingChallenge>();

  set(key: string, challenge: PendingChallenge): void {
    this.pending.set(key, challenge);
  }
  /** Non consuma: serve alla pagina che mostra la challenge. */
  get(key: string): PendingChallenge | undefined {
    return this.pending.get(key);
  }
  /** Consuma: una challenge vale una volta sola. */
  take(key: string): PendingChallenge | undefined {
    const value = this.pending.get(key);
    if (value) this.pending.delete(key);
    return value;
  }
  delete(key: string): void {
    this.pending.delete(key);
  }
  clear(): void {
    this.pending.clear();
  }
  /** Scarta le challenge scadute: `Challenge` non serializza, restano in memoria. */
  sweep(maxAgeMs = 10 * 60_000): void {
    const cutoff = Date.now() - maxAgeMs;
    for (const [key, value] of this.pending) {
      if (value.createdAt < cutoff) this.pending.delete(key);
    }
  }
}
