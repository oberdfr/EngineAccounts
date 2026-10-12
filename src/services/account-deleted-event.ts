import crypto from 'node:crypto';
import { CompactSign, compactVerify } from 'jose';
import type { Config } from '../config.js';
import type { ClientRecord } from '../domain/types.js';
import type { Db } from '../db/pool.js';
import { createLogger } from '../logger.js';
import { table } from '../db/pool.js';
import { isAllowedBackchannelUri } from '../config.js';

/**
 * C11 — evento di cancellazione account.
 *
 * Payload in `contracts/oidc.md` §8, consumato ad esempio da
 * `POST /internal/events/account-deleted` di StreamingEngine:
 *
 *   { event, sub, iss, aud, iat, exp, jti, signature }
 *
 * `signature` e' un JWS compatto HS256 (HMAC-SHA256) sul **payload canonico**,
 * cioe' la serializzazione JSON dei sette campi *senza* `signature`, nell'ordine
 * esatto in cui sono elencati nel contratto:
 *
 *   event, sub, iss, aud, iat, exp, jti
 *
 * L'ordine delle chiavi e' quello del contratto, non alfabetico: chi verifica
 * deve ricostruire la stringa esattamente cosi'. Il codice qui sotto e' la
 * reference per il proxy (stessa ricostruzione, `jose.verify`).
 *
 * Perche' HS256 e non EdDSA: il segreto e' gia' condiviso fra provider e proxy
 * (`OIDC_EVENT_SIGNING_SECRET`). Non c'e' chiave pubblica da distribuire, e il
 * canale back-channel e' gia' autenticato dal fatto che il provider conosce
 * l'URL solo dei client registrati.
 */

export const ACCOUNT_DELETED = 'account.deleted';
export const ACCOUNT_DATA_PURGE = 'account.data_purge';

/** Ordine dei campi canonici: NON riordinare, e' il contratto. */
export const CANONICAL_FIELDS = ['event', 'sub', 'iss', 'aud', 'iat', 'exp', 'jti'] as const;

export interface AccountDeletedPayload {
  event: typeof ACCOUNT_DELETED | typeof ACCOUNT_DATA_PURGE;
  sub: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
}

export type AccountDeletedEvent = AccountDeletedPayload & { signature: string };

/** Serializzazione canonica: `JSON.stringify` dei sette campi nell'ordine sopra. */
export function canonicalize(payload: AccountDeletedPayload): string {
  return JSON.stringify({
    event: payload.event,
    sub: payload.sub,
    iss: payload.iss,
    aud: payload.aud,
    iat: payload.iat,
    exp: payload.exp,
    jti: payload.jti,
  });
}

export interface EventOptions {
  issuer: string;
  signingKey: Uint8Array;
  ttlSeconds?: number;
  now?: () => number;
  jti?: () => string;
}

export function buildAccountDeletedPayload(sub: string, audience: string, options: EventOptions): AccountDeletedPayload {
  const now = (options.now ?? (() => Math.floor(Date.now() / 1000)))();
  const ttl = options.ttlSeconds ?? 300;
  return {
    event: ACCOUNT_DELETED,
    sub,
    iss: options.issuer,
    aud: audience,
    iat: now,
    exp: now + ttl,
    jti: options.jti ? options.jti() : crypto.randomUUID(),
  };
}

export async function signAccountDeleted(payload: AccountDeletedPayload, key: Uint8Array): Promise<string> {
  // JWS compatto con `alg: HS256` esplicito: nessuna negoziazione, nessun
  // `none`. Il payload firmato e' il **testo canonico**, non un oggetto —
  // quindi firmiamo i byte esatti con `CompactSign` invece di `SignJWT` (che
  // vuole un claims set e ri-serializzerebbe i campi in ordine diverso).
  return new CompactSign(new TextEncoder().encode(canonicalize(payload)))
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .sign(key);
}

export function assembleAccountDeletedEvent(payload: AccountDeletedPayload, signature: string): AccountDeletedEvent {
  return {
    event: payload.event,
    sub: payload.sub,
    iss: payload.iss,
    aud: payload.aud,
    iat: payload.iat,
    exp: payload.exp,
    jti: payload.jti,
    signature,
  };
}

export async function makeAccountDeletedEvent(
  sub: string,
  audience: string,
  options: EventOptions,
): Promise<AccountDeletedEvent> {
  const payload = buildAccountDeletedPayload(sub, audience, options);
  const signature = await signAccountDeleted(payload, options.signingKey);
  return assembleAccountDeletedEvent(payload, signature);
}

/** Same wire format, separate HKDF purpose and service-specific destination. */
export async function makeAccountDataPurgeEvent(sub: string, audience: string, options: EventOptions): Promise<AccountDeletedEvent> {
  const payload = { ...buildAccountDeletedPayload(sub, audience, options), event: ACCOUNT_DATA_PURGE } as AccountDeletedPayload;
  return assembleAccountDeletedEvent(payload, await signAccountDeleted(payload, options.signingKey));
}

/** Verifica lato destinatario: stessa procedura, chiave condivisa. */
export async function verifyAccountDeletedEvent(
  event: unknown,
  key: Uint8Array,
  expected: { iss: string; aud?: string; now?: number; event?: typeof ACCOUNT_DELETED | typeof ACCOUNT_DATA_PURGE },
): Promise<{ valid: true; payload: AccountDeletedPayload } | { valid: false; reason: string }> {
  if (typeof event !== 'object' || event === null) return { valid: false, reason: 'corpo non oggetto' };
  const candidate = event as Record<string, unknown>;
  for (const field of CANONICAL_FIELDS) {
    if (!(field in candidate)) return { valid: false, reason: `campo mancante: ${field}` };
  }
  if (candidate.event !== (expected.event ?? ACCOUNT_DELETED)) return { valid: false, reason: 'evento sconosciuto' };
  if (candidate.iss !== expected.iss) return { valid: false, reason: 'iss non valido' };
  if (expected.aud !== undefined && candidate.aud !== expected.aud) return { valid: false, reason: 'aud non valido' };
  if (typeof candidate.signature !== 'string') return { valid: false, reason: 'firma mancante' };
  const now = expected.now ?? Math.floor(Date.now() / 1000);
  if (typeof candidate.iat !== 'number' || typeof candidate.exp !== 'number' ||
      !Number.isInteger(candidate.iat) || !Number.isInteger(candidate.exp) ||
      candidate.iat > now + 30 || candidate.exp <= now || candidate.exp <= candidate.iat ||
      candidate.exp - candidate.iat > 300) return { valid: false, reason: 'tempo non valido' };
  if (typeof candidate.sub !== 'string' || typeof candidate.aud !== 'string' ||
      typeof candidate.jti !== 'string' || !candidate.jti) return { valid: false, reason: 'claim non validi' };

  const payload: AccountDeletedPayload = {
    event: candidate.event as typeof ACCOUNT_DELETED,
    sub: String(candidate.sub),
    iss: String(candidate.iss),
    aud: String(candidate.aud),
    iat: Number(candidate.iat),
    exp: Number(candidate.exp),
    jti: String(candidate.jti),
  };
  try {
    // `algorithms: ['HS256']` esplicito: mai `none`, mai accept-all.
    const { payload: signed } = await compactVerify(candidate.signature, key, { algorithms: ['HS256'] });
    // La firma copre il testo canonico: verifichiamo che i byte firmati siano
    // proprio quelli, non un insieme di claim con lo stesso contenuto.
    if (new TextDecoder().decode(signed) !== canonicalize(payload)) {
      return { valid: false, reason: 'payload canonico non corrispondente' };
    }
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, reason: `firma non valida: ${(err as Error).message}` };
  }
}

/* -------------------------------------------------------------------------- */
/* outbox + consegna                                                            */
/* -------------------------------------------------------------------------- */

const logger = createLogger((process.env.LOG_LEVEL as never) ?? 'info', { svc: 'engine-accounts' });

export interface EventEmitter {
  emitForClients(sub: string, clients: ClientRecord[]): Promise<{ jti: string; delivered: number; failed: number }>;
  emitDataPurge(sub: string, service: { serviceId: string; audience: string; adminApiUrl: string | null }): Promise<{ jti: string; delivered: number; failed: number }>;
  flushPending(limit?: number): Promise<{ delivered: number; failed: number }>;
}

export function createAccountDeletedEmitter(db: Db, config: Config): EventEmitter {
  const outbox = table(db, 'outbox_events');

  return {
    async emitDataPurge(sub, service) {
      if (!service.adminApiUrl || !isAllowedBackchannelUri(service.adminApiUrl, config.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) {
        throw new Error('API admin del servizio non disponibile');
      }
      const event = await makeAccountDataPurgeEvent(sub, service.audience, {
        issuer: config.issuer, signingKey: config.serviceAdminSigningKey, ttlSeconds: 300,
      });
      await db.query(`INSERT INTO ${outbox} (id,event,sub,audience,jti,payload) VALUES ($1,$2,$3,$4,$5,$6)`,
        [crypto.randomUUID(), event.event, sub, service.audience, event.jti, JSON.stringify(event)]);
      const ok = await deliver(db, config, service.adminApiUrl, event);
      return { jti: event.jti, delivered: ok ? 1 : 0, failed: ok ? 0 : 1 };
    },
    async emitForClients(sub, clients) {
      let delivered = 0;
      let failed = 0;
      let firstJti = '';
      for (const client of clients) {
        if (!client.backchannelEventsUri) continue;
        const event = await makeAccountDeletedEvent(sub, client.audience, {
          issuer: config.issuer,
          signingKey: config.eventSigningKey,
        });
        if (!firstJti) firstJti = event.jti;
        await db.query(
          `INSERT INTO ${outbox} (id, event, sub, audience, jti, payload) VALUES ($1,$2,$3,$4,$5,$6)`,
          [crypto.randomUUID(), event.event, sub, client.audience, event.jti, JSON.stringify(event)],
        );
        const ok = await deliver(db, config, client.backchannelEventsUri, event);
        if (ok) delivered += 1;
        else failed += 1;
      }
      if (delivered || failed) {
        logger.info('evento account.deleted processato', { sub, clients: clients.length, delivered, failed });
      }
      return { jti: firstJti, delivered, failed };
    },

    async flushPending(limit = 20) {
      const rows = await db.query<{ jti: string; audience: string; payload: Record<string, unknown> }>(
        `SELECT jti, audience, payload FROM ${outbox}
         WHERE delivered_at IS NULL ORDER BY created_at LIMIT $1`,
        [limit],
      );
      let delivered = 0;
      let failed = 0;
      for (const row of rows) {
        if (row.payload.event === ACCOUNT_DATA_PURGE) {
          const service = await db.one<{ admin_api_url: string | null; enabled: boolean }>(
            `SELECT admin_api_url, enabled FROM ${table(db, 'services')} WHERE audience = $1`, [row.audience]);
          if (!service?.enabled || !service.admin_api_url || !isAllowedBackchannelUri(service.admin_api_url, config.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) {
            await db.query(`UPDATE ${outbox} SET attempts = attempts + 1, last_error = 'API admin non disponibile' WHERE jti = $1`, [row.jti]);
            failed += 1;
            continue;
          }
          // Retry retains its idempotency key but renews the short delivery window.
          const renewed = await makeAccountDataPurgeEvent(String(row.payload.sub), row.audience, {
            issuer: config.issuer, signingKey: config.serviceAdminSigningKey, jti: () => row.jti,
          });
          await db.query(`UPDATE ${outbox} SET payload = $2 WHERE jti = $1`, [row.jti, JSON.stringify(renewed)]);
          if (await deliver(db, config, service.admin_api_url, renewed)) delivered += 1;
          else failed += 1;
          continue;
        }
        const client = await findClientByAudience(db, row.audience);
        if (!client?.backchannelEventsUri) {
          await db.query(`UPDATE ${outbox} SET attempts = attempts + 1, last_error = 'nessun destinatario' WHERE jti = $1`, [
            row.jti,
          ]);
          failed += 1;
          continue;
        }
        // Stesso jti: il destinatario deve essere idempotente, e lo e' davvero
        // perche' il jti non cambia fra i tentativi.
        const ok = await deliver(
          db,
          config,
          client.backchannelEventsUri,
          row.payload as unknown as AccountDeletedEvent,
        );
        if (ok) delivered += 1;
        else failed += 1;
      }
      return { delivered, failed };
    },
  };
}

async function findClientByAudience(db: Db, audience: string): Promise<ClientRecord | undefined> {
  const row = await db.one<{
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
  }>(
    `SELECT client_id, client_name, client_type, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, response_types, scope, audience, backchannel_events_uri,
            token_endpoint_auth_method, enabled, created_at, updated_at
       FROM ${table(db, 'clients')} WHERE audience = $1 AND enabled = true`,
    [audience],
  );
  if (!row) return undefined;
  return {
    clientId: row.client_id,
    clientName: row.client_name,
    clientType: row.client_type,
    clientSecretHash: row.client_secret_hash,
    redirectUris: row.redirect_uris ?? [],
    postLogoutRedirectUris: row.post_logout_redirect_uris ?? [],
    grantTypes: row.grant_types ?? [],
    responseTypes: row.response_types ?? [],
    scope: row.scope ?? [],
    audience: row.audience,
    backchannelEventsUri: row.backchannel_events_uri,
    tokenEndpointAuthMethod: row.token_endpoint_auth_method,
    enabled: row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function deliver(db: Db, config: Config, url: string, event: AccountDeletedEvent): Promise<boolean> {
  const outbox = table(db, 'outbox_events');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    if (!isAllowedBackchannelUri(url, config.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) throw new Error('destinatario non sicuro');
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: config.issuer },
      body: JSON.stringify(event),
      redirect: 'error',
      signal: controller.signal,
    });
    if ((event.event === ACCOUNT_DATA_PURGE ? res.status === 204 : (res.status >= 200 && res.status < 300)) || res.status === 409) {
      await db.query(`UPDATE ${outbox} SET delivered_at = now(), attempts = attempts + 1, last_error = NULL WHERE jti = $1`, [event.jti]);
      return true;
    }
    await db.query(`UPDATE ${outbox} SET attempts = attempts + 1, last_error = $2 WHERE jti = $1`, [
      event.jti,
      `http ${res.status}`,
    ]);
    logger.warn('evento non accettato', { event: event.event, jti: event.jti, status: res.status });
    return false;
  } catch (err) {
    await db.query(`UPDATE ${outbox} SET attempts = attempts + 1, last_error = $2 WHERE jti = $1`, [
      event.jti,
      'consegna fallita',
    ]);
    logger.warn('consegna evento fallita', { jti: event.jti, event: event.event });
    return false;
  } finally {
    clearTimeout(timer);
  }
}
