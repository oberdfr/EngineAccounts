import crypto from 'node:crypto';

/**
 * Primitive crittografiche di servizio. Nessuna e' scritta a mano: qui ci sono
 * solo *wrapper* e *scelte di formato* attorno alle API di `node:crypto` (D8).
 */

/** base64url senza padding, come in RFC 7515 e come la vuole oidc-provider. */
export const b64url = (input: Buffer | string): string =>
  (Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8')).toString('base64url');

/**
 * Confronta due stringhe a tempo costante.
 *
 * Nessun early return: si allineano a `max(len)` byte e si accumula lo XOR di
 * tutti, sommandolo anche alla differenza di lunghezza. Il numero di iterazioni
 * dipende solo dalla lunghezza massima, non da dove diverge la stringa.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  const len = Math.max(bufA.length, bufB.length, 1);
  const pa = Buffer.alloc(len);
  const pb = Buffer.alloc(len);
  bufA.copy(pa);
  bufB.copy(pb);
  let diff = bufA.length ^ bufB.length;
  for (let i = 0; i < len; i++) {
    diff |= pa[i]! ^ pb[i]!;
  }
  return diff === 0;
}

/** Token casuale opaco, url-safe. 32 byte = 256 bit di entropia. */
export function randomToken(bytes = 32): string {
  return b64url(crypto.randomBytes(bytes));
}

export function hmacSha256(key: Buffer, data: string): string {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest('base64url');
}

/**
 * Cifratura a riposo AES-256-GCM, formato `v1.<iv>.<tag>.<ciphertext>` in base64url.
 * Serve per il segreto TOTP: in chiaro nel database un attaccante potrebbe
 * generare codici MFA a piacere.
 */
export function encrypt(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${b64url(iv)}.${b64url(tag)}.${b64url(ct)}`;
}

export function decrypt(key: Buffer, envelope: string): string {
  const [version, ivB64, tagB64, ctB64] = envelope.split('.');
  if (version !== 'v1' || !ivB64 || !tagB64 || !ctB64) throw new Error('formato cifrato non valido');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64url')), decipher.final()]).toString('utf8');
}

/** Etichetta per device/sessione: niente user agent grezzo nelle liste. */
export function deviceLabel(userAgent: string | null, ip: string | null): string {
  const ua = (userAgent ?? '').toLowerCase();
  let browser = 'Browser sconosciuto';
  if (/edg\//.test(ua)) browser = 'Edge';
  else if (/opr\/|opera/.test(ua)) browser = 'Opera';
  else if (/chrome\//.test(ua)) browser = 'Chrome';
  else if (/firefox\//.test(ua)) browser = 'Firefox';
  else if (/safari\//.test(ua)) browser = 'Safari';

  let os = 'sistema sconosciuto';
  if (/windows/.test(ua)) os = 'Windows';
  else if (/android/.test(ua)) os = 'Android';
  else if (/iphone|ipad|ios/.test(ua)) os = 'iOS';
  else if (/mac os x/.test(ua)) os = 'macOS';
  else if (/linux/.test(ua)) os = 'Linux';

  const ipPart = ip && ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  return `${browser} su ${os}${ipPart ? ` · ${ipPart}` : ''}`;
}

/** Legge il valore di un cookie da un header `Set-Cookie` (usato dopo l'interaction). */
export function readSetCookie(headers: unknown, name: string): string | undefined {
  const raw = (() => {
    const res = headers as { getHeader?: (k: string) => unknown };
    if (res && typeof res.getHeader === 'function') return res.getHeader('set-cookie');
    return headers;
  })();
  if (!raw) return undefined;
  const list = Array.isArray(raw) ? (raw as string[]) : [String(raw)];
  for (const entry of list) {
    const [pair] = entry.split(';');
    if (!pair) continue;
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    if (pair.slice(0, idx).trim() === name) return decodeURIComponent(pair.slice(idx + 1).trim());
  }
  return undefined;
}