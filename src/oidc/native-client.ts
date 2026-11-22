import type { ClientRecord } from '../domain/types.js';

type Policy = Pick<ClientRecord, 'applicationType' | 'corsOrigins' | 'clientType' | 'redirectUris' | 'postLogoutRedirectUris'> &
  Partial<Pick<ClientRecord, 'grantTypes'>>;

export const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * Origini opache delle app TV impacchettate servite da file://. LG webOS 6
 * (Chromium 79) invia `Origin: file://<appId>-webos` (verificato su TV
 * reale); altre versioni `file://` o `null`. Ammesse solo per client
 * device-flow che le dichiarano esattamente.
 */
function isOpaqueTvOrigin(origin: string): boolean {
  return origin === 'null' || /^file:\/\/[a-z0-9.-]*$/i.test(origin);
}

/** Un client che usa il Device Authorization Grant (RFC 8628), tipicamente una TV. */
export function isDeviceClient(client: { grantTypes?: readonly string[] }): boolean {
  return (client.grantTypes ?? []).includes(DEVICE_GRANT);
}

/** Device-only: nessun redirect, quindi nessuna navigazione verso l'app. */
function isDeviceOnly(client: { grantTypes?: readonly string[] }): boolean {
  return isDeviceClient(client) && !(client.grantTypes ?? []).includes('authorization_code');
}

/** Explicit native metadata, never inferred from a client name or redirect. */
export function validateClientApplication(client: Policy): void {
  const type = client.applicationType ?? 'web';
  if (!['web', 'native'].includes(type)) throw new Error('Invalid application type.');
  if (type === 'web') {
    if (client.corsOrigins?.length) throw new Error('Explicit CORS origins require a native client.');
    return;
  }
  if (client.clientType !== 'public') throw new Error('Native clients must be public and use PKCE.');
  if ((!client.redirectUris.length && !isDeviceOnly(client)) || !client.corsOrigins?.length || client.corsOrigins.length > 8) {
    throw new Error('Native clients require redirects and a bounded explicit CORS allowlist.');
  }
  for (const origin of client.corsOrigins) {
    // Il literal `null` (webOS file://) e' ammesso solo per i client device-flow, esplicitamente.
    if (isOpaqueTvOrigin(origin) && isDeviceClient(client)) continue;
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password || origin.includes('*')) {
      throw new Error('Native CORS origins must be exact HTTPS origins, not paths, wildcards or null.');
    }
  }
  for (const uri of [...client.redirectUris, ...client.postLogoutRedirectUris]) {
    const url = new URL(uri);
    const custom = /^[a-z][a-z0-9+.-]*:$/.test(url.protocol) &&
      (url.protocol.includes('.') || url.protocol === 'streamingengine:');
    if ((!custom && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash || uri.includes('*')) {
      throw new Error('Native redirects require an exact application scheme or claimed HTTPS URI.');
    }
    if (url.protocol === 'https:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
      throw new Error('Native HTTPS redirects must be claimed public URLs.');
    }
  }
}

export function nativeCorsAllowed(origin: string, client: { applicationType?: string; corsOrigins?: readonly string[]; grantTypes?: readonly string[] }): boolean {
  if (isOpaqueTvOrigin(origin)) {
    return client.applicationType === 'native' && isDeviceClient(client) && (client.corsOrigins ?? []).includes(origin);
  }
  if (origin === '*') return false;
  return client.applicationType === 'native' && (client.corsOrigins ?? []).some((allowed) => {
    try { return !allowed.includes('*') && new URL(allowed).protocol === 'https:' && new URL(allowed).origin === allowed && allowed === origin; }
    catch { return false; }
  });
}
