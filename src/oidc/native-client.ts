import type { ClientRecord } from '../domain/types.js';

type Policy = Pick<ClientRecord, 'applicationType' | 'corsOrigins' | 'clientType' | 'redirectUris' | 'postLogoutRedirectUris'>;

/** Explicit native metadata, never inferred from a client name or redirect. */
export function validateClientApplication(client: Policy): void {
  const type = client.applicationType ?? 'web';
  if (!['web', 'native'].includes(type)) throw new Error('Invalid application type.');
  if (type === 'web') {
    if (client.corsOrigins?.length) throw new Error('Explicit CORS origins require a native client.');
    return;
  }
  if (client.clientType !== 'public') throw new Error('Native clients must be public and use PKCE.');
  if (!client.redirectUris.length || !client.corsOrigins?.length || client.corsOrigins.length > 8) {
    throw new Error('Native clients require redirects and a bounded explicit CORS allowlist.');
  }
  for (const origin of client.corsOrigins) {
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

export function nativeCorsAllowed(origin: string, client: { applicationType?: string; corsOrigins?: readonly string[] }): boolean {
  if (origin === 'null' || origin === '*') return false;
  return client.applicationType === 'native' && (client.corsOrigins ?? []).some((allowed) => {
    try { return !allowed.includes('*') && new URL(allowed).protocol === 'https:' && new URL(allowed).origin === allowed && allowed === origin; }
    catch { return false; }
  });
}
