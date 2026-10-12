import crypto from 'node:crypto';
import { constantTimeEqual } from './crypto.js';

/**
 * CSRF — doppio submit.
 *
 * Il cookie `__Host-ea_csrf` e' random a 256 bit e non ha attributo `Domain`:
 * solo il nostro origin puo' scriverlo, quindi nessun sottodominio (ne' un
 * attaccante che ne controlla uno) puo' farlo leggere al browser come nostro.
 * Su http (sviluppo) il prefisso `__Host-` viene omesso, perche' richiede
 * `Secure`; la protezione resta la stessa.
 *
 * Il form deve rimandare lo stesso valore in un campo nascosto; il confronto e'
 * a tempo costante.
 *
 * Le rotte OIDC che autenticano il client (token, introspect, revoke, userinfo)
 * non sono protette da CSRF: non usano la sessione di login, e l'autenticazione
 * del client (secret, o `none` + PKCE) e' il loro controllo.
 */

export const CSRF_FIELD = '_csrf';
export const CSRF_HEADER = 'x-csrf-token';

export function csrfCookieName(cookiePrefix: string): string {
  return `${cookiePrefix}ea_csrf`;
}

export function issueCsrfToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function verifyCsrfToken(expected: string | undefined, received: unknown): boolean {
  if (typeof received !== 'string' || !received) return false;
  if (typeof expected !== 'string' || !expected) return false;
  if (expected.length !== received.length) return false;
  return constantTimeEqual(expected, received);
}

/** Percorsi di gestione: la sola parte della UI che scrive. */
export function isCsrfProtected(method: string, url: string): boolean {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) return false;
  const path = url.split('?')[0] ?? '';
  return (
    path.startsWith('/ui/') ||
    path === '/ui' ||
    path.startsWith('/account/') ||
    path === '/admin' ||
    path.startsWith('/admin/') ||
    path === '/account' ||
    path === '/account/logout'
  );
}
