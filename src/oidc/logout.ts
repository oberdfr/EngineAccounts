import type { KoaContextWithOIDC } from 'oidc-provider';
import { CSP } from '../security/headers.js';

/** Chromium applica form-action anche al redirect successivo al POST.
 * Aggiunge solo l'origine del redirect di logout già validato per questo RP;
 * tutte le altre direttive della risposta rimangono invariate.
 */
function allowLogoutRedirect(ctx: KoaContextWithOIDC): void {
  const uri = ctx.oidc.params?.post_logout_redirect_uri;
  const client = ctx.oidc.client;
  if (typeof uri !== 'string' || !client?.postLogoutRedirectUriAllowed(uri)) return;
  const target = new URL(uri);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') return;
  const policy = ctx.response.get('Content-Security-Policy') || CSP;
  let replaced = false;
  const directives = policy.split(';').map((directive) => {
    if (!/^\s*form-action(?:\s|$)/.test(directive)) return directive;
    replaced = true;
    return ` form-action 'self' ${target.origin}`;
  });
  if (!replaced) directives.push(` form-action 'self' ${target.origin}`);
  ctx.set('Content-Security-Policy', directives.join(';').trim());
}

/** Solo dopo la validazione di firma, issuer, audience e redirect del provider.
 * Un client_id o un parametro «confirmed» non provano il consenso del RP.
 * Il token deve appartenere al login corrente, non solo allo stesso account.
 */
function canAutoSubmit(ctx: KoaContextWithOIDC): boolean {
  const { client, session, entities, params } = ctx.oidc;
  const hint = entities.IdTokenHint?.payload;
  if (!client || !session || !params?.id_token_hint || !params.post_logout_redirect_uri || !hint) return false;
  if (hint.sub !== session.accountId || hint.aud !== client.clientId) return false;
  if (typeof hint.exp !== 'number' || hint.exp <= Math.floor(Date.now() / 1000)) return false;
  if (!session.authorizations?.[client.clientId]?.grantId) return false;
  // sid e' opzionale nei nostri ID token; auth_time lega il caso ordinario
  // al login corrente. Se sid e' presente, deve combaciare anch'esso.
  if (typeof hint.auth_time !== 'number' || hint.auth_time !== session.loginTs) return false;
  return hint.sid === undefined || (typeof hint.sid === 'string' && hint.sid === session.sidFor(client.clientId));
}

function page(title: string, content: string, autoSubmit = false): string {
  return `<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · Engine Accounts</title><link rel="stylesheet" href="/static/app.css">
${autoSubmit ? '<script src="/static/logout.js" defer></script>' : ''}</head>
<body class="layout-narrow logout-page"><header class="top"><a class="brand" href="/">Engine Accounts</a></header>
<main><h1>${title}</h1>${content}</main></body></html>`;
}

/** Mantiene intatti action e xsrf generati dalla libreria: il POST resta suo. */
export function logoutSource(ctx: KoaContextWithOIDC, form: string): void {
  allowLogoutRedirect(ctx);
  const autoSubmit = canAutoSubmit(ctx);
  ctx.type = 'html';
  ctx.body = page(autoSubmit ? 'Uscita in corso' : 'Vuoi uscire?', `
<p class="lede">${autoSubmit ? 'Stiamo chiudendo la tua sessione in sicurezza.' : 'La sessione di Engine Accounts verrà chiusa su questo browser.'}</p>
${form}
<button id="logout-confirm" type="submit" form="op.logoutForm" name="logout" value="yes">${autoSubmit ? 'Continua' : 'Esci'}</button>
${autoSubmit ? '<noscript><p>Seleziona Continua per completare l’uscita.</p></noscript>' : '<p><a href="/">Resta connesso</a></p>'}`, autoSubmit);
}

export function postLogoutSuccessSource(ctx: KoaContextWithOIDC): void {
  ctx.type = 'html';
  ctx.body = page('Sei uscito', '<p class="lede">La richiesta di uscita è stata completata.</p><p><a href="/ui/login">Torna all’accesso</a></p>');
}
