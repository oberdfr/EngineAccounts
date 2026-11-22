import { esc, layout } from '../ui/layout.js';

/**
 * Pagine del Device Authorization Grant (RFC 8628), in italiano e con il
 * layout/CSP delle altre pagine IdP: nessuno script o stile inline, CSS da
 * `/static`. Il token anti-CSRF e' lo `xsrf` della libreria (legato alla
 * sessione del provider): lo passiamo come campo nascosto `xsrf`.
 *
 * La pagina di conferma mostra il dispositivo (nome del client) e il codice:
 * chi conferma deve poterlo confrontare con quello sulla TV.
 */

interface DeviceCtx {
  type: string;
  body: unknown;
  set(name: string, value: string): void;
  oidc: {
    session?: { state?: { secret?: string } };
    urlFor(name: string): string;
    client?: { clientName?: string; clientId: string };
  };
}

function action(ctx: DeviceCtx): string {
  try { return new URL(ctx.oidc.urlFor('code_verification'), 'http://x').pathname; } catch { return '/device'; }
}

function send(ctx: DeviceCtx, html: string): void {
  ctx.type = 'text/html; charset=utf-8';
  ctx.set('Cache-Control', 'no-store');
  ctx.body = html;
}

function xsrf(ctx: DeviceCtx): string {
  return esc(ctx.oidc.session?.state?.secret ?? '');
}

const MESSAGES: Record<string, string> = {
  NotFoundError: 'Il codice inserito non è corretto. Controlla il codice sullo schermo e riprova.',
  NoCodeError: 'Inserisci il codice mostrato sulla TV.',
  ExpiredError: 'Il codice è scaduto. Torna sulla TV per ottenerne uno nuovo.',
  AlreadyUsedError: 'Questo codice è già stato utilizzato. Torna sulla TV per ottenerne uno nuovo.',
  AbortedError: 'Richiesta annullata. Nessun accesso è stato concesso.',
};

export function userCodeInputPage(ctx: DeviceCtx, err?: { name?: string }, prefill = ''): void {
  const message = err ? (MESSAGES[err.name ?? ''] ?? 'Impossibile elaborare la richiesta. Riprova.') : '';
  const aborted = err?.name === 'AbortedError';
  send(ctx, layout({
    title: 'Collega un dispositivo',
    body: `<h1>Collega un dispositivo</h1>
<p class="lede">Inserisci il codice mostrato sulla tua TV per accedere con il tuo account Engine.</p>
${message ? `<p class="flash ${aborted ? 'flash-info' : 'flash-error'}" role="${aborted ? 'status' : 'alert'}">${esc(message)}</p>` : ''}
${aborted ? '' : `<form class="stack" method="post" action="${esc(action(ctx))}" novalidate>
  <input type="hidden" name="xsrf" value="${xsrf(ctx)}">
  <div class="field">
    <label for="f-user_code">Codice del dispositivo</label>
    <input id="f-user_code" name="user_code" type="text" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" maxlength="12" placeholder="ABCD-EFGH"${prefill ? ` value="${esc(prefill.slice(0, 12))}"` : ''} required autofocus>
    <p class="hint">Otto lettere, con o senza trattino.</p>
  </div>
  <button type="submit" class="primary">Continua</button>
</form>`}`,
  }));
}

export function deviceRateLimitedPage(ctx: DeviceCtx): void {
  send(ctx, layout({
    title: 'Troppi tentativi',
    body: `<h1>Troppi tentativi</h1>
<p class="lede">Hai inserito troppi codici in poco tempo. Attendi qualche minuto e riprova.</p>`,
  }));
}

export function userCodeConfirmPage(ctx: DeviceCtx, userCode: string, deviceName: string): void {
  send(ctx, layout({
    title: 'Conferma il dispositivo',
    body: `<h1>Conferma il dispositivo</h1>
<p class="lede">Stai per dare accesso al tuo account Engine a <strong>${esc(deviceName)}</strong>.</p>
<p>Il codice mostrato sulla TV deve essere:</p>
<p class="device-code"><code>${esc(userCode)}</code></p>
<p class="hint">Se non hai avviato tu questa operazione o il codice non coincide, premi Annulla.</p>
<form class="stack" method="post" action="${esc(action(ctx))}">
  <input type="hidden" name="xsrf" value="${xsrf(ctx)}">
  <input type="hidden" name="user_code" value="${esc(userCode)}">
  <div class="row">
    <button type="submit" name="confirm" value="yes" class="primary" autofocus>Conferma</button>
    <button type="submit" name="abort" value="yes" class="secondary">Annulla</button>
  </div>
</form>`,
  }));
}

export function deviceSuccessPage(ctx: DeviceCtx): void {
  const name = ctx.oidc.client?.clientName ?? ctx.oidc.client?.clientId ?? 'il dispositivo';
  send(ctx, layout({
    title: 'Dispositivo collegato',
    body: `<h1>Dispositivo collegato</h1>
<p class="lede"><strong>${esc(name)}</strong> è ora collegato al tuo account. Puoi chiudere questa pagina e tornare alla TV.</p>`,
  }));
}
