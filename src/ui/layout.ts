/**
 * HTML e CSS delle pagine nostre.
 *
 * Vincoli, perche' la CSP non ammette `unsafe-inline`:
 *  - nessuno stile inline (`style="..."`) e nessuno `<script>` inline;
 *  - la classe CSS e il JS si servono da `/static/*`, stesso origin;
 *  - per il comportamento che normalmente si risolverebbe con JS inline
 *    (submit di un form a un endpoint diverso, conferma distruttiva) usiamo
 *    `<form>` puro e `formaction`: HTML, non script.
 *
 * Ogni interpolazione passa da `esc()`: nessun dato utente finisce nell'HTML
 * grezzo (XSSriflesso).
 */

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function esc(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

export interface Flash {
  kind: 'ok' | 'error' | 'info';
  text: string;
}

export interface LayoutOptions {
  title: string;
  /** `wide` per il pannello account, `narrow` per login/verifica. */
  width?: 'narrow' | 'wide';
  flash?: Flash | undefined;
  /** Token CSRF: presente solo dove ci sono form. */
  csrf?: string | undefined;
  userEmail?: string | null | undefined;
  body: string;
}

function flashHtml(flash: Flash | undefined): string {
  if (!flash) return '';
  const role = flash.kind === 'error' ? 'alert' : 'status';
  return `<p class="flash flash-${esc(flash.kind)}" role="${role}">${esc(flash.text)}</p>`;
}

/** Nav col logout solo se c'e' una sessione (l'utente e' noto). */
export function nav(userEmail: string | null | undefined, csrf: string | undefined): string {
  if (!userEmail) {
    return `<nav class="nav"><a href="/ui/login">Accedi</a></nav>`;
  }
  return `<nav class="nav">
  <a href="/account">Account</a>
  <a href="/account/security">Sicurezza</a>
  <a href="/account/sessions">Sessioni</a>
  <a href="/account/apps">App</a>
  <a href="/account/activity">Attivita</a>
  <span class="nav-user">${esc(userEmail)}</span>
  <form method="post" action="/account/logout" class="inline">
    ${csrfInput(csrf)}
    <button type="submit" class="link">Esci</button>
  </form>
</nav>`;
}

export function layout(options: LayoutOptions): string {
  const { title, width = 'narrow', flash, userEmail, body, csrf } = options;
  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Engine Accounts</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body class="layout-${width}">
<header class="top">
  <a class="brand" href="/">Engine Accounts</a>
  ${nav(userEmail, csrf)}
</header>
<main>
${flashHtml(flash)}
${body}
</main>
<footer class="foot"><p>Suite StreamingEngine · identity provider</p></footer>
<script src="/static/app.js" defer></script>
</body>
</html>`;
}

export function field(options: {
  name: string;
  label: string;
  type?: string;
  value?: string;
  autocomplete?: string;
  required?: boolean;
  minlength?: number;
  maxlength?: number;
  pattern?: string;
  hint?: string;
  inputmode?: string;
  autofocus?: boolean;
}): string {
  const id = `f-${options.name}`;
  const attrs = [
    `id="${esc(id)}"`,
    `name="${esc(options.name)}"`,
    `type="${esc(options.type ?? 'text')}"`,
    options.autocomplete ? `autocomplete="${esc(options.autocomplete)}"` : '',
    options.required ? 'required' : '',
    options.minlength !== undefined ? `minlength="${esc(options.minlength)}"` : '',
    options.maxlength !== undefined ? `maxlength="${esc(options.maxlength)}"` : '',
    options.pattern ? `pattern="${esc(options.pattern)}"` : '',
    options.inputmode ? `inputmode="${esc(options.inputmode)}"` : '',
    options.autofocus ? 'autofocus' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `<div class="field">
  <label for="${esc(id)}">${esc(options.label)}</label>
  <input ${attrs}${options.value ? ` value="${esc(options.value)}"` : ''}>
  ${options.hint ? `<p class="hint">${esc(options.hint)}</p>` : ''}
</div>`;
}

export function csrfInput(csrf: string | undefined): string {
  return `<input type="hidden" name="_csrf" value="${esc(csrf ?? '')}">`;
}

export function errorList(errors: string[]): string {
  if (!errors.length) return '';
  return `<ul class="errors">${errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>`;
}