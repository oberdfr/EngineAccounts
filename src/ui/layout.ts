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
  admin?: boolean;
  /** Server-authorized service administration destinations; never inferred from identity text. */
  adminDestinations?: { href: string; label: string }[];
  /** Exact request pathname when available; older callers use the title fallback. */
  currentPath?: string;
  body: string;
}

function flashHtml(flash: Flash | undefined): string {
  if (!flash) return '';
  const role = flash.kind === 'error' ? 'alert' : 'status';
  return `<p class="flash flash-${esc(flash.kind)}" role="${role}">${esc(flash.text)}</p>`;
}

// Original small line icons, decorative only. Every destination retains its label.
const ICON_PATHS: Record<string, string> = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  profile: '<circle cx="12" cy="8" r="3.5"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
  security: '<path d="m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  sessions: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  apps: '<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M8 12h8m-4-4v8"/>',
  services: '<path d="M9 7H6a4 4 0 0 0 0 8h3m6-8h3a4 4 0 0 1 0 8h-3M8 11h8"/>',
  activity: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  export: '<path d="M12 3v12m-4-4 4 4 4-4M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
  admin: '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="9" cy="18" r="2"/>',
  logout: '<path d="M9 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h4m5-12 4 4-4 4m-5-4h9"/>',
};
function icon(name: string): string {
  return `<svg class="nav-icon" aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICON_PATHS[name] ?? ICON_PATHS.overview}</svg>`;
}

const ACCOUNT_LINKS = [
  ['/account', 'Panoramica', 'overview'], ['/account/profile', 'Profilo', 'profile'],
  ['/account/security', 'Sicurezza', 'security'], ['/account/sessions', 'Sessioni', 'sessions'],
  ['/account/apps', 'App collegate', 'apps'], ['/account/services', 'Servizi', 'services'],
  ['/account/activity', 'Attività', 'activity'], ['/account/export', 'I tuoi dati', 'export'],
] as const;

function isCurrent(url: string, path: string): boolean {
  return path === url || (url !== '/account' && url !== '/admin' && path.startsWith(`${url}/`));
}
function accountLinks(currentPath: string): string {
  return ACCOUNT_LINKS.map(([url, label, glyph]) => `<a href="${url}"${isCurrent(url, currentPath) ? ' aria-current="page"' : ''}>${icon(glyph)}<span>${label}</span></a>`).join('');
}

/** Complete native mobile navigation; also available to existing callers. */
export function nav(userEmail: string | null | undefined, csrf: string | undefined, _admin = false, currentPath = ''): string {
  if (!userEmail) return `<nav class="nav" aria-label="Accesso"><a href="/ui/login"${currentPath === '/ui/login' ? ' aria-current="page"' : ''}>Accedi</a><a href="/ui/register"${currentPath === '/ui/register' ? ' aria-current="page"' : ''}>Crea account</a></nav>`;
  return `<nav class="nav" aria-label="Account">${accountLinks(currentPath)}<div class="nav-identity"><span class="nav-user">${esc(userEmail)}</span><form method="post" action="/account/logout" class="inline">${csrfInput(csrf)}<button type="submit" class="link">${icon('logout')}Esci</button></form></div></nav>`;
}

const chevron = '<svg class="ui-select-chevron" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>';

function areaNavigation(options: LayoutOptions, currentPath: string): string {
  const destinations = options.admin ? [{ href: '/admin', label: 'Admin' }] : (options.adminDestinations ?? [])
    .filter(({ href }) => /^\/admin(?:\/|\?|$)/.test(href) && !/[\s\\]/.test(href))
    .map(({ href, label }) => ({ href, label: `Admin · ${label}` }));
  const choices = [{ href: '/account', label: 'Account' }, ...destinations];
  const selected = currentPath === '/admin' || currentPath.startsWith('/admin/')
    ? [...destinations].sort((a, b) => b.href.length - a.href.length)
      .find(({ href }) => { const path = href.split('?')[0]!; return currentPath === path || currentPath.startsWith(`${path}/`); })
      ?? destinations[0] ?? choices[0]!
    : choices[0]!;
  const adminDestination = selected.href !== '/account' ? selected : destinations[0];
  return `<nav class="area-navigation" aria-label="Area"><a href="/account"${selected.href === '/account' ? ' aria-current="page"' : ''}>Account</a>${adminDestination ? `<a href="${esc(adminDestination.href)}"${selected.href !== '/account' ? ' aria-current="page"' : ''}>Admin</a>` : ''}</nav>`;
}

function titlePath(title: string): string {
  const paths: Record<string, string> = {
    Account: '/account', 'Il tuo account': '/account', Panoramica: '/account', Profilo: '/account/profile',
    Sicurezza: '/account/security', Sessioni: '/account/sessions', 'App collegate': '/account/apps',
    Servizi: '/account/services', 'Servizi collegati': '/account/services', Attivita: '/account/activity', 'Attività': '/account/activity',
    'Esporta i tuoi dati': '/account/export', 'I tuoi dati': '/account/export', 'Elimina account': '/account/delete',
    'Attiva TOTP': '/account/security/totp/setup', 'Codici di recupero': '/account/security/recovery-codes',
    'Registra una passkey': '/account/security/webauthn/register', 'Amministrazione Engine': '/admin',
    'Amministrazione': '/admin', 'Account Engine': '/admin/accounts', 'Dettaglio account': '/admin/accounts',
    'Impostazioni identità': '/admin/settings', 'Registro amministrativo': '/admin/audit', Diagnostica: '/admin/diagnostics',
    Accedi: '/ui/login', 'Crea account': '/ui/register',
  };
  return paths[title] ?? '';
}

export function layout(options: LayoutOptions): string {
  const { title, width = 'narrow', flash, userEmail, body, csrf } = options;
  const adminShell = body.includes('class="admin-shell"');
  const accountShell = Boolean(userEmail && width === 'wide' && !adminShell);
  const currentPath = (options.currentPath ?? titlePath(title)).split('?')[0] ?? '';
  const sidebar = accountShell ? `<aside class="account-rail"><p class="sidebar-label">Il tuo spazio</p><nav class="sidebar account-sidebar" aria-label="Pannello account">${accountLinks(currentPath)}</nav><div class="sidebar-note">${icon('security')}<p>Un’identità.<br>Tutta la suite Engine.</p></div></aside>` : '';
  const logout = `<form method="post" action="/account/logout" class="inline">${csrfInput(csrf)}<button type="submit" class="link">${icon('logout')}Esci dall’account</button></form>`;
  const desktopNav = userEmail
    ? `${areaNavigation(options, currentPath)}<details class="identity-menu" data-identity-menu><summary aria-label="Menu profilo: ${esc(userEmail)}"><span class="avatar" aria-hidden="true">${esc(userEmail.slice(0, 1).toUpperCase())}</span><span class="identity-email">${esc(userEmail)}</span>${chevron}</summary><div class="identity-dropdown"><p class="muted">Account Engine</p><p class="identity-address">${esc(userEmail)}</p><a href="/account/profile">${icon('profile')}<span>Gestisci il profilo</span></a>${logout}</div></details>`
    : `<nav class="header-switch" aria-label="Accesso"><a href="/ui/login"${currentPath === '/ui/login' ? ' aria-current="page"' : ''}>Accedi</a><a href="/ui/register"${currentPath === '/ui/register' ? ' aria-current="page"' : ''}>Crea account</a></nav>`;
  const breadcrumb = width === 'wide' ? `<nav class="breadcrumbs" aria-label="Percorso"><a href="${adminShell ? '/admin' : '/account'}">${adminShell ? 'Amministrazione' : 'Account'}</a><span aria-hidden="true">/</span><span aria-current="page">${esc(title)}</span></nav>` : '';
  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Engine Accounts</title>
<link rel="stylesheet" href="/static/app.css?v=20261012-ui4">
<link rel="stylesheet" href="/static/header-controls.css?v=20261012-ui4">
<link rel="stylesheet" href="/static/select-controls.css?v=20261012-ui4">
</head>
<body class="layout-${width}${adminShell ? ' layout-admin' : ''}">
<a class="skip-link" href="#main">Salta al contenuto</a>
<header class="top">
  <a class="brand" href="${userEmail ? '/account' : '/'}" aria-label="Engine Accounts"><svg class="brand-mark" aria-hidden="true" width="32" height="32" viewBox="0 0 32 32" fill="none"><path d="M7 7h18M7 16h14M7 25h18M7 7v18" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/><path d="m23 13 3 3-3 3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span class="brand-name">Engine<span class="brand-product">Accounts</span></span></a>
  <div class="desktop-nav${userEmail ? ' header-controls' : ''}">${desktopNav}</div>
  <details class="mobile-nav"><summary>${icon('overview')}<span>Menu</span></summary>${nav(userEmail, csrf, options.admin, currentPath)}</details>
</header>
<main id="main" tabindex="-1">
${accountShell ? `<div class="account-shell">${sidebar}<div class="account-content">${breadcrumb}${flashHtml(flash)}${body}</div></div>` : `${breadcrumb}${flashHtml(flash)}${width === 'narrow' ? `<div class="auth-panel">${body}</div>` : body}`}
</main>
<footer class="foot"><p><strong>Engine</strong><span>Identità e accessi, in un unico spazio.</span></p><label class="motion-preference" hidden><input type="checkbox" data-animation-preference> Animazioni<span class="sr-only"> su questo browser, disattivate per impostazione predefinita</span></label></footer>
<script src="/static/preferences.js?v=20261012-ui4" defer></script>
<script src="/static/app.js?v=20261012-ui4" defer></script>
<script src="/static/header-controls.js?v=20261012-ui4" defer></script>
<script src="/static/select-controls.js?v=20261012-ui4" defer></script>
</body>
</html>`;
}

export function field(options: {
  id?: string;
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
  error?: string;
  inputmode?: string;
  autofocus?: boolean;
}): string {
  const id = options.id ?? `f-${options.name}`;
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
    options.hint || options.error ? `aria-describedby="${[options.hint ? `${esc(id)}-hint` : '', options.error ? `${esc(id)}-error` : ''].filter(Boolean).join(' ')}"` : '',
    options.error ? 'aria-invalid="true"' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `<div class="field">
  <label for="${esc(id)}">${esc(options.label)}</label>
  <input ${attrs}${options.value ? ` value="${esc(options.value)}"` : ''}>
    ${options.hint ? `<p class="hint" id="${esc(id)}-hint">${esc(options.hint)}</p>` : ''}
    ${options.error ? `<p class="errors" id="${esc(id)}-error">${esc(options.error)}</p>` : ''}
</div>`;
}

export function csrfInput(csrf: string | undefined): string {
  return `<input type="hidden" name="_csrf" value="${esc(csrf ?? '')}">`;
}

export function errorList(errors: string[]): string {
  if (!errors.length) return '';
  return `<ul class="errors">${errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>`;
}
