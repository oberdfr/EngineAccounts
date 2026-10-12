import type { Flash } from './layout.js';
import { csrfInput, errorList, esc, field, layout } from './layout.js';
import type { ConsentRecord, SessionRecord, WebauthnCredential } from '../domain/types.js';
import { presentSessions, type PresentedSession, type SessionOverview } from '../services/session-manager.js';
type AdminDestination = { href: string; label: string };

/**
 * Pagine di `/ui/*` (login, registrazione, verifica, reset, challenge MFA,
 * consenso). Server-side rendering puro: nessun framework, nessun bundle.
 * Il comportamento (conferma distruttiva, autofill, copie negli input) e' in
 * `app.js`, caricato dallo stesso origin.
 */

export function loginPage(options: {
  csrf: string;
  clientName?: string;
  errors?: string[];
  email?: string;
  flash?: Flash;
  passwordOnly?: boolean;
}): string {
  return layout({
    title: 'Accedi',
    csrf: options.csrf,
    flash: options.flash,
    body: `<p class="eyebrow">IDENTITÀ ENGINE</p><h1>Bentornato.</h1><p class="lede">Accedi per gestire il tuo account e i servizi della suite.</p>
${
  options.clientName
    ? `<p class="lede">Stai accedendo con <strong>${esc(options.clientName)}</strong>.</p>`
    : ''
}
${errorList(options.errors ?? [])}
<form method="post" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'email', label: 'Email', type: 'email', autocomplete: 'username', required: true, value: options.email, autofocus: true })}
  ${field({ name: 'password', label: 'Password', type: 'password', autocomplete: 'current-password', required: true })}
  <button type="submit" class="primary">Accedi</button>
</form>
<div class="links">
  ${options.clientName ? '' : '<a class="button secondary" href="/ui/passkey">Accedi con una passkey</a>'}
  <a href="/ui/forgot-password">Password dimenticata?</a>
  <a href="/ui/register">Crea un account</a>
  ${options.passwordOnly ? '' : '<a href="/ui/magic-code">Accedi con un codice</a>'}
</div>`,
  });
}

export function registerPage(options: { csrf: string; errors?: string[]; email?: string; flash?: Flash }): string {
  return layout({
    title: 'Crea account',
    csrf: options.csrf,
    flash: options.flash,
    body: `<p class="eyebrow">ENTRA NELLA SUITE</p><h1>Crea un account</h1><p class="lede">Un’unica identità per i tuoi servizi Engine.</p>
${errorList(options.errors ?? [])}
<form method="post" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'email', label: 'Email', type: 'email', autocomplete: 'username', required: true, value: options.email, autofocus: true })}
  ${field({ name: 'displayName', label: 'Nome visualizzato (facoltativo)', autocomplete: 'name' })}
  ${field({
    name: 'password',
    label: 'Password',
    type: 'password',
    autocomplete: 'new-password',
    required: true,
    minlength: 12,
    hint: 'Minimo 12 caratteri. Una passphrase lunga e\' piu\' sicura di una corta con i simboli.',
  })}
  <button type="submit" class="primary">Crea account</button>
</form>
<p class="hint">Riceverai un email di conferma. L\'account resta inutilizzabile finche\' non confermi.</p>
<div class="links"><a href="/ui/login">Ho gia\' un account</a></div>`,
  });
}

export function forgotPasswordPage(options: { csrf: string; errors?: string[]; flash?: Flash }): string {
  return layout({
    title: 'Password dimenticata',
    csrf: options.csrf,
    flash: options.flash,
    body: `<p class="eyebrow">RECUPERA L’ACCESSO</p><h1>Password dimenticata?</h1><p class="lede">Inserisci l’email del tuo account. Se può ricevere il recupero, ti invieremo un link per scegliere una nuova password.</p>
${errorList(options.errors ?? [])}
<form method="post" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'email', label: 'Email', type: 'email', autocomplete: 'username', required: true, autofocus: true })}
  <button type="submit" class="primary">Inviami il link</button>
</form>
<div class="links"><a href="/ui/login">Torna all\'accesso</a></div>`,
  });
}

export function resetPasswordPage(options: { csrf: string; token: string; errors?: string[] }): string {
  return layout({
    title: 'Nuova password',
    csrf: options.csrf,
    body: `<h1>Scegli una nuova password</h1>
${errorList(options.errors ?? [])}
<form method="post" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  <input type="hidden" name="token" value="${esc(options.token)}">
  ${field({ name: 'password', label: 'Nuova password', type: 'password', autocomplete: 'new-password', required: true, minlength: 12, autofocus: true })}
  ${field({ name: 'confirm', label: 'Conferma la password', type: 'password', autocomplete: 'new-password', required: true })}
  <button type="submit" class="primary">Salva la password</button>
</form>
<p class="hint">Il link vale pochi minuti e si usa una volta sola.</p>`,
  });
}

export function magicCodeRequestPage(options: { csrf: string; flash?: Flash }): string {
  return layout({
    title: 'Codice di accesso',
    csrf: options.csrf,
    flash: options.flash,
    body: `<h1>Accedi con un codice</h1>
<p class="lede">Ti spediamo un codice di 6 cifre via email.</p>
<form method="post" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'email', label: 'Email', type: 'email', autocomplete: 'username', required: true, autofocus: true })}
  <button type="submit" class="primary">Invia il codice</button>
</form>
<div class="links"><a href="/ui/login">Accesa con la password</a></div>`,
  });
}

export function magicCodeVerifyPage(options: {
  csrf: string;
  email: string;
  errors?: string[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Codice di accesso',
    csrf: options.csrf,
    flash: options.flash,
    body: `<h1>Inserisci il codice</h1>
<p class="lede">Codice inviato a <strong>${esc(options.email)}</strong>.</p>
${errorList(options.errors ?? [])}
<form method="post" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({
    name: 'code',
    label: 'Codice',
    inputmode: 'numeric',
    autocomplete: 'one-time-code',
    required: true,
    pattern: '[0-9]{6}',
    autofocus: true,
  })}
  <button type="submit" class="primary">Accedi</button>
</form>
<div class="links"><a href="/ui/login">Accesa con la password</a></div>`,
  });
}

export function verifyEmailPage(options: { flash?: Flash }): string {
  return layout({
    title: 'Email',
    body: options.flash
      ? `<h1>${esc(options.flash.kind === 'ok' ? 'Indirizzo confermato' : 'Link non valido')}</h1>`
      : `<h1>Verifica in corso…</h1>
<form method="post" class="stack">
  <button type="submit" class="primary">Continua</button>
</form>`,
    flash: options.flash,
  });
}

/* -------------------------------------------------------------------------- */
/* interazione OIDC                                                            */
/* -------------------------------------------------------------------------- */

export function interactionLoginPage(options: {
  csrf: string;
  uid: string;
  clientName: string;
  errors?: string[];
  email?: string;
  mfaRequired?: boolean;
}): string {
  return layout({
    title: 'Accesso richiesto',
    csrf: options.csrf,
    body: `<h1>Accedi per continuare</h1>
<p class="lede"><strong>${esc(options.clientName)}</strong> chiede di accedere al tuo account.</p>
${errorList(options.errors ?? [])}
<form method="post" action="/ui/interaction/${esc(options.uid)}/login" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'email', label: 'Email', type: 'email', autocomplete: 'username', required: true, value: options.email, autofocus: true })}
  ${field({ name: 'password', label: 'Password', type: 'password', autocomplete: 'current-password', required: true })}
  <input type="hidden" name="mfaRequired" value="${options.mfaRequired ? '1' : ''}">
  <button type="submit" class="primary">Continua</button>
</form>
<div class="links"><a href="/ui/register">Crea un account</a></div>`,
  });
}

export function interactionMfaPage(options: {
  csrf: string;
  uid: string;
  method: 'totp' | 'webauthn' | 'recovery';
  errors?: string[];
  /** Endpoint JSON che espone le options WebAuthn (nessuno script inline). */
  webauthnOptionsUrl?: string;
}): string {
  const label =
    options.method === 'totp'
      ? 'Codice dall\'app di autenticazione'
      : options.method === 'recovery'
        ? 'Codice di recupero'
        : 'Passkey';
  const input =
    options.method === 'webauthn'
      ? `<div data-webauthn="auth" data-webauthn-options="${esc(options.webauthnOptionsUrl ?? '')}">
  <p id="wa-status" class="hint">Appoggia il sensore o usa il PIN del dispositivo.</p>
</div>
<input type="hidden" name="webauthnResponse" value="">`
      : field({
          name: 'code',
          label,
          inputmode: options.method === 'totp' ? 'numeric' : 'text',
          autocomplete: 'one-time-code',
          required: true,
          autofocus: true,
        });
  return layout({
    title: 'Verifica in due passaggi',
    csrf: options.csrf,
    body: `<h1>Verifica in due passaggi</h1>
${errorList(options.errors ?? [])}
<form method="post" action="/ui/interaction/${esc(options.uid)}/mfa" class="stack" id="mfa-form">
  ${csrfInput(options.csrf)}
  <input type="hidden" name="method" value="${esc(options.method)}">
  ${input}
  <button type="submit" class="primary">Verifica</button>
</form>
<div class="links">
  <a href="/ui/interaction/${esc(options.uid)}/mfa?method=totp">Usa il codice TOTP</a>
  <a href="/ui/interaction/${esc(options.uid)}/mfa?method=recovery">Usa un codice di recupero</a>
</div>`,
  });
}

export function consentPage(options: {
  csrf: string;
  uid: string;
  clientName: string;
  scopes: { value: string; description: string }[];
  accountName: string;
}): string {
  return layout({
    title: 'Autorizza',
    csrf: options.csrf,
    body: `<h1>Autorizza l\'accesso</h1>
<p class="lede"><strong>${esc(options.clientName)}</strong> chiede di accedere come <strong>${esc(options.accountName)}</strong>.</p>
<ul class="scopes">
${options.scopes
  .map(
    (s) => `<li><code>${esc(s.value)}</code><span>${esc(s.description)}</span></li>`,
  )
  .join('\n')}
</ul>
<form method="post" action="/ui/interaction/${esc(options.uid)}/consent" class="stack">
  ${csrfInput(options.csrf)}
  <div class="row">
    <button type="submit" name="decision" value="allow" class="primary">Consenti</button>
    <button type="submit" name="decision" value="deny" class="secondary">Rifiuta</button>
  </div>
</form>`,
  });
}

/* -------------------------------------------------------------------------- */
/* pannello account                                                            */
/* -------------------------------------------------------------------------- */

export function accountHomePage(options: {
  csrf: string;
  email: string;
  displayName: string | null;
  emailVerified: boolean;
  createdAt: Date;
  sessions: number;
  consents: number;
  hasTotp: boolean;
  passkeys: number;
  recoveryLeft: number;
  lastActivity?: Date | null;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  serviceRoles?: { serviceId: string; name: string; admin: boolean }[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Il tuo account',
    adminDestinations: options.adminDestinations,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    admin: options.isGlobalAdmin,
    flash: options.flash,
    body: `<header class="page-header"><p class="eyebrow">ENGINE · IL TUO SPAZIO</p><h1>Benvenuto${options.displayName ? `, ${esc(options.displayName)}` : ''}.</h1><p class="lede">Tutto ciò che riguarda il tuo account, senza perdere di vista la sicurezza.</p></header>
<section class="panel account-overview"><div><div class="identity-heading"><h2>${esc(options.displayName ?? 'Il tuo profilo')}</h2><span class="badge ${options.emailVerified ? 'success' : 'warning'}">${options.emailVerified ? 'Email verificata' : 'Verifica email richiesta'}</span></div><p>${esc(options.email)}</p></div><a class="button secondary" href="/account/profile">Visualizza il profilo completo</a></section>
<section class="cards dashboard-grid" aria-label="Panoramica account">
  <article class="card"><h2>Sicurezza</h2>
    <p class="muted">Secondo fattore</p>
    <p>${options.hasTotp ? 'TOTP attivo' : '<strong>TOTP non attivo</strong>'}</p>
    <p class="muted">Passkey</p><p>${options.passkeys} registrati</p>
    <p class="muted">Codici recupero inutilizzati</p><p>${options.recoveryLeft}</p>
    <p><a class="button secondary" href="/account/security">Gestisci sicurezza</a></p>
  </article>
  <article class="card"><h2>Sessioni</h2>
    <p class="muted">Sessioni di accesso attive</p><p class="stat-value numeric">${options.sessions}</p>
    <p><a class="button secondary" href="/account/sessions">Controlla gli accessi</a></p>
  </article>
  <article class="card"><h2>App collegate</h2>
    <p class="muted">Autorizzazioni attive</p><p class="stat-value numeric">${options.consents}</p><p class="hint">Gestisci i permessi concessi alle applicazioni che usano il tuo account.</p>
    <p><a class="button secondary" href="/account/apps">Controlla i permessi</a></p>
  </article>
</section>
${options.isGlobalAdmin ? '<section class="panel"><p class="eyebrow">AMMINISTRAZIONE</p><h2>Gestisci Engine</h2><p>Il tuo account è un amministratore.</p><p>Gestisci account, ruoli, servizi e attività della suite.</p><a class="button primary" href="/admin">Apri Amministrazione</a></section>' : ''}
<section class="panel">
  <h2>Il controllo dei tuoi dati</h2><p>Scarica una copia dei dati del tuo account o consulta il registro degli accessi.</p>
  <div class="row">
    <a class="button secondary" href="/account/export">Esporta i tuoi dati</a>
    <a class="button secondary" href="/account/activity">Consulta attività</a>
  </div>
</section>`,
  });
}

export function accountProfilePage(options: {
  csrf: string;
  email: string;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  displayName: string | null;
  emailVerified: boolean;
  account?: { id: string; status: string; createdAt: Date; updatedAt: Date; lastLoginAt: Date | null; emailVerifiedAt: Date | null; mustChangePassword?: boolean; isGlobalAdmin?: boolean; totpEnabled?: boolean; failedLogins?: number; lockedUntil?: Date | null; blockedReason?: string | null };
  serviceRoles?: { serviceId: string; name: string; admin: boolean }[];
  errors?: string[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Profilo',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<header class="page-header"><p class="eyebrow">IDENTITÀ</p><h1>Il tuo profilo</h1><p class="lede">I dettagli del tuo account Engine e il modo in cui ti presenti nei servizi.</p></header>
${errorList(options.errors ?? [])}
${options.account ? `<section class="panel"><div class="section-header"><h2>Dettagli account</h2><span class="badge">${esc(options.account.status === 'active' ? 'Attivo' : options.account.status)}</span></div><dl class="detail-grid">
<div><dt>Identificatore account</dt><dd><code>${esc(options.account.id)}</code></dd></div>
<div><dt>Email</dt><dd>${esc(options.email)}</dd></div><div><dt>Nome visualizzato</dt><dd>${esc(options.displayName ?? 'Non impostato')}</dd></div>
<div><dt>Verifica email</dt><dd>${options.emailVerified ? 'Verificata' : 'Non verificata'}${options.account.emailVerifiedAt ? ` · ${esc(options.account.emailVerifiedAt.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC` : ''}</dd></div>
<div><dt>Creato il</dt><dd>${esc(options.account.createdAt.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC</dd></div>
<div><dt>Ultima modifica</dt><dd>${esc(options.account.updatedAt.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC</dd></div>
<div><dt>Ultimo accesso</dt><dd>${options.account.lastLoginAt ? `${esc(options.account.lastLoginAt.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC` : 'Non disponibile'}</dd></div>
<div><dt>Ruolo Engine</dt><dd>${options.account.isGlobalAdmin ? 'Amministratore globale' : 'Utente'}</dd></div><div><dt>Aggiornamento password richiesto</dt><dd>${options.account.mustChangePassword ? 'Sì' : 'No'}</dd></div><div><dt>Autenticazione TOTP</dt><dd>${options.account.totpEnabled ? 'Attiva' : 'Non attiva'}</dd></div><div><dt>Tentativi di accesso falliti consecutivi</dt><dd>${options.account.failedLogins ?? 'Non disponibile'}</dd></div><div><dt>Blocco temporaneo</dt><dd>${options.account.lockedUntil && options.account.lockedUntil.getTime() > Date.now() ? `${esc(options.account.lockedUntil.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC` : 'Nessuno'}</dd></div>${options.account.blockedReason ? `<div><dt>Motivo del blocco</dt><dd>${esc(options.account.blockedReason)}</dd></div>` : ''}</dl><p class="hint">Per sicurezza non mostriamo hash della password, token o segreti di autenticazione.</p>
</section>` : ''}
<section class="split">
  <form method="post" action="/account/profile/name" class="stack panel">
    <h2>Nome visualizzato</h2>
    ${csrfInput(options.csrf)}
    ${field({ name: 'displayName', label: 'Nome', autocomplete: 'name', value: options.displayName ?? '' })}
    <button type="submit" class="primary">Salva</button>
  </form>
   <div class="stack panel">
    <h2>Email</h2>
    <p><strong>${esc(options.email)}</strong> ${options.emailVerified ? '' : '<strong>(non verificata)</strong>'}</p>
    <form method="post" action="/account/profile/email" class="stack">
      ${csrfInput(options.csrf)}
      ${field({ name: 'newEmail', label: 'Nuovo indirizzo', type: 'email', autocomplete: 'email', required: true })}
      <button type="submit" class="primary">Cambia email</button>
    </form>
    <p class="hint">Il link di conferma viene inviato al nuovo indirizzo: l\'attuale resta attivo fino allora.</p>
  </div>
</section><section class="panel"><h2>Privacy e dati</h2><p>Puoi scaricare i tuoi dati o chiudere l’account. La cancellazione è definitiva e richiede una conferma esplicita.</p><div class="row"><a class="button secondary" href="/account/export">Esporta dati</a><a class="button danger" href="/account/delete">Elimina account</a></div></section>`,
  });
}

export function accountSecurityPage(options: {
  csrf: string;
  email: string;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  hasTotp: boolean;
  totpConfirmed: boolean;
  passkeys: (WebauthnCredential & { label: string })[];
  recoveryLeft: number;
  errors?: string[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Sicurezza',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<header class="page-header"><p class="eyebrow">PROTEZIONE ACCOUNT</p><h1>La tua sicurezza</h1><p class="lede">Password, autenticazione a due fattori e recupero: scegli come proteggere il tuo accesso.</p></header>
${errorList(options.errors ?? [])}
<section class="panel security-summary"><div class="section-header"><h2>Secondo fattore</h2><span class="badge ${options.hasTotp || options.passkeys.length ? 'success' : 'warning'}">${options.hasTotp || options.passkeys.length ? 'Configurato' : 'Da configurare'}</span></div><p>${options.hasTotp || options.passkeys.length ? 'Hai configurato un metodo aggiuntivo per proteggere il login.' : 'Attiva TOTP o una passkey per aggiungere una protezione al tuo account.'} L’accesso ai pannelli amministrativi richiede sempre un secondo fattore.</p><div class="row"><a class="button secondary" href="#totp">Codice TOTP</a><a class="button secondary" href="#passkeys">Passkey</a><a class="button secondary" href="#recovery">Recupero</a></div></section>
<section class="split">
  <div class="stack panel">
    <h2>Password</h2>
    <p class="muted">Il cambio richiede la password attuale.</p>
    <form method="post" action="/account/security/password" class="stack" novalidate>
      ${csrfInput(options.csrf)}
      ${field({ name: 'currentPassword', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
      ${field({ name: 'newPassword', label: 'Nuova password', type: 'password', autocomplete: 'new-password', required: true, minlength: 12 })}
      ${field({ name: 'confirm', label: 'Conferma la nuova password', type: 'password', autocomplete: 'new-password', required: true })}
      <button type="submit" class="primary">Cambia password</button>
    </form>
  </div>
  <div class="stack panel totp-panel" id="totp">
    <div class="section-header"><h2>App di autenticazione</h2><span class="badge ${options.hasTotp && options.totpConfirmed ? 'success' : 'neutral'}">${options.hasTotp && options.totpConfirmed ? 'Attiva' : 'Non attiva'}</span></div>
    <p class="muted">Un codice temporaneo generato dalla tua app per confermare l’accesso.</p>
    ${
      options.hasTotp && options.totpConfirmed
        ? `<div class="totp-state"><strong>Il tuo account è protetto con TOTP.</strong><p>Apri la tua app di autenticazione quando ti viene richiesto il codice a sei cifre.</p></div>
    <details class="totp-manage"><summary>Disattiva l’app di autenticazione</summary><p class="hint">Rimuoverai questo metodo di verifica. Conferma con la password attuale.</p>
    <form class="stack" method="post" action="/account/security/totp/disable">
      ${csrfInput(options.csrf)}
      ${field({ id: 'totp-disable-password', name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
      <div class="row"><button type="submit" class="danger">Disattiva TOTP</button></div>
    </form></details>`
        : `<p>Aggiungi il tuo account con un QR e conferma il primo codice. Puoi usare qualsiasi app compatibile con TOTP.</p>
    <p><a class="button primary" href="/account/security/totp/setup">Attiva TOTP</a></p>`
    }
  </div>
</section>
<section class="stack panel" id="passkeys">
  <h2>Passkey (WebAuthn)</h2>
  <p class="muted">Usa impronta, volto, PIN o una chiave di sicurezza. I dati biometrici restano sul dispositivo; Engine conserva solo la credenziale pubblica.</p>
  ${
    options.passkeys.length
      ? `<ul class="list">
${options.passkeys
  .map(
     (p) => `<li><div><strong>${esc(p.label)}</strong><br><span class="muted">${esc(p.deviceType)}${p.backedUp ? ' · backup disponibile' : ''} · registrata ${esc(p.createdAt.toISOString().slice(0, 10))}</span><details><summary>Dettagli della credenziale</summary><p class="hint">Identificatore <code>${esc(p.credentialId)}</code></p><p class="hint">Trasporti: ${esc(p.transports?.join(', ') || 'Non indicati')}</p></details></div>
  <form method="post" action="/account/security/webauthn/delete" class="inline">
    ${csrfInput(options.csrf)}
    <input type="hidden" name="credentialId" value="${esc(p.credentialId)}">
    <button type="submit" class="secondary small">Rimuovi</button>
  </form></li>`,
  )
  .join('\n')}
</ul>`
      : '<p>Nessuna passkey registrata.</p>'
  }
  <p><a class="button secondary" href="/account/security/webauthn/register">Registra una passkey</a></p>
</section>
<section class="stack panel" id="recovery">
  <h2>Codici di recupero</h2>
  <p>Codici monouso per entrare se perdi l'app di autenticazione. <strong>${options.recoveryLeft}</strong> ancora disponibili.</p>
  <form method="post" action="/account/security/recovery-codes" class="stack">
    ${csrfInput(options.csrf)}
    ${field({ id: 'recovery-password', name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
    <button type="submit" class="secondary">Genera nuovi codici</button>
  </form>
</section>`,
  });
}

export function totpSetupPage(options: { csrf: string; email: string; isGlobalAdmin?: boolean; adminDestinations?: AdminDestination[]; secret: string; uri: string; qrSvg?: string; invalid?: boolean }): string {
  return layout({
    title: 'Attiva TOTP',
    admin: options.isGlobalAdmin,
    adminDestinations: options.adminDestinations,
    csrf: options.csrf,
    userEmail: options.email,
    body: `<header class="page-header"><p class="eyebrow">SECONDO FATTORE · TOTP</p><h1>Proteggi il tuo accesso.</h1><p class="lede">Collega un’app di autenticazione. Ogni accesso richiederà un codice temporaneo.</p></header>
${options.invalid ? '<p class="flash bad" role="alert">Codice non valido. Usa il codice più recente e controlla l’orologio del telefono. Questa chiave resta valida durante la configurazione.</p>' : ''}
<section class="panel"><h2>1. Scansiona il QR</h2><p>Apri la tua app di autenticazione e aggiungi un account scansionando questo codice.</p>
${options.qrSvg ? `<div class="totp-qr" role="img" aria-label="Codice QR per configurare TOTP">${options.qrSvg}</div>` : ''}
<details><summary>Non puoi scansionare? Usa la chiave manuale</summary><p>Seleziona una chiave TOTP basata sul tempo (6 cifre, 30 secondi) e inserisci questa chiave:</p><p class="key"><code>${esc(options.secret)}</code></p><p class="hint">Non condividere la chiave o il QR: permettono di generare i codici del tuo account.</p><p class="hint">URI di configurazione: <code>${esc(options.uri)}</code></p></details></section>
<section class="panel"><h2>2. Conferma il codice</h2><p>TOTP sarà attivo soltanto dopo la conferma di un codice generato dall’app.</p>
<form method="post" action="/account/security/totp/confirm" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'code', label: 'Codice a 6 cifre mostrato dall\'app', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, pattern: '[0-9]{6}', autofocus: true })}
  <button type="submit" class="primary">Conferma e attiva</button>
</form>
<p class="hint">Se il codice non e\' accettato, controlla che l\'orologio del telefono sia sincronizzato.</p></section><p><a class="button secondary" href="/account/security">Torna alla sicurezza</a></p>`,
  });
}

export function recoveryCodesPage(options: { csrf: string; email: string; isGlobalAdmin?: boolean; adminDestinations?: AdminDestination[]; codes: string[] }): string {
  return layout({
    title: 'Codici di recupero',
    admin: options.isGlobalAdmin,
    adminDestinations: options.adminDestinations,
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Codici di recupero</h1>
<p class="warning"><strong>Compariranno una volta sola.</strong> Copiali e conservali fuori dal browser: ogni codice vale per un solo accesso.</p>
<ul class="codes">${options.codes.map((c) => `<li><code>${esc(c)}</code></li>`).join('')}</ul>
<p><a class="button primary" href="/account/security">Ho conservato i codici</a></p>`,
  });
}

export function accountSessionsPage(options: {
  csrf: string;
  email: string;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  sessions: PresentedSession[] | (SessionRecord & { current: boolean })[];
  sessionOverview?: SessionOverview;
  flash?: Flash;
}): string {
  const overview = options.sessionOverview ?? presentSessions(options.sessions as SessionRecord[], options.sessions.find(s => s.current)?.id ?? '');
  const timestamp = (date: Date) => `${esc(date.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC`;
  const sessionRow = (s: PresentedSession) => `<li class="session-row${s.current ? ' current' : ''}"><div><strong>${esc(s.label)}</strong> <span class="badge ${s.current ? 'success' : ''}">${s.current ? 'Questo accesso' : s.status === 'active' ? 'Attiva' : s.status === 'expired' ? 'Scaduta' : 'Revocata'}</span><p class="hint">Ultimo utilizzo ${timestamp(s.lastSeenAt)}</p><details><summary>Dettagli di questa sessione</summary><dl class="detail-grid"><div><dt>Identificatore</dt><dd><code>${esc(s.id)}</code></dd></div><div><dt>Accesso iniziale</dt><dd>${timestamp(s.createdAt)}</dd></div><div><dt>Scadenza</dt><dd>${timestamp(s.expiresAt)}</dd></div><div><dt>IP registrato</dt><dd>${esc(s.ip ?? 'Non disponibile')}</dd></div><div><dt>Metodo di accesso</dt><dd>${esc(s.amr.map(m => ({ pwd: 'Password', otp: 'Codice TOTP', webauthn: 'Passkey', recovery: 'Codice di recupero' })[m] ?? m).join(' · ') || 'Non disponibile')}</dd></div>${s.revokedAt ? `<div><dt>Revocata il</dt><dd>${timestamp(s.revokedAt)}</dd></div><div><dt>Motivo</dt><dd>${esc(s.revokeReason ?? 'Non disponibile')}</dd></div>` : ''}</dl></details></div>${s.status === 'active' ? `<form method="post" action="/account/sessions/revoke" class="inline" data-confirm="${s.current ? 'Vuoi uscire da questo accesso?' : 'Vuoi revocare questo accesso? Anche gli accessi OIDC collegati possono essere chiusi.'}">${csrfInput(options.csrf)}<input type="hidden" name="sessionId" value="${esc(s.id)}"><button type="submit" class="secondary">${s.current ? 'Esci da qui' : 'Revoca accesso'}</button></form>` : ''}</li>`;
  return layout({
    title: 'Sessioni',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<header class="page-header"><p class="eyebrow">ACCESSI ACCOUNT</p><h1>Le tue sessioni</h1><p class="lede">Riconosci i tuoi accessi e chiudi quelli che non ti servono più.</p></header>
<section class="panel session-summary"><h2>Sessioni, non dispositivi</h2><p>Il conteggio indica accessi, non dispositivi. I gruppi browser/sistema sono indicativi.</p><div class="cards stats-grid"><div><strong class="stat-value numeric">${overview.counts.active}</strong><p>Accessi attivi</p></div><div><strong class="stat-value numeric">${overview.counts.browserGroups}</strong><p>Gruppi browser</p></div><div><strong class="stat-value numeric">${overview.counts.expired + overview.counts.revoked}</strong><p>Non più attivi</p></div></div><details><summary>Perché ci sono più sessioni dei dispositivi?</summary><p>Una sessione è un accesso autenticato. Login ripetuti e autorizzazioni SSO possono creare più sessioni nello stesso browser. I gruppi qui sotto descrivono browser e sistema operativo: non identificano in modo certo dispositivi fisici.</p><p class="hint">L’IP è quello registrato all’accesso: può cambiare con rete mobile, VPN o proxy. Non indica una posizione geografica verificata.</p></details></section>
${
  overview.groups.length
    ? `<ul class="list">
${overview.groups.map(g => `<li class="session-group"><section><div class="section-header"><h2>${esc(g.label)}</h2><span class="badge">${g.activeCount} ${g.activeCount === 1 ? 'accesso attivo' : 'accessi attivi'}</span></div><ul class="list">${g.sessions.map(sessionRow).join('')}</ul></section></li>`).join('')}
</ul>`
    : '<p>Nessuna sessione attiva.</p>'
}
<section class="panel"><h2>Non riconosci un accesso?</h2><p>Chiudi le altre sessioni e aggiorna la password nella pagina Sicurezza. L’accesso che stai usando viene conservato.</p><form method="post" action="/account/sessions/revoke-all" class="stack" data-confirm="Chiudere tutte le altre sessioni conservando quella corrente?">
  ${csrfInput(options.csrf)}
  <button type="submit" class="danger">Chiudi tutte le altre sessioni</button>
</form></section>${overview.history.length ? `<details class="panel"><summary>Cronologia · ${overview.history.length} sessioni scadute o revocate</summary><p class="hint">Questi accessi non sono più attivi. Mantenerli nel registro non significa che qualcuno possa usarli.</p><ul class="list">${overview.history.map(sessionRow).join('')}</ul></details>` : ''}`,
  });
}

export function accountAppsPage(options: {
  csrf: string;
  email: string;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  consents: (ConsentRecord & { clientName: string })[];
  flash?: Flash;
}): string {
  return layout({
    title: 'App collegate',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<header class="page-header"><p class="eyebrow">AUTORIZZAZIONI</p><h1>Applicazioni collegate</h1><p class="lede">Controlla quali applicazioni possono usare il tuo account e quali permessi hai concesso.</p></header>
<p class="hint">Revoca il consenso per rimuovere l’autorizzazione. Per chiudere gli accessi già aperti, controlla anche la pagina Sessioni.</p>
${
  options.consents.length
    ? `<ul class="list">
${options.consents
  .map(
    (c) => `<li>
  <div><strong>${esc(c.clientName)}</strong><br><span class="muted">${esc(c.scope.join(' · '))}</span>
  <br><span class="muted">Concesso ${esc(c.grantedAt.toISOString().slice(0, 10))}</span></div>
  <form method="post" action="/account/apps/revoke" class="inline">
    ${csrfInput(options.csrf)}
    <input type="hidden" name="clientId" value="${esc(c.clientId)}">
    <button type="submit" class="secondary small">Revoca</button>
  </form>
</li>`,
  )
  .join('\n')}
</ul>`
    : '<p>Nessuna app collegata.</p>'
}`,
  });
}

function activityLabel(event: string): string {
  const names: Record<string, string> = {
    'account.login': 'Accesso account', 'login.success': 'Accesso riuscito', 'account.logout': 'Uscita account',
    'account.password.changed': 'Password aggiornata', 'account.email.changed': 'Email aggiornata',
    'account.totp.enabled': 'TOTP attivato', 'account.totp.disabled': 'TOTP disattivato',
    'register.created': 'Account creato', 'email_verify.success': 'Email verificata', 'email_verify.failed': 'Verifica email non riuscita',
    'login.bad_password': 'Password non corretta', 'login.blocked_account': 'Accesso a un account bloccato',
    'password_reset.requested': 'Richiesto recupero password', 'password_reset.success': 'Password reimpostata',
    'password_change.success': 'Password aggiornata', 'password_change.rejected_reauth': 'Verifica password non riuscita',
    'password_change.rejected_policy': 'Nuova password non valida', 'email_change.requested': 'Richiesta modifica email',
    'email_change.success': 'Email aggiornata', 'magic_code.requested': 'Codice di accesso richiesto',
    'account_delete.success': 'Account eliminato', 'data_export.requested': 'Dati account esportati',
    'admin.account.delete': 'Cancellazione amministrativa', 'admin.global_role': 'Modifica ruolo globale',
  };
  return names[event] ?? 'Evento account';
}

export function accountActivityPage(options: {
  csrf: string;
  email: string;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  entries: {
    at: Date;
    event: string;
    outcome: string;
    ip: string | null;
    metadata: Record<string, unknown>;
  }[];
  total: number;
}): string {
  return layout({
    title: 'Attivita',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Attivita recente</h1>
<p class="lede">Eventi di sicurezza registrati sul tuo account. Il registro e\' append-only: non puo\' essere modificato, ne' dall\'amministratore.</p>
${
  options.entries.length
    ? `<div class="table-scroll" role="region" aria-label="Attività recente" tabindex="0"><table class="table">
<thead><tr><th>Quando</th><th>Evento</th><th>Esito</th><th>IP</th></tr></thead>
<tbody>
${options.entries
  .map(
    (e) =>
      `<tr><td>${esc(e.at.toLocaleString('it-IT', { timeZone: 'UTC' }))} UTC</td><td>${esc(activityLabel(e.event))}<br><code class="hint">${esc(e.event)}</code></td><td><span class="badge">${esc(e.outcome === 'success' ? 'Completato' : e.outcome === 'denied' ? 'Negato' : e.outcome === 'failure' ? 'Non riuscito' : e.outcome)}</span></td><td>${esc(e.ip ?? 'Non disponibile')}</td></tr>`,
  )
  .join('\n')}
</tbody>
</table></div>
<p class="hint">${options.total} eventi registrati in totale.</p>`
    : '<p>Nessun evento registrato.</p>'
}`,
  });
}

export function accountExportPage(options: { csrf: string; email: string; isGlobalAdmin?: boolean; adminDestinations?: AdminDestination[]; downloadUrl: string }): string {
  return layout({
    title: 'Esporta i tuoi dati',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Esporta i tuoi dati</h1>
<p class="lede">Un file JSON con profilo, sessioni, app collegate, passkey (senza le chiavi pubbliche) e registro attivita\'.</p>
<p class="hint">Il file contiene dati personali: scaricalo e conservalo come si deve.</p>
<ul class="list"><li>Profilo e informazioni account</li><li>Sessioni e applicazioni autorizzate</li><li>Metadati delle passkey e attività registrate</li></ul><p class="hint">L’esportazione non contiene password, segreti TOTP, token o chiavi private.</p><div class="export-actions"><a class="button primary" href="${esc(options.downloadUrl)}" download="engine-accounts-export.json">Scarica il JSON</a></div>`,
  });
}

export function webauthnRegisterPage(options: {
  csrf: string;
  email: string;
  isGlobalAdmin?: boolean;
  adminDestinations?: AdminDestination[];
  optionsJson: string;
}): string {
  return layout({
    title: 'Registra una passkey',
    admin: options.isGlobalAdmin,
    adminDestinations: options.adminDestinations,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Registra una passkey</h1>
<p class="lede">La passkey ti permette di accedere con impronta, volto o PIN del dispositivo.</p>
<form method="post" action="/account/security/webauthn/verify" class="stack" data-webauthn="register" data-webauthn-verify="1">
  ${csrfInput(options.csrf)}
  <input type="hidden" name="webauthnResponse" value="">
  ${field({ name: 'nickname', label: 'Nome della passkey (facoltativo)', maxlength: 64, hint: 'Per riconoscerla in seguito, ad esempio “Laptop personale” o “Telefono”.' })}
  <p id="wa-status" class="hint">Premi il pulsante e segui le istruzioni del dispositivo.</p>
  <button type="submit" class="primary">Registra la passkey</button>
</form>
<script type="application/json" id="wa-options">${options.optionsJson.replace(/</g, '\\u003c')}</script>
<noscript><p class="warning">Per registrare una passkey devi abilitare JavaScript. Puoi invece configurare TOTP senza JavaScript.</p></noscript>
<p><a class="button secondary" href="/account/security">Torna alla sicurezza</a></p>
<p class="hint">Questa pagina usa WebAuthn: nessun dato lascia il tuo dispositivo senza la tua conferma.</p>`,
  });
}

export function accountDeletedPage(options: { email: string; eventsSent: number }): string {
  return layout({
    title: 'Account eliminato',
    body: `<h1>Account eliminato</h1>
<p class="lede">L'account <strong>${esc(options.email)}</strong> e' stato eliminato: profilo, sessioni, app collegate e secondo fattore non esistono piu'.</p>
${
  options.eventsSent > 0
    ? `<p>Le app collegate sono state avvisate (${options.eventsSent}). La rimozione dei dati nei servizi viene gestita dai servizi stessi: l’avviso non certifica che sia già completata.</p>`
    : '<p>Nessuna app collegata da avvisare.</p>'
}
<p><a href="/ui/login">Torna all\'accesso</a></p>`,
  });
}

export const accountDeletedStaticPage = accountDeletedPage({ email: '', eventsSent: 0 });

export const csrfErrorPage =
  '<!doctype html><html lang="it"><head><meta charset="utf-8"><title>Richiesta non valida</title>' +
  '<link rel="stylesheet" href="/static/app.css"></head><body class="layout-narrow">' +
  '<header class="top"><a class="brand" href="/">Engine Accounts</a></header><main>' +
  '<h1>Richiesta non valida</h1><p class="lede">Token di sicurezza mancante o scaduto: ricarica la pagina e riprova.</p>' +
  '<p><a href="/account">Torna all\'account</a></p></main></body></html>';

export function accountDeletePage(options: { csrf: string; email: string; isGlobalAdmin?: boolean; adminDestinations?: AdminDestination[]; errors?: string[]; flash?: Flash }): string {
  return layout({
    title: 'Elimina account',
    adminDestinations: options.adminDestinations,
    admin: options.isGlobalAdmin,
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>Elimina l\'account</h1>
${errorList(options.errors ?? [])}
<div class="warning">
  <p><strong>Questa azione non e\' reversibile.</strong> Verranno rimossi: accesso, sessioni, app collegate, secondo fattore, consensi. Le app collegate ricevono una notifica di cancellazione.</p>
</div>
<form method="post" action="/account/delete" class="stack" novalidate data-confirm="Eliminare definitivamente il tuo account e tutti i suoi accessi?">
  ${csrfInput(options.csrf)}
  ${field({ name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true, autofocus: true })}
  ${field({ name: 'confirm', label: 'Scrivi ELIMINA per confermare', required: true, autocomplete: 'off' })}
  <button type="submit" class="danger">Elimina definitivamente</button>
</form>
<p><a href="/account">Annulla</a></p>`,
  });
}

/** Shared service links: navigation follows ordinary SSO, never an admin token. */
export function accountServicesPage(options: {
  csrf: string; email: string; admin?: boolean;
  services: { id: string; name: string; enabled: boolean; linked?: boolean; adminUrl?: string | null }[];
}): string {
  return layout({ title: 'Servizi', width: 'wide', userEmail: options.email, csrf: options.csrf, admin: options.admin,
    body: `<h1>Servizi collegati</h1><p class="lede">I servizi gestiscono i propri dati e le proprie impostazioni. L’accesso usa il normale SSO.</p>
    <ul class="list">${options.services.map(s => `<li><div><strong>${esc(s.name)}</strong><p class="muted">${s.enabled ? 'Disponibile' : 'Disabilitato'} · ${s.linked ? 'Collegato' : 'Non collegato'}</p></div>${s.enabled && safeExternalUrl(s.adminUrl) ? `<a class="button secondary" href="${esc(s.adminUrl)}">Apri ${esc(s.name)}</a>` : ''}</li>`).join('')}</ul>${options.services.length ? '' : '<p>Nessun servizio disponibile.</p>'}` });
}

export function safeExternalUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password; } catch { return false; }
}

export function forcePasswordPage(options: { csrf: string; email: string; errors?: string[] }): string {
  return layout({ title: 'Aggiorna la password', csrf: options.csrf, userEmail: options.email,
    body: `<h1>Aggiorna la password</h1><p class="lede">Prima di continuare devi scegliere una nuova password.</p>${errorList(options.errors ?? [])}
    <form method="post" action="/account/force-password" class="stack">${csrfInput(options.csrf)}
    ${field({ name: 'currentPassword', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
    ${field({ name: 'newPassword', label: 'Nuova password', type: 'password', autocomplete: 'new-password', minlength: 12, required: true })}
    ${field({ name: 'confirm', label: 'Conferma nuova password', type: 'password', autocomplete: 'new-password', required: true })}
    <button class="primary" type="submit">Aggiorna password</button></form>` });
}
