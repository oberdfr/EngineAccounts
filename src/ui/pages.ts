import type { Flash } from './layout.js';
import { csrfInput, errorList, esc, field, layout } from './layout.js';
import type { ConsentRecord, SessionRecord, WebauthnCredential } from '../domain/types.js';

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
    body: `<h1>Accedi</h1>
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
    body: `<h1>Crea un account</h1>
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
    body: `<h1>Password dimenticata</h1>
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
  flash?: Flash;
}): string {
  return layout({
    title: 'Il tuo account',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>Il tuo account</h1>
<section class="cards">
  <article class="card"><h2>Profilo</h2>
    <p class="muted">Email</p><p><strong>${esc(options.email)}</strong></p>
    <p class="muted">Nome</p><p>${esc(options.displayName ?? '—')}</p>
    <p class="muted">Stato</p><p>${options.emailVerified ? 'Email verificata' : '<strong>Email non verificata</strong>'}</p>
    <p class="muted">Creato</p><p>${esc(options.createdAt.toISOString().slice(0, 10))}</p>
    <p><a href="/account/profile">Modifica profilo</a></p>
  </article>
  <article class="card"><h2>Sicurezza</h2>
    <p class="muted">Secondo fattore</p>
    <p>${options.hasTotp ? 'TOTP attivo' : '<strong>TOTP non attivo</strong>'}</p>
    <p class="muted">Passkey</p><p>${options.passkeys} registrati</p>
    <p class="muted">Codici recupero inutilizzati</p><p>${options.recoveryLeft}</p>
    <p><a href="/account/security">Gestisci sicurezza</a></p>
  </article>
  <article class="card"><h2>Sessioni</h2>
    <p class="muted">Dispositivi attivi</p><p>${options.sessions}</p>
    <p><a href="/account/sessions">Sessioni e dispositivi</a></p>
  </article>
  <article class="card"><h2>App collegate</h2>
    <p class="muted">Consensi attivi</p><p>${options.consents}</p>
    <p><a href="/account/apps">App collegate</a></p>
  </article>
</section>
<section class="zone-danger">
  <h2>I tuoi dati</h2>
  <div class="row">
    <a class="button secondary" href="/account/export">Esporta i tuoi dati</a>
    <a class="button danger" href="/account/delete">Elimina l\'account</a>
  </div>
</section>`,
  });
}

export function accountProfilePage(options: {
  csrf: string;
  email: string;
  displayName: string | null;
  emailVerified: boolean;
  errors?: string[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Profilo',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>Profilo</h1>
${errorList(options.errors ?? [])}
<section class="split">
  <form method="post" action="/account/profile/name" class="stack">
    <h2>Nome visualizzato</h2>
    ${csrfInput(options.csrf)}
    ${field({ name: 'displayName', label: 'Nome', autocomplete: 'name', value: options.displayName ?? '' })}
    <button type="submit" class="primary">Salva</button>
  </form>
  <div class="stack">
    <h2>Email</h2>
    <p><strong>${esc(options.email)}</strong> ${options.emailVerified ? '' : '<strong>(non verificata)</strong>'}</p>
    <form method="post" action="/account/profile/email" class="stack">
      ${csrfInput(options.csrf)}
      ${field({ name: 'newEmail', label: 'Nuovo indirizzo', type: 'email', autocomplete: 'email', required: true })}
      <button type="submit" class="primary">Cambia email</button>
    </form>
    <p class="hint">Il link di conferma viene inviato al nuovo indirizzo: l\'attuale resta attivo fino allora.</p>
  </div>
</section>`,
  });
}

export function accountSecurityPage(options: {
  csrf: string;
  email: string;
  hasTotp: boolean;
  totpConfirmed: boolean;
  passkeys: (WebauthnCredential & { label: string })[];
  recoveryLeft: number;
  errors?: string[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Sicurezza',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>Sicurezza</h1>
${errorList(options.errors ?? [])}
<section class="split">
  <div class="stack">
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
  <div class="stack">
    <h2>Codice di accesso (TOTP)</h2>
    ${
      options.hasTotp && options.totpConfirmed
        ? `<p>Stato: <strong>attivo</strong>.</p>
    <form method="post" action="/account/security/totp/disable">
      ${csrfInput(options.csrf)}
      ${field({ name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
      <button type="submit" class="secondary">Disattiva</button>
    </form>`
        : `<p>Stato: <strong>non attivo</strong>.</p>
    <p><a class="button primary" href="/account/security/totp/setup">Attiva TOTP</a></p>`
    }
  </div>
</section>
<section class="stack">
  <h2>Passkey (WebAuthn)</h2>
  ${
    options.passkeys.length
      ? `<ul class="list">
${options.passkeys
  .map(
    (p) => `<li><div><strong>${esc(p.label)}</strong><br><span class="muted">${esc(p.deviceType)}${p.backedUp ? ' · sincronizzata' : ''} · registrata ${esc(p.createdAt.toISOString().slice(0, 10))}</span></div>
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
<section class="stack">
  <h2>Codici di recupero</h2>
  <p>Codici monouso per entrare se perdi l'app di autenticazione. <strong>${options.recoveryLeft}</strong> ancora disponibili.</p>
  <form method="post" action="/account/security/recovery-codes" class="stack">
    ${csrfInput(options.csrf)}
    ${field({ name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}
    <button type="submit" class="secondary">Genera nuovi codici</button>
  </form>
</section>`,
  });
}

export function totpSetupPage(options: { csrf: string; email: string; secret: string; uri: string }): string {
  return layout({
    title: 'Attiva TOTP',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Attiva il codice di accesso</h1>
<ol class="steps">
  <li>Apri l'app di autenticazione sul telefono.</li>
  <li>Aggiungi un account di tipo "altro" e incolla questa chiave:</li>
</ol>
<p class="key"><code>${esc(options.secret)}</code></p>
<p class="hint">URI per l'app: <code>${esc(options.uri)}</code></p>
<form method="post" action="/account/security/totp/confirm" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'code', label: 'Codice a 6 cifre mostrato dall\'app', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, pattern: '[0-9]{6}', autofocus: true })}
  <button type="submit" class="primary">Conferma e attiva</button>
</form>
<p class="hint">Se il codice non e\' accettato, controlla che l\'orologio del telefono sia sincronizzato.</p>`,
  });
}

export function recoveryCodesPage(options: { csrf: string; email: string; codes: string[] }): string {
  return layout({
    title: 'Codici di recupero',
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
  sessions: (SessionRecord & { current: boolean })[];
  flash?: Flash;
}): string {
  return layout({
    title: 'Sessioni',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>Sessioni e dispositivi</h1>
<p class="lede">Chiudere una sessione revoca anche i token rilasciati da quel dispositivo.</p>
${
  options.sessions.length
    ? `<ul class="list">
${options.sessions
  .map(
    (s) => `<li${s.current ? ' class="current"' : ''}>
  <div>
    <strong>${esc(s.deviceLabel)}</strong>${s.current ? ' <span class="badge">questa</span>' : ''}
    <br><span class="muted">Acceduta ${esc(s.createdAt.toISOString().slice(0, 16).replace('T', ' '))} · ultimo uso ${esc(s.lastSeenAt.toISOString().slice(0, 16).replace('T', ' '))}</span>
    <br><span class="muted">Metodi: ${esc(s.amr.join(', ') || '—')}</span>
  </div>
  ${
    s.current
      ? ''
      : `<form method="post" action="/account/sessions/revoke" class="inline">
    ${csrfInput(options.csrf)}
    <input type="hidden" name="sessionId" value="${esc(s.id)}">
    <button type="submit" class="secondary small">Revoca</button>
  </form>`
  }
</li>`,
  )
  .join('\n')}
</ul>`
    : '<p>Nessuna sessione attiva.</p>'
}
<form method="post" action="/account/sessions/revoke-all" class="stack">
  ${csrfInput(options.csrf)}
  <button type="submit" class="danger">Chiudi tutte le altre sessioni</button>
</form>`,
  });
}

export function accountAppsPage(options: {
  csrf: string;
  email: string;
  consents: (ConsentRecord & { clientName: string })[];
  flash?: Flash;
}): string {
  return layout({
    title: 'App collegate',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>App collegate</h1>
<p class="lede">Revocare un consenso impedisce i nuovi accessi. Le sessioni gia' aperte restano valide finche' non scadono: revoca anche le sessioni se serve tagliar fuori.</p>
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

export function accountActivityPage(options: {
  csrf: string;
  email: string;
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
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Attivita recente</h1>
<p class="lede">Eventi di sicurezza registrati sul tuo account. Il registro e\' append-only: non puo\' essere modificato, ne' dall\'amministratore.</p>
${
  options.entries.length
    ? `<table class="table">
<thead><tr><th>Quando</th><th>Evento</th><th>Esito</th><th>IP</th></tr></thead>
<tbody>
${options.entries
  .map(
    (e) =>
      `<tr><td>${esc(e.at.toISOString().slice(0, 16).replace('T', ' '))}</td><td><code>${esc(e.event)}</code></td><td>${esc(e.outcome)}</td><td>${esc(e.ip ?? '—')}</td></tr>`,
  )
  .join('\n')}
</tbody>
</table>
<p class="hint">${options.total} eventi registrati in totale.</p>`
    : '<p>Nessun evento registrato.</p>'
}`,
  });
}

export function accountExportPage(options: { csrf: string; email: string; downloadUrl: string }): string {
  return layout({
    title: 'Esporta i tuoi dati',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Esporta i tuoi dati</h1>
<p class="lede">Un file JSON con profilo, sessioni, app collegate, passkey (senza le chiavi pubbliche) e registro attivita\'.</p>
<p class="hint">Il file contiene dati personali: scaricalo e conservalo come si deve.</p>
<p><a class="button primary" href="${esc(options.downloadUrl)}" download="engine-accounts-export.json">Scarica il JSON</a></p>`,
  });
}

export function webauthnRegisterPage(options: {
  csrf: string;
  email: string;
  optionsJson: string;
}): string {
  return layout({
    title: 'Registra una passkey',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    body: `<h1>Registra una passkey</h1>
<p class="lede">La passkey ti permette di accedere con impronta, volto o PIN del dispositivo.</p>
<form method="post" action="/account/security/webauthn/verify" class="stack" data-webauthn="register" data-webauthn-verify="1">
  ${csrfInput(options.csrf)}
  <input type="hidden" name="webauthnResponse" value="">
  <p id="wa-status" class="hint">Premi il pulsante e segui le istruzioni del dispositivo.</p>
  <button type="submit" class="primary">Registra la passkey</button>
</form>
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
    ? `<p>Le app collegate sono state avvisate (${options.eventsSent}). Se avevi dati salvati in una di queste, sono stati cancellati anche li.</p>`
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

export function accountDeletePage(options: { csrf: string; email: string; errors?: string[]; flash?: Flash }): string {
  return layout({
    title: 'Elimina account',
    width: 'wide',
    csrf: options.csrf,
    userEmail: options.email,
    flash: options.flash,
    body: `<h1>Elimina l\'account</h1>
${errorList(options.errors ?? [])}
<div class="warning">
  <p><strong>Questa azione non e\' reversibile.</strong> Verranno rimossi: accesso, sessioni, app collegate, secondo fattore, consensi. Le app collegate ricevono una notifica di cancellazione.</p>
</div>
<form method="post" action="/account/delete" class="stack" novalidate>
  ${csrfInput(options.csrf)}
  ${field({ name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true, autofocus: true })}
  ${field({ name: 'confirm', label: 'Scrivi ELIMINA per confermare', required: true, autocomplete: 'off' })}
  <button type="submit" class="danger">Elimina definitivamente</button>
</form>
<p><a href="/account">Annulla</a></p>`,
  });
}