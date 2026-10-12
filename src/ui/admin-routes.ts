import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import type { AccountsStore } from '../domain/ports.js';
import { sessionCookieName, type SessionManager } from '../services/session-manager.js';
import { csrfCookieName, issueCsrfToken, verifyCsrfToken } from '../security/csrf.js';
import { verifyPassword } from '../security/password.js';
import { csrfInput, esc, field, layout } from './layout.js';
import { safeExternalUrl } from './pages.js';

type Context = { ip: string | null; userAgent: string | null };
/** Structural boundary: persistence, policy and all audit writes belong to the service. */
export interface AdministrationUI {
  isGlobalAdmin(sub: string): Promise<boolean>;
  authorization(sub: string, serviceId: string): Promise<{ admin: boolean; global: boolean; status: string | null }>;
  listServices(): Promise<unknown>;
  findService(id: string): Promise<unknown>;
  assignments(id: string): Promise<unknown>;
  accounts(filters: { q?: string; status?: 'active' | 'blocked' | 'deleted'; mfa?: 'enabled' | 'disabled'; role?: 'global' | 'service' | 'none'; service?: string; page?: number; pageSize?: number }): Promise<unknown>;
  accountDetail(sub: string): Promise<unknown>;
  mutateAccount(actor: string, target: string, action: 'ban' | 'unban' | 'force-password' | 'revoke-sessions' | 'reset-mfa' | 'revoke-consent' | 'delete', options: { serviceId?: string; accountService?: AdminDeps['accounts']; reauth?: { password: string; totpCode?: string } }, context: Context): Promise<unknown>;
  setServiceEnabled(actor: string, serviceId: string, enabled: boolean, context: Context): Promise<unknown>;
  grant(actor: string, serviceId: string, target: string, context: Context): Promise<unknown>;
  revoke(actor: string, serviceId: string, target: string, context: Context): Promise<unknown>;
  setGlobalRole(actor: string, target: string, enabled: boolean, options: { context: Context }): Promise<unknown>;
  listAudit(filters: Record<string, string | number>): Promise<unknown>;
  getSettings(): Promise<unknown>;
  setSetting(actor: string, key: string, value: unknown, context: Context): Promise<unknown>;
  diagnostics(): Promise<unknown>;
}
export interface AdminDeps {
  config: Config;
  store: AccountsStore;
  accounts: {
    deleteAccountAsAdmin(actorSub: string, targetSub: string, reauth: { password: string }, context: Context): Promise<{ ok: boolean; message: string }>;
  };
  sessions: Pick<SessionManager, 'resolve'>;
  admin: AdministrationUI;
  purge(actorSub: string, sub: string, serviceId: string, context: Context): Promise<unknown>;
}

const record = (value: unknown): Record<string, unknown> => value && typeof value === 'object' ? value as Record<string, unknown> : {};
function rows(value: unknown): Record<string, unknown>[] {
  const r = record(value);
  const items = Array.isArray(value) ? value : r.items ?? r.accounts ?? r.entries ?? r.services;
  return Array.isArray(items) ? items.map(record) : [];
}
const idOf = (r: Record<string, unknown>) => String(r.id ?? r.sub ?? r.userId ?? r.serviceId ?? '');
const pathId = (value: unknown) => encodeURIComponent(String(value ?? ''));
const text = (value: unknown) => esc(value instanceof Date ? value.toISOString() : value);
const statusLabel = (value: unknown) => ({ active: 'Attivo', blocked: 'Bloccato', deleted: 'Eliminato', success: 'Riuscito', failure: 'Non riuscito', denied: 'Negato', available: 'Disponibile', unavailable: 'Non disponibile', disabled: 'Disabilitato' }[String(value)] ?? String(value ?? 'Non disponibile'));
const yesNo = (value: unknown) => value === undefined ? 'Non disponibile' : value ? 'Sì' : 'No';
const settingLabels: Record<string, [string, string]> = {
  EMAIL_VERIFICATION_REQUIRED: ['Verifica email obbligatoria', 'Richiede che l’utente confermi il proprio indirizzo email.'],
  TOTP_REQUIRED: ['TOTP obbligatorio', 'Richiede un’app di autenticazione per gli account.'],
  ADMIN_MFA_REQUIRED: ['MFA amministratori obbligatoria', 'Protezione sempre attiva per i privilegi amministrativi; non modificabile.'],
  REGISTRATION_MODE: ['Registrazione account', 'open: aperta; closed: chiusa; invite: solo su invito.'],
  PASSWORD_MIN_LENGTH: ['Lunghezza minima password', 'Numero minimo di caratteri, da 8 a 128, entro il massimo configurato.'],
  SESSION_TTL: ['Durata sessioni', 'Durata in secondi: da 300 a 31.536.000.'],
  CONSENT_TTL: ['Durata consensi', 'Durata in secondi: da 3.600 a 315.360.000.'],
  PASSWORD_RESET_TTL: ['Scadenza recupero password', 'Durata del link in secondi: da 60 a 86.400.'],
  EMAIL_VERIFICATION_TTL: ['Scadenza verifica email', 'Durata del link in secondi: da 60 a 86.400.'],
  EMAIL_CHANGE_TTL: ['Scadenza cambio email', 'Durata del link in secondi: da 60 a 86.400.'],
  MAGIC_CODE_TTL: ['Scadenza codice di accesso', 'Durata del codice in secondi: da 60 a 3.600.'],
};
function savedUrl(url: string): string {
  const parsed = new URL(url, 'http://internal');
  parsed.searchParams.set('notice', 'saved');
  return parsed.pathname + parsed.search;
}
function facts(items: [string, unknown][]): string {
  return `<dl class="facts">${items.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${text(value ?? 'Non disponibile')}</dd></div>`).join('')}</dl>`;
}
const actionHelp: Record<string, string> = {
  ban: 'Blocca nuovi accessi e revoca le sessioni e le autorizzazioni esistenti.',
  unban: 'Riattiva l’account e azzera il blocco temporaneo dei tentativi di accesso. Non ripristina sessioni revocate.',
  'force-password': 'Revoca gli accessi esistenti e richiede una nuova password prima di accedere di nuovo.',
  'revoke-sessions': 'Disconnette l’account e revoca le autorizzazioni di accesso ai servizi.',
  'reset-mfa': 'Rimuove TOTP, passkey e codici di recupero e revoca gli accessi. L’utente dovrà configurare nuovamente MFA.',
  'revoke-consent': 'Revoca il consenso e le autorizzazioni solo per questo servizio. Non elimina l’identità Engine.',
  purge: 'Richiede la cancellazione dei dati nel servizio selezionato. Non elimina l’account Engine; verifica l’esito nel registro.',
  delete: 'Elimina irreversibilmente l’identità Engine e i suoi accessi. I servizi ricevono l’evento di cancellazione.',
  'global-grant': 'Consente di amministrare tutte le identità e tutti i servizi della suite.',
  'global-revoke': 'Rimuove l’amministrazione globale. L’ultimo amministratore globale attivo è protetto.',
  'service-grant': 'Assegna privilegi limitati al servizio indicato, senza accesso alle impostazioni globali.',
  'service-revoke': 'Rimuove i privilegi amministrativi per il servizio indicato.',
  grant: 'Assegna a un altro account attivo il ruolo di amministratore di questo servizio.',
  revoke: 'Rimuove il ruolo di amministratore di questo servizio dall’account indicato.',
  disable: 'Disabilita il servizio nel registro delle identità. Non modifica le impostazioni applicative del servizio.',
  enable: 'Riabilita il servizio nel registro delle identità.',
  setting: 'Modifica solo questa impostazione di EngineAccounts. Le impostazioni dei servizi non cambiano.',
};
const eventLabels: Record<string, string> = {
  'admin.reauth': 'Verifica identità amministratore', 'admin.global_role.granted': 'Amministrazione globale assegnata',
  'admin.global_role.revoked': 'Amministrazione globale rimossa', 'admin.service_role.granted': 'Amministrazione servizio assegnata',
  'admin.service_role.revoked': 'Amministrazione servizio rimossa', 'admin.service.enabled': 'Servizio abilitato',
  'admin.service.disabled': 'Servizio disabilitato', 'admin.service.registered': 'Servizio registrato',
  'admin.service.data_purge': 'Cancellazione dati del servizio richiesta', 'admin.service.consent_revoked': 'Consenso servizio revocato',
  'admin.settings.updated': 'Impostazione identità aggiornata',
};
function auditEvent(value: unknown): string {
  const code = String(value ?? '');
  const action = code.startsWith('admin.account.') ? code.slice('admin.account.'.length) : '';
  const label = eventLabels[code] ?? ({ ban: 'Account bloccato', block: 'Account bloccato', unban: 'Account sbloccato', unblock: 'Account sbloccato', delete: 'Account eliminato', 'force-password': 'Cambio password richiesto', 'revoke-sessions': 'Sessioni revocate', 'reset-mfa': 'MFA reimpostata' }[action] ?? 'Evento di sicurezza');
  return `<strong>${esc(label)}</strong><br><code>${esc(code)}</code>`;
}
function auditTable(entries: Record<string, unknown>[]): string {
  return table('Registro eventi', ['Quando', 'Chi', 'Evento', 'Esito', 'Dettagli'], entries.map(e => [text(e.at), text(e.actor ?? 'Sistema'), auditEvent(e.event), esc(statusLabel(e.outcome)), `<details><summary>Mostra dettagli</summary>${facts([['Soggetto', e.subjectId ?? e.userId], ['Servizio', record(e.metadata).serviceId], ['Impostazione', record(e.metadata).setting], ['Indirizzo IP', e.ip], ['Dispositivo / browser', e.userAgent], ['ID evento', e.id]])}</details>`]));
}
function table(label: string, headers: string[], data: string[][]): string {
  if (!data.length) return `<div class="empty-state"><h3>${esc(label)}</h3><p>Nessun risultato disponibile. Se hai applicato filtri, prova a modificarli.</p></div>`;
  return `<div class="table-scroll" role="region" tabindex="0" aria-label="${esc(label)}"><table class="table"><caption>${esc(label)}</caption><thead><tr>${headers.map(h => `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead><tbody>${data.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function actionForm(csrf: string, url: string, action: string, label: string, extra = ''): string {
  const destructive = ['delete', 'purge', 'ban', 'revoke-sessions', 'reset-mfa', 'revoke-consent', 'disable'].includes(action);
  return `<details class="panel${destructive ? ' danger-zone' : ''}"><summary>${esc(label)}</summary><form class="stack" method="post" action="${esc(url)}">${csrfInput(csrf)}<input type="hidden" name="action" value="${esc(action)}"><p>${esc(actionHelp[action] ?? 'Operazione amministrativa registrata nel registro di audit.')}</p>${extra}<p class="muted">Controlla destinatario e ambito prima di confermare. È richiesta una verifica dell’identità negli ultimi cinque minuti.</p>${field({ id: `confirm-${Buffer.from(label + url).toString('base64url')}`, name: 'confirm', label: 'Scrivi CONFERMA per procedere', required: true, autocomplete: 'off' })}<button type="submit" class="${destructive ? 'danger' : 'secondary'}">${esc(label)}</button></form></details>`;
}

export async function registerAdminRoutes(app: FastifyInstance, deps: AdminDeps): Promise<void> {
  await app.register(async (scoped) => {
    scoped.setErrorHandler((error, _req, reply) => {
      const code = record(error).code;
      if (code === 'forbidden' || code === 'not_found') return reply.code(404).send({ error: 'Not found' });
       const message = code === 'last_active_global_admin' ? 'Non è possibile rimuovere l’ultimo amministratore globale attivo.' : code === 'invalid_input' || code === 'bootstrap_cli_only' ? 'Operazione non consentita o dati non validi. Controlla i campi e le autorizzazioni del destinatario.' : 'Operazione non riuscita. Controlla il registro prima di riprovare: alcuni passaggi potrebbero essere già stati eseguiti.';
       return reply.code(code === 'last_active_global_admin' ? 409 : code === 'invalid_input' || code === 'bootstrap_cli_only' ? 400 : 500).type('text/html; charset=utf-8').send(layout({ title: 'Intervento non completato', body: `<header class="page-header"><p class="eyebrow">Amministrazione Engine</p><h1>Intervento non completato</h1><p class="flash flash-error" role="alert">${esc(message)}</p></header><p>Torna alla pagina dell’intervento per controllare i dati. Non vengono eseguiti tentativi automatici.</p><a class="button secondary" href="/account">Torna al tuo account</a>` }));
    });
    await registerRoutes(scoped, deps);
  });
}

async function registerRoutes(app: FastifyInstance, deps: AdminDeps): Promise<void> {
  const { config, sessions, store, admin } = deps;
  // Only internal session IDs are retained, never cookie values or passwords.
  const recent = new Map<string, { sub: string; at: number }>();
  const attempts = new Map<string, { count: number; until: number }>();
  const postLimits = new Map<string, { count: number; until: number }>();
  const bound = (map: Map<string, unknown>) => { while (map.size > 10_000) map.delete(map.keys().next().value!); };
  const csrfCookie = csrfCookieName(config.cookiePrefix);
  const ctx = (req: FastifyRequest): Context => ({ ip: req.ip ?? null, userAgent: req.headers['user-agent'] ?? null });
  const body = (req: FastifyRequest) => record(req.body);
  function csrf(req: FastifyRequest, reply: FastifyReply): string {
    const existing = req.cookies[csrfCookie];
    if (existing && existing.length >= 32) return existing;
    const value = issueCsrfToken();
    reply.setCookie(csrfCookie, value, { httpOnly: true, secure: config.secureCookies, sameSite: 'lax', path: '/' });
    return value;
  }
  const notFound = (reply: FastifyReply) => reply.code(404).send({ error: 'Not found' });
  async function gate(req: FastifyRequest, reply: FastifyReply, serviceId?: string, reauth = true) {
    reply.header('Cache-Control', 'no-store');
    const active = await sessions.resolve(req.cookies[sessionCookieName(config)]);
    if (!active || active.user.status !== 'active') { notFound(reply); return; }
    const global = await admin.isGlobalAdmin(active.user.id);
    if (!global) {
      if (!serviceId) { notFound(reply); return; }
      const auth = await admin.authorization(active.user.id, serviceId);
      if (!auth.admin || auth.status !== 'active') { notFound(reply); return; }
    }
    if (active.user.mustChangePassword) {
      reply.code(403).type('text/html; charset=utf-8').send(layout({ title: 'Aggiorna la password', width: 'wide', userEmail: active.user.email, csrf: csrf(req, reply), body: '<header class="page-header"><p class="eyebrow">Accesso amministrativo</p><h1>Aggiorna la password</h1><p class="lede">Prima di usare i privilegi amministrativi devi completare il cambio password richiesto per il tuo account.</p></header><a class="button primary" href="/ui/force-password-change">Cambia password</a>' })); return;
    }
    // Authorization precedes every redirect, including reauthentication itself.
    if (!active.user.totpEnabled && !(await store.listWebauthnCredentials(active.user.id)).length) {
      reply.code(403).type('text/html; charset=utf-8').send(layout({ title: 'Proteggi l’accesso amministrativo', width: 'wide', userEmail: active.user.email, csrf: csrf(req, reply), body: '<header class="page-header"><p class="eyebrow">Accesso amministrativo · MFA richiesta</p><h1>Proteggi il tuo account</h1><p class="lede">Il ruolo amministrativo è assegnato, ma per usarlo devi attivare TOTP o una passkey. Una password da sola non è sufficiente.</p></header><section class="panel"><h2>Il prossimo passo</h2><p>Configura un secondo fattore nella pagina Sicurezza, poi torna qui e conferma la tua identità. Nessuna operazione amministrativa è stata eseguita.</p><a class="button primary" href="/account/security?admin=mfa-required">Configura MFA</a></section>' })); return;
    }
    // Enrollment alone does not upgrade a pre-existing password-only session.
    // Check actual authentication methods on every request, including reauth.
    if (!Array.isArray(active.session.amr) || !active.session.amr.some(method => ['otp', 'webauthn', 'recovery_code'].includes(method))) {
      reply.code(403).type('text/html; charset=utf-8').send(layout({ title: 'Completa secondo fattore', width: 'wide', userEmail: active.user.email, csrf: csrf(req, reply), body: '<header class="page-header"><p class="eyebrow">Accesso amministrativo · verifica MFA</p><h1>Completa secondo fattore</h1><p class="lede">Hai configurato MFA, ma questa sessione non ha verificato un secondo fattore. Confermare soltanto la password non abilita l’amministrazione.</p></header><section class="panel"><h2>Accedi di nuovo con MFA</h2><p>Completa un nuovo accesso con TOTP, passkey o un codice di recupero, poi torna al pannello amministrativo. Nessuna operazione amministrativa è stata eseguita.</p><a class="button primary" href="/ui/login">Accedi con secondo fattore</a></section>' })); return;
    }
    if (req.method === 'POST') {
      const now = Date.now();
      for (const [key, value] of postLimits) if (value.until <= now) postLimits.delete(key);
      const key = active.user.id;
      const limit = postLimits.get(key) ?? { count: 0, until: now + 60_000 };
      if (limit.count >= 30) { reply.code(429).header('Retry-After', String(Math.ceil((limit.until - now) / 1000))).send({ error: 'Riprova più tardi.' }); return; }
      limit.count++; postLimits.set(key, limit); bound(postLimits);
      if (!verifyCsrfToken(req.cookies[csrfCookie], body(req)._csrf)) { reply.code(403).send({ error: 'Invalid CSRF' }); return; }
    }
    const now = Date.now();
    for (const [key, value] of recent) if (now - value.at >= 300_000) recent.delete(key);
    for (const [key, value] of attempts) if (value.until <= now) attempts.delete(key);
    const verified = recent.get(active.session.id);
    if (reauth && (!verified || verified.sub !== active.user.id || now - verified.at >= 300_000)) {
      reply.redirect(serviceId ? `/admin/services/${pathId(serviceId)}/reauth` : '/admin/reauth', 303); return;
    }
    return { ...active, global };
  }
  function render(req: FastifyRequest, reply: FastifyReply, email: string, title: string, content: string, serviceId?: string) {
    const base = serviceId ? `/admin/services/${pathId(serviceId)}` : '/admin';
    const links = serviceId ? [[base, 'Servizio'], [`${base}/accounts`, 'Utenti collegati']] : [['/admin', 'Panoramica'], ['/admin/accounts', 'Account'], ['/admin/services', 'Servizi'], ['/admin/settings', 'Impostazioni'], ['/admin/audit', 'Audit'], ['/admin/diagnostics', 'Diagnostica']];
    const descriptions: Record<string, string> = {
      'Amministrazione Engine': 'Gestisci identità, accessi e integrazioni della suite. Scegli un’attività per iniziare.',
      'Account Engine': 'Trova un’identità, controlla sicurezza e accessi, oppure intervieni sulle autorizzazioni.',
      'Utenti del servizio': 'Solo account collegati a questo servizio. Il ruolo di servizio non consente di modificare l’identità globale.',
      'Dettaglio account': 'Controlla identità, protezioni e accessi prima di scegliere un intervento.',
      Servizi: 'Registro delle integrazioni SSO, dei client e della consegna eventi. Le impostazioni applicative restano nei servizi.',
      'Impostazioni identità': 'Regole di accesso e durata delle autorizzazioni EngineAccounts, non configurazione dei servizi.',
      'Registro amministrativo': 'Ricostruisci chi ha fatto cosa e con quale esito. Il registro è append-only: gli eventi non si modificano.',
      Diagnostica: 'Verifica i componenti dell’identità e la coda eventi. I riepiloghi non certificano la salute dei servizi consumer.',
      'Conferma la tua identità': 'Per accedere ai controlli amministrativi serve una verifica recente della password, valida cinque minuti per questa sessione.',
    };
    const current = req.url.split('?')[0];
    return reply.type('text/html; charset=utf-8').send(layout({ title, width: 'wide', csrf: csrf(req, reply), userEmail: email, admin: !serviceId, currentPath: current,
      adminDestinations: serviceId ? [{ href: base, label: serviceId }] : undefined,
      body: `<div class="admin-shell"><nav class="sidebar" aria-label="Amministrazione">${links.map(([url, label]) => `<a href="${esc(url)}"${current === url ? ' aria-current="page"' : ''}>${esc(label)}</a>`).join('')}</nav><div class="page-content"><header class="page-header"><p class="eyebrow">${serviceId ? `Amministrazione servizio · ${esc(serviceId)}` : 'Amministrazione globale · Engine Accounts'}</p><h1>${esc(title)}</h1><p class="lede">${esc(descriptions[title] ?? 'Identità e autorizzazioni di questo servizio. Le impostazioni applicative restano nel suo pannello dedicato.')}</p></header><p class="scope-note muted">${serviceId ? 'Ambito limitato a questo servizio: consensi e dati locali. Nessun privilegio globale.' : 'Ambito globale: identità, ruoli e servizi della suite.'} MFA obbligatoria · verifica password valida 5 minuti.</p>${record(req.query).notice === 'saved' ? '<p class="flash flash-ok" role="status">Operazione completata e registrata nell’audit.</p>' : ''}${content}</div></div>` }));
  }
  for (const route of ['/admin/reauth', '/admin/services/:serviceId/reauth']) {
    app.get(route, async (req, reply) => {
      const serviceId = record(req.params).serviceId as string | undefined;
      const active = await gate(req, reply, serviceId, false); if (!active) return reply;
      return render(req, reply, active.user.email, 'Conferma la tua identità', `<p class="lede">L’accesso amministrativo richiede una verifica recente, valida cinque minuti per questa sessione.</p><form method="post" class="stack">${csrfInput(csrf(req, reply))}${field({ name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}<button class="primary" type="submit">Verifica</button></form>`, serviceId);
    });
    app.post(route, async (req, reply) => {
      const serviceId = record(req.params).serviceId as string | undefined;
      const active = await gate(req, reply, serviceId, false); if (!active) return reply;
      const key = `${active.user.id}:${req.ip}`;
      const attempt = attempts.get(key) ?? { count: 0, until: Date.now() + 900_000 };
      if (attempt.count >= 5) return reply.code(429).header('Retry-After', '900').send({ error: 'Riprova più tardi.' });
      attempt.count++; attempts.set(key, attempt); bound(attempts);
      const password = body(req).password;
      if (typeof password !== 'string' || password.length > 1024 || !await verifyPassword(active.user.passwordHash, password, config)) {
        await store.appendAudit({ userId: active.user.id, event: 'admin.reauth', outcome: 'failure', ...ctx(req), metadata: {} });
         reply.code(403);
         return render(req, reply, active.user.email, 'Conferma la tua identità', `<p class="flash flash-error" role="alert">Password non valida. Nessuna operazione amministrativa è stata eseguita.</p><form method="post" class="stack">${csrfInput(csrf(req, reply))}${field({ name: 'password', label: 'Password attuale', type: 'password', autocomplete: 'current-password', required: true })}<button class="primary" type="submit">Riprova verifica</button></form><a href="/account/security">Gestisci la sicurezza del tuo account</a>`, serviceId);
      }
      recent.set(active.session.id, { sub: active.user.id, at: Date.now() }); bound(recent);
      attempts.delete(key);
      await store.appendAudit({ userId: active.user.id, event: 'admin.reauth', outcome: 'success', ...ctx(req), metadata: {} });
      return reply.redirect(serviceId ? `/admin/services/${pathId(serviceId)}` : '/admin', 303);
    });
  }
  app.get('/admin', async (req, reply) => {
    const active = await gate(req, reply); if (!active) return reply;
    const services = rows(await admin.listServices());
    const tiles: [string, string, string][] = [['/admin/accounts', 'Account e accessi', 'Cerca persone, verifica MFA, gestisci sessioni e ruoli.'], ['/admin/services', 'Servizi e integrazioni', `${services.length} servizi registrati. Controlla client, utenti e consegna eventi.`], ['/admin/audit', 'Registro amministrativo', 'Controlla l’esito degli interventi e ricostruisci le modifiche.'], ['/admin/settings', 'Regole dell’identità', 'Gestisci registrazione, sicurezza e scadenze degli accessi.'], ['/admin/diagnostics', 'Diagnostica e coda eventi', 'Verifica database, posta e consegne in attesa o in errore.']];
    return render(req, reply, active.user.email, 'Amministrazione Engine', `<section aria-labelledby="admin-tasks"><h2 id="admin-tasks">Cosa vuoi gestire?</h2><div class="card-grid">${tiles.map(([url, label, help]) => `<article class="panel action-card"><h3><a href="${url}">${label}</a></h3><p>${esc(help)}</p><a class="button secondary" href="${url}">Apri ${label.toLowerCase()}</a></article>`).join('')}</div></section><section><h2>Servizi registrati</h2>${table('Servizi registrati', ['Servizio', 'Stato', 'Eventi da controllare'], services.map(s => [`<a href="/admin/services/${pathId(idOf(s))}">${text(s.name ?? idOf(s))}</a>`, s.enabled ? 'Attivo' : 'Disabilitato', `${text(record(s.delivery).pending ?? 0)} in attesa · ${text(record(s.delivery).failed ?? 0)} in errore`]))}</section>`);
  });
  for (const route of ['/admin/accounts', '/admin/services/:serviceId/accounts']) {
    app.get(route, async (req, reply) => {
      const serviceId = record(req.params).serviceId as string | undefined;
      const active = await gate(req, reply, serviceId); if (!active) return reply;
      const query = record(req.query);
      const page = Math.max(1, Math.min(100_000, Math.trunc(Number(query.page) || 1)));
      const filters: Parameters<AdministrationUI['accounts']>[0] = { page, pageSize: 25 };
      if (typeof query.q === 'string' && query.q) filters.q = query.q.slice(0, 200);
      if (['active', 'blocked', 'deleted'].includes(String(query.status))) filters.status = query.status as typeof filters.status;
      if (active.global && ['enabled', 'disabled'].includes(String(query.mfa))) filters.mfa = query.mfa as typeof filters.mfa;
      if (active.global && ['global', 'service', 'none'].includes(String(query.role))) filters.role = query.role as typeof filters.role;
      if (typeof query.service === 'string' && query.service) filters.service = query.service.slice(0, 200);
      if (serviceId) filters.service = serviceId;
      const result = await admin.accounts(filters);
      const base = serviceId ? `/admin/services/${pathId(serviceId)}/accounts` : '/admin/accounts';
      const choices = { status: [['active', 'Attivo'], ['blocked', 'Bloccato'], ['deleted', 'Eliminato']], mfa: [['enabled', 'Attiva'], ['disabled', 'Non attiva']], role: [['global', 'Admin globale'], ['service', 'Admin servizio'], ['none', 'Utente']] };
      const select = (key: keyof typeof choices, label: string) => `<div class="field"><label for="filter-${key}">${label}</label><select id="filter-${key}" name="${key}"><option value="">Tutti</option>${choices[key].map(([value, name]) => `<option value="${value}" ${filters[key] === value ? 'selected' : ''}>${name}</option>`).join('')}</select></div>`;
       const controls = field({ name: 'q', label: 'Email, nome o identificatore account', value: filters.q }) + select('status', 'Stato account') + (active.global ? select('mfa', 'Autenticazione a più fattori (MFA)') + select('role', 'Ruolo amministrativo') : '') + (!serviceId ? field({ name: 'service', label: 'Identificatore servizio (facoltativo)', value: filters.service }) : '');
      const params = new URLSearchParams(Object.entries(filters).filter(([k]) => k !== 'page').map(([k, v]): [string, string] => [k, String(v)]));
      const pager = (p: number, label: string) => { const next = new URLSearchParams(params); next.set('page', String(p)); return `<a class="button secondary" href="${base}?${esc(next.toString())}">${label}</a>`; };
       return render(req, reply, active.user.email, serviceId ? 'Utenti del servizio' : 'Account Engine', `<p>Combina ricerca e filtri per restringere i risultati. MFA include TOTP e passkey; un collegamento al servizio non implica un ruolo amministrativo.</p><form class="filters" method="get">${controls}<button class="primary" type="submit">Filtra account</button><a class="button secondary" href="${base}">Azzera filtri</a></form>${table('Account', active.global ? ['Email', 'Stato', 'MFA', 'Ruolo'] : ['Email', 'Stato'], rows(result).map(a => [`<a href="${base}/${pathId(idOf(a))}">${text(a.email ?? idOf(a))}</a>`, esc(statusLabel(a.status)), ...(active.global ? [a.mfa ? 'Attiva' : 'Non attiva', text(a.role ?? (a.isGlobalAdmin ? 'Admin globale' : a.hasServiceRole ? 'Admin servizio' : 'Ruoli di servizio nel dettaglio'))] : [])]))}<div class="row"><p>Pagina ${page}${record(result).total !== undefined ? ` · ${text(record(result).total)} risultati` : ''}</p>${page > 1 ? pager(page - 1, 'Precedente') : ''}${page * Number(record(result).pageSize ?? 25) < Number(record(result).total ?? 0) ? pager(page + 1, 'Successiva') : ''}</div>`, serviceId);
    });
  }
  for (const route of ['/admin/accounts/:sub', '/admin/services/:serviceId/accounts/:sub']) {
    app.get(route, async (req, reply) => {
      const params = record(req.params); const serviceId = params.serviceId as string | undefined; const sub = String(params.sub);
      const active = await gate(req, reply, serviceId); if (!active) return reply;
      const detail = record(await admin.accountDetail(sub));
      const user = record(detail.user ?? detail.account ?? detail);
      if (!idOf(user)) return notFound(reply);
      if (serviceId && !linked(detail, serviceId)) return notFound(reply);
      const url = serviceId ? `/admin/services/${pathId(serviceId)}/accounts/${pathId(sub)}` : `/admin/accounts/${pathId(sub)}`;
      const token = csrf(req, reply);
      const canPurge = serviceId && Boolean(record(await admin.findService(serviceId)).adminApiUrl);
      const actions = serviceId ? [['revoke-consent', 'Revoca consenso'], ...(canPurge ? [['purge', 'Elimina dati del servizio']] : [])] : [['ban', 'Blocca account'], ['unban', 'Sblocca account'], ['force-password', 'Richiedi nuova password'], ['revoke-sessions', 'Revoca sessioni'], ['reset-mfa', 'Reimposta MFA'], ['global-grant', 'Assegna admin globale'], ['global-revoke', 'Rimuovi admin globale']];
      const deletion = !serviceId ? actionForm(token, url, 'delete', 'Elimina account', `<p class="warning">Eliminazione irreversibile dell’identità e dei suoi accessi. I servizi riceveranno l’evento di cancellazione.</p>${field({ name: 'password', label: 'La tua password amministratore', type: 'password', autocomplete: 'current-password', required: true })}`) : '';
       const state = (r: Record<string, unknown>) => r.revokedAt ? 'Revocato' : r.expiresAt && new Date(String(r.expiresAt)).getTime() <= Date.now() ? 'Scaduto' : 'Attivo';
       const sessionsTable = !serviceId ? `<section><h2>Sessioni e dispositivi</h2><p>Gli stati dipendono da revoca e scadenza. La revoca degli accessi disconnette tutte le sessioni dell’account.</p>${table('Sessioni', ['Dispositivo', 'Stato', 'Creata', 'Ultimo uso', 'Scadenza', 'Dettagli'], rows(detail.sessions).map(s => [text(s.deviceLabel), state(s), text(s.createdAt), text(s.lastSeenAt), text(s.expiresAt), `<details><summary>Dettagli sessione</summary>${facts([['ID sessione', s.id], ['IP', s.ip], ['Dispositivo / browser', s.userAgent], ['Metodi di autenticazione', Array.isArray(s.amr) ? s.amr.join(', ') : undefined], ['Revocata il', s.revokedAt ?? 'Non revocata'], ['Motivo revoca', s.revokeReason]])}</details>`]))}</section>` : '';
       const serviceActions = !serviceId ? rows(detail.services).map(s => actionForm(token, `/admin/services/${pathId(s.serviceId)}/accounts/${pathId(sub)}`, 'revoke-consent', `Revoca consenso · ${String(s.name ?? s.serviceId)}`) + (s.adminApiUrl ? actionForm(token, `/admin/services/${pathId(s.serviceId)}/accounts/${pathId(sub)}`, 'purge', `Elimina dati · ${String(s.name ?? s.serviceId)}`) : '')).join('') + table('Ruoli di servizio', ['Servizio', 'Ruolo'], rows(detail.assignments).map(s => [`<a href="/admin/services/${pathId(s.serviceId)}">${text(s.serviceId)}</a>`, 'Admin servizio'])) + (sub !== active.user.id ? ['grant', 'revoke'].map(action => actionForm(token, url, `service-${action}`, action === 'grant' ? 'Assegna admin servizio' : 'Revoca admin servizio', field({ id: `account-service-${action}`, name: 'serviceId', label: 'Identificatore servizio', required: true }))).join('') : '<p>Le assegnazioni dei tuoi stessi privilegi non sono modificabili da questa pagina.</p>') : '';
       const visibleServices = rows(detail.services).filter(s => !serviceId || String(s.serviceId) === serviceId);
       const visibleClients = new Set(visibleServices.flatMap(s => rows(s.clients).map(c => String(c.clientId))));
       const consents = rows(detail.consents).filter(c => !serviceId || visibleClients.has(String(c.clientId)));
       const mfa = record(detail.mfa);
       const identity = facts([['Identificatore account', sub], ['Stato account', statusLabel(user.status)], ...(!serviceId ? [['Nome visualizzato', user.displayName ?? 'Non impostato'], ['Email verificata', user.emailVerifiedAt ?? 'Non verificata'], ['Creato il', user.createdAt], ['Ultimo accesso', user.lastLoginAt ?? 'Nessun accesso registrato'], ['Ultimo aggiornamento', user.updatedAt], ['Blocco temporaneo fino al', user.lockedUntil ?? 'Nessun blocco temporaneo'], ['Tentativi falliti consecutivi', user.failedLogins], ['Motivo del blocco', user.blockedReason ?? 'Nessuno'], ['Eliminato il', user.deletedAt ?? 'Non eliminato'], ['Cambio password obbligatorio', yesNo(user.mustChangePassword)]] as [string, unknown][] : [])]);
       const protection = !serviceId ? `<section class="panel"><h2>Sicurezza e privilegi</h2>${facts([['MFA', user.mfa ? 'Attiva' : 'Non attiva'], ['App di autenticazione TOTP', yesNo(user.totpEnabled)], ['Amministratore globale', yesNo(user.isGlobalAdmin)], ['Ruoli di servizio', rows(detail.assignments).map(a => String(a.serviceId)).join(', ') || 'Nessun ruolo di servizio'], ['Passkey registrate', mfa.webauthnCount], ['Codici di recupero disponibili', mfa.recoveryCodesRemaining]])}<p>Il ruolo globale autorizza la gestione dell’intera suite; un ruolo di servizio vale solo per il servizio assegnato. Non puoi modificare i tuoi stessi privilegi.</p></section>` : '';
       const allowedActions = actions.filter(([action]) => sub !== active.user.id || !['global-grant', 'global-revoke'].includes(action!));
       return render(req, reply, active.user.email, 'Dettaglio account', `<section class="panel"><h2>${text(user.email)}</h2>${identity}</section>${protection}<section><h2>Servizi collegati e consensi</h2><p>Il collegamento e il consenso non assegnano un ruolo amministrativo. Le autorizzazioni richieste (scope) indicano i dati e le funzioni accessibili al client.</p>${table('Servizi collegati', ['Servizio', 'Stato', 'Audience'], visibleServices.map(s => [`<a href="/admin/services/${pathId(s.serviceId)}">${text(s.name ?? s.serviceId)}</a>`, s.enabled === undefined ? 'Collegato' : s.enabled ? 'Abilitato' : 'Disabilitato', text(s.audience)]))}${table('Consensi per client', ['Client', 'Stato', 'Autorizzazioni (scope)', 'Concesso il', 'Scadenza', 'Revocato il'], consents.map(c => [text(c.clientId), state(c), text(Array.isArray(c.scope) ? c.scope.join(', ') : 'Non disponibili'), text(c.grantedAt), text(c.expiresAt ?? 'Senza scadenza'), text(c.revokedAt ?? 'Non revocato')]))}</section>${sessionsTable}${!serviceId ? `<section><h2>Attività recente dell’account</h2>${auditTable(rows(detail.audit))}</section>` : ''}<section><h2>Interventi amministrativi</h2><p>Apri un intervento per leggerne l’effetto e confermarlo. Nessuna modifica avviene aprendo questi pannelli.</p><div class="stack">${allowedActions.map(([action, label]) => actionForm(token, url, action!, label!)).join('')}${deletion}${serviceActions}</div></section>`, serviceId);
    });
    app.post(route, async (req, reply) => {
      const params = record(req.params); const serviceId = params.serviceId as string | undefined; const sub = String(params.sub);
      const active = await gate(req, reply, serviceId); if (!active) return reply;
      const b = body(req); if (b.confirm !== 'CONFERMA') return reply.code(400).send({ error: 'Conferma richiesta.' });
      const action = String(b.action ?? '');
      if (serviceId) {
        if (!['revoke-consent', 'purge'].includes(action)) return notFound(reply);
        if (!linked(record(await admin.accountDetail(sub)), serviceId)) return notFound(reply);
        if (action === 'purge') {
          if (!record(await admin.findService(serviceId)).adminApiUrl) return notFound(reply);
          await deps.purge(active.user.id, sub, serviceId, ctx(req));
        }
        else await admin.mutateAccount(active.user.id, sub, 'revoke-consent', { serviceId }, ctx(req));
      } else {
        if (action === 'service-grant' || action === 'service-revoke') {
          if (typeof b.serviceId !== 'string' || !b.serviceId) return reply.code(400).send({ error: 'Servizio richiesto.' });
          if (action === 'service-grant') await admin.grant(active.user.id, b.serviceId, sub, ctx(req));
          else await admin.revoke(active.user.id, b.serviceId, sub, ctx(req));
        }
        else if (action === 'global-grant' || action === 'global-revoke') await admin.setGlobalRole(active.user.id, sub, action === 'global-grant', { context: ctx(req) });
        else if (action === 'delete') {
          const key = `delete:${active.user.id}:${req.ip}`;
          const attempt = attempts.get(key) ?? { count: 0, until: Date.now() + 900_000 };
          if (attempt.count >= 5) return reply.code(429).send({ error: 'Riprova più tardi.' });
          attempt.count++; attempts.set(key, attempt); bound(attempts);
          if (typeof b.password !== 'string' || !b.password || b.password.length > 1024) return reply.code(400).send({ error: 'Credenziali richieste.' });
          const result = record(await admin.mutateAccount(active.user.id, sub, 'delete', { accountService: deps.accounts, reauth: { password: b.password } }, ctx(req)));
          if (result.ok === false) return reply.code(403).send({ error: 'Eliminazione non riuscita.' });
          attempts.delete(key);
        }
        else {
          if (!['ban', 'unban', 'force-password', 'revoke-sessions', 'reset-mfa'].includes(action)) return notFound(reply);
          await admin.mutateAccount(active.user.id, sub, action as 'ban' | 'unban' | 'force-password' | 'revoke-sessions' | 'reset-mfa', {}, ctx(req));
        }
      }
      return reply.redirect(savedUrl(req.url), 303);
    });
  }
  function linked(detail: Record<string, unknown>, serviceId: string): boolean {
    return rows(detail.services ?? detail.consents).some(s => String(s.serviceId ?? s.id) === serviceId);
  }
  app.get('/admin/services', async (req, reply) => {
    const active = await gate(req, reply); if (!active) return reply;
    return render(req, reply, active.user.email, 'Servizi', table('Servizi', ['Nome', 'Audience', 'Client', 'Origine', 'Utenti', 'Eventi in errore', 'Stato'], rows(await admin.listServices()).map(s => [`<a href="/admin/services/${pathId(idOf(s))}">${text(s.name ?? idOf(s))}</a>`, text(s.audience), rows(s.clients).map(c => text(c.clientId)).join('<br>'), s.origin === 'env' ? 'Gestito da .env · sola lettura' : 'CLI', text(s.connectedUsers), text(record(s.delivery).failed), s.enabled ? 'Attivo' : 'Disabilitato'])));
  });
  app.get('/admin/services/:serviceId', async (req, reply) => {
    const serviceId = String(record(req.params).serviceId);
    const active = await gate(req, reply, serviceId); if (!active) return reply;
    const service = record(await admin.findService(serviceId)); if (!idOf(service)) return notFound(reply);
    const token = csrf(req, reply);
    const controls = active.global ? `${actionForm(token, req.url, service.enabled ? 'disable' : 'enable', service.enabled ? 'Disabilita servizio' : 'Abilita servizio')}${actionForm(token, req.url, 'grant', 'Assegna amministratore', field({ id: 'grant-sub', name: 'sub', label: 'Identificatore account', required: true }))}${actionForm(token, req.url, 'revoke', 'Rimuovi amministratore', field({ id: 'revoke-sub', name: 'sub', label: 'Identificatore account', required: true }))}` : '';
    const delivery = record(service.delivery);
    return render(req, reply, active.user.email, String(service.name ?? 'Servizio'), `<section class="panel"><h2>Identità del servizio</h2><p>${text(service.description)}</p>${facts([['Identificatore servizio', serviceId], ['Stato', service.enabled ? 'Attivo' : 'Disabilitato'], ['Audience', service.audience], ['Origine', service.origin === 'env' ? 'Gestito da .env · metadati in sola lettura' : 'CLI']])}<p>L’audience identifica il destinatario dei token; i client sono le applicazioni che richiedono l’accesso.</p></section><div class="row">${safeExternalUrl(service.adminUrl) ? `<a class="button secondary" href="${esc(service.adminUrl)}">Apri pannello del servizio (SSO)</a>` : ''}<a class="button primary" href="/admin/services/${pathId(serviceId)}/accounts">Gestisci utenti collegati · ${text(service.connectedUsers)}</a></div><section><h2>Client e autorizzazioni</h2>${table('Client registrati', ['Client', 'Nome', 'Origine', 'Stato'], rows(service.clients).map(c => [text(c.clientId), text(c.name), c.origin === 'env' ? 'Gestito da .env' : 'CLI', c.enabled ? 'Attivo' : 'Disabilitato']))}<p>Gli scope descrivono le autorizzazioni richieste dai client. Non sono ruoli amministrativi.</p>${table('Autorizzazioni del servizio (scope)', ['Scope', 'Cosa consente'], rows(service.scopes).map(s => [text(s.scope), text(s.description)]))}</section><section><h2>Amministratori del servizio</h2>${table('Amministratori assegnati', ['Account', 'Stato', 'Assegnato il', 'Assegnato da'], rows(await admin.assignments(serviceId)).map(a => [active.global ? `<a href="/admin/accounts/${pathId(a.userId)}">${text(a.email ?? a.userId)}</a>` : text(a.email ?? a.userId), esc(statusLabel(a.status)), text(a.grantedAt), text(a.grantedBy)]))}</section><section class="panel"><h2>Consegna eventi · outbox</h2><p>In attesa: ${text(delivery.pending)} · In errore: ${text(delivery.failed)}</p><p>Ultima consegna: ${text(delivery.lastDeliveredAt ?? 'Nessuna consegna')}</p><p>Gli eventi in errore sono consegne non completate dopo almeno un tentativo. Questi dati non attestano la salute del servizio.</p>${active.global ? '<a href="/admin/diagnostics">Controlla diagnostica e coda eventi</a>' : ''}</section>${controls ? `<section><h2>Stato e assegnazioni</h2><p>Non puoi assegnare o rimuovere i tuoi stessi privilegi. I metadati del registro si gestiscono tramite CLI o ambiente.</p><div class="stack">${controls}</div></section>` : '<p>Il tuo ruolo consente la gestione degli utenti collegati, non la modifica di registrazioni, ruoli o stato del servizio.</p>'}`, active.global ? undefined : serviceId);
  });
  app.post('/admin/services/:serviceId', async (req, reply) => {
    // Service administrators cannot edit registrations, roles, or service state.
    const active = await gate(req, reply); if (!active) return reply;
    const serviceId = String(record(req.params).serviceId); const b = body(req);
    if (b.confirm !== 'CONFERMA') return reply.code(400).send({ error: 'Conferma richiesta.' });
    if (b.action === 'enable' || b.action === 'disable') await admin.setServiceEnabled(active.user.id, serviceId, b.action === 'enable', ctx(req));
    else if (b.action === 'grant' || b.action === 'revoke') {
      if (typeof b.sub !== 'string' || !b.sub) return reply.code(400).send({ error: 'Account richiesto.' });
      if (b.action === 'grant') await admin.grant(active.user.id, serviceId, b.sub, ctx(req));
      else await admin.revoke(active.user.id, serviceId, b.sub, ctx(req));
    } else return notFound(reply);
    return reply.redirect(savedUrl(req.url), 303);
  });
  app.get('/admin/settings', async (req, reply) => {
    const active = await gate(req, reply); if (!active) return reply;
    const settings = rows(await admin.getSettings());
    return render(req, reply, active.user.email, 'Impostazioni identità', `<p>Le impostazioni fissate nell’ambiente sono di sola lettura. Ogni modifica viene registrata nell’audit.</p><div class="stack">${settings.map(s => {
      const [label, help] = settingLabels[String(s.key)] ?? [String(s.key), 'Impostazione del servizio di identità.'];
      const intro = `<p>${esc(help)}</p><p><code>${text(s.key)}</code></p>${facts([['Origine', s.source === 'env' ? 'Ambiente · sola lettura' : s.source === 'db' ? 'Valore salvato' : 'Valore predefinito'], ['Valore attuale', typeof s.value === 'boolean' ? yesNo(s.value) : s.value]])}`;
      const input = typeof s.value === 'boolean' ? `<div class="field"><label for="setting-${esc(s.key)}">${esc(label)}</label><select id="setting-${esc(s.key)}" name="value"><option value="true" ${s.value ? 'selected' : ''}>Abilitato</option><option value="false" ${!s.value ? 'selected' : ''}>Disabilitato</option></select></div>` : s.key === 'REGISTRATION_MODE' ? `<div class="field"><label for="setting-registration">Registrazione account</label><select id="setting-registration" name="value">${[['open', 'Aperta'], ['closed', 'Chiusa'], ['invite', 'Solo su invito']].map(([value, name]) => `<option value="${value}"${s.value === value ? ' selected' : ''}>${name}</option>`).join('')}</select></div>` : field({ id: `setting-${String(s.key)}`, name: 'value', label: `${label}${String(s.key).endsWith('_TTL') ? ' (secondi)' : ''}`, type: typeof s.value === 'number' ? 'number' : 'text', value: String(s.value), required: true });
      return s.editable ? actionForm(csrf(req, reply), '/admin/settings', 'setting', label, `${intro}<input type="hidden" name="key" value="${esc(s.key)}">${input}`) : `<section class="panel"><h2>${esc(label)}</h2>${intro}<p>Sola lettura</p></section>`;
    }).join('')}</div>`);
  });
  app.post('/admin/settings', async (req, reply) => {
    const active = await gate(req, reply); if (!active) return reply;
    const b = body(req); const settings = rows(await admin.getSettings());
    const key = String(b.key ?? '');
    const setting = settings.find(s => s.key === key && s.editable === true);
    if (b.confirm !== 'CONFERMA' || !setting) return reply.code(400).send({ error: 'Impostazione non valida.' });
    if (typeof setting.value === 'boolean' && b.value !== 'true' && b.value !== 'false') return reply.code(400).send({ error: 'Valore non valido.' });
    const value = typeof setting.value === 'boolean' ? b.value === 'true' : typeof setting.value === 'number' ? Number(b.value) : String(b.value ?? '');
    await admin.setSetting(active.user.id, key, value, ctx(req));
    return reply.redirect('/admin/settings?notice=saved', 303);
  });
  app.get('/admin/audit', async (req, reply) => {
    const active = await gate(req, reply); if (!active) return reply;
    const page = Math.max(1, Math.min(100_000, Number(record(req.query).page) || 1));
    const filters: Record<string, string | number> = { page };
    for (const key of ['actor', 'event', 'outcome', 'subjectId', 'serviceId']) if (typeof record(req.query)[key] === 'string' && record(req.query)[key]) filters[key] = String(record(req.query)[key]).slice(0, 200);
    const result = record(await admin.listAudit(filters)); const entries = rows(result);
    const params = new URLSearchParams(Object.entries(filters).map(([k, v]): [string, string] => [k, String(v)]));
    const pager = (p: number, label: string) => { const next = new URLSearchParams(params); next.set('page', String(p)); return `<a class="button secondary" href="?${esc(next.toString())}">${label}</a>`; };
    const labels: Record<string, string> = { actor: 'Autore (admin:ID account o admin:cli)', event: 'Codice evento (es. admin.account.ban)', outcome: 'Esito (success, failure, denied, info)', subjectId: 'Identificatore account interessato', serviceId: 'Identificatore servizio' };
    return render(req, reply, active.user.email, 'Registro amministrativo', `<p>I filtri cercano valori esatti. Il nome leggibile accompagna il codice originale; i dettagli mostrano solo informazioni operative consentite, mai segreti.</p><form method="get" class="filters">${['actor', 'event', 'outcome', 'subjectId', 'serviceId'].map(k => field({ name: k, label: labels[k]!, value: String(filters[k] ?? '') })).join('')}<button type="submit" class="primary">Filtra audit</button><a class="button secondary" href="/admin/audit">Azzera filtri</a></form>${auditTable(entries)}<div class="row">${page > 1 ? pager(page - 1, 'Precedente') : ''}<p>Pagina ${page}${result.total !== undefined ? ` · ${text(result.total)} eventi` : ''}</p>${page * Number(result.pageSize ?? 25) < Number(result.total ?? 0) ? pager(page + 1, 'Successiva') : ''}</div>`);
  });
  app.get('/admin/diagnostics', async (req, reply) => {
    const active = await gate(req, reply); if (!active) return reply;
    const diagnostic = record(await admin.diagnostics());
    // Whitelist operational summaries; never render raw config, keys, cookies or metadata.
    const keys = ['database', 'smtp', 'outbox', 'services', 'sessions', 'status', 'pendingEvents', 'failedEvents', 'issuer', 'mailEnabled', 'secureCookies', 'users'];
    const jwks = record(diagnostic.jwks);
    const labels: Record<string, string> = { database: 'Connessione database', smtp: 'Server posta (SMTP)', outbox: 'Coda eventi (outbox)', services: 'Servizi', sessions: 'Sessioni', status: 'Stato', pendingEvents: 'Eventi in attesa di consegna', failedEvents: 'Eventi con tentativi non riusciti', issuer: 'Emittente identità', mailEnabled: 'Invio email abilitato', secureCookies: 'Cookie solo HTTPS', users: 'Account' };
    return render(req, reply, active.user.email, 'Diagnostica', `<section><h2>Componenti dell’identità</h2>${table('Stato operativo', ['Componente', 'Stato'], keys.filter(k => typeof diagnostic[k] === 'string' || typeof diagnostic[k] === 'number' || typeof diagnostic[k] === 'boolean').map(k => [esc(labels[k] ?? k), typeof diagnostic[k] === 'boolean' ? yesNo(diagnostic[k]) : typeof diagnostic[k] === 'string' ? esc(statusLabel(diagnostic[k])) : text(diagnostic[k])]))}<p>Gli eventi in errore sono ancora in attesa dopo almeno un tentativo. Una connessione riuscita non certifica tutti i flussi del servizio.</p><div class="row"><a class="button secondary" href="/admin/services">Controlla le consegne per servizio</a><a class="button secondary" href="/admin/audit">Apri il registro eventi</a></div></section><section class="panel"><h2>Chiavi pubbliche di firma (JWKS)</h2><p>Stato: ${esc(statusLabel(jwks.status))} · Età del file: ${text(jwks.fileAgeSeconds ?? 'Non disponibile')} secondi. Non è l’età di ogni singola chiave.</p><p>Questi identificatori pubblici permettono ai servizi di verificare i token. Le chiavi private non sono mostrate e questa pagina non modifica né ruota le chiavi.</p>${table('Identificatori pubblici', ['Identificatore chiave (kid)', 'Algoritmo'], rows(jwks.keys).map(k => [text(k.kid), text(k.alg)]))}</section>`);
  });
}
