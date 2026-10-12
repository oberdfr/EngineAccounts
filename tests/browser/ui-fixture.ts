/** Loopback-only synthetic rendering fixture. No database, deployment config or real credentials. */
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import * as pages from '../../src/ui/pages.js';
import { layout, esc } from '../../src/ui/layout.js';
import { registerAdminRoutes, type AdminDeps } from '../../src/ui/admin-routes.js';
import { loadConfig } from '../../src/config.js';
import { hashPassword } from '../../src/security/password.js';
import { sessionCookieName, presentSessions } from '../../src/services/session-manager.js';
import { renderTotpQrSvg } from '../../src/services/mfa.js';
import { csrfCookieName } from '../../src/security/csrf.js';
import type { SessionRecord, WebauthnCredential } from '../../src/domain/types.js';

const app = Fastify();
await app.register(formbody);
const csrf = 'synthetic-fixture-csrf-only'.repeat(2);
const email = `${'long'.repeat(20)}@example.test`;
const now = new Date('2026-10-12T10:30:00Z');
const created = new Date('2026-01-01T09:00:00Z');
const identity = { csrf, email };
const account = { id: '00000000-0000-4000-8000-000000000001', status: 'active', createdAt: created, updatedAt: now, lastLoginAt: now, emailVerifiedAt: created, mustChangePassword: false, isGlobalAdmin: true, totpEnabled: true, failedLogins: 0, lockedUntil: null, blockedReason: null };
const sessions: (SessionRecord & { current: boolean })[] = [
  ['current', 'Chrome · Linux', '192.0.2.10', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36', true],
  ['same-browser', 'Chrome · Linux', '192.0.2.10', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36', false],
  ['phone', 'Safari · iPhone', '2001:db8::12', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1', false],
  ['unknown', 'Browser non riconosciuto', null, null, false],
].map(([id, deviceLabel, ip, userAgent, current], index) => ({ id: String(id), userId: account.id, tokenDigest: 'synthetic-not-a-token', providerSessionId: null, providerSessionUid: null, deviceLabel: String(deviceLabel), ip: ip as string | null, userAgent: userAgent as string | null, current: Boolean(current), amr: index === 3 ? ['pwd'] : ['pwd', 'otp'], createdAt: new Date(created.getTime() + index * 86_400_000), lastSeenAt: now, expiresAt: new Date('2099-01-01'), revokedAt: null, revokeReason: null }));
const passkeys: (WebauthnCredential & { label: string })[] = ['Passkey del portatile', 'Chiave di sicurezza di riserva'].map((label, index) => ({ id: `fixture-key-${index}`, userId: account.id, credentialId: Buffer.from(`synthetic-public-credential-${index}`).toString('base64url'), publicKey: Buffer.alloc(0), counter: 0, transports: index ? ['usb', 'nfc'] : ['internal', 'hybrid'], aaguid: null, deviceType: index ? 'singleDevice' : 'multiDevice', backedUp: !index, nickname: label, label, createdAt: created, lastUsedAt: now }));
const consents = ['Engine Studio', 'Archivio documenti'].map((clientName, index) => ({ id: `consent-${index}`, userId: account.id, clientId: `fixture-client-${index}`, clientName, scope: ['openid', 'profile', 'email', 'documents:read'], grantedAt: created, expiresAt: null, revokedAt: null }));
const services = [
  { id: 'assigned', serviceId: 'assigned', name: 'Engine Studio', audience: 'https://studio.example.test', enabled: true, linked: true, adminUrl: 'https://studio.example.test/admin', adminApiUrl: 'https://studio.example.test/api/admin', description: 'Ambiente sintetico per collaborazione e documenti.', origin: 'env', connectedUsers: 42, clients: [{ clientId: 'fixture-client-0', enabled: true, origin: 'env' }], delivery: { pending: 3, failed: 1, lastDeliveredAt: now } },
  { id: 'archive', serviceId: 'archive', name: 'Archivio documenti con un nome volutamente molto lungo', audience: 'https://archive.example.test', enabled: false, linked: false, adminUrl: null, origin: 'cli', connectedUsers: 0, clients: [{ clientId: 'fixture-client-1', enabled: false }], delivery: { pending: 0, failed: 0 } },
];
const entries = ['account.login', 'account.password.changed', 'account.totp.enabled', 'synthetic.unknown.event'].map((event, index) => ({ at: new Date(now.getTime() - index * 86_400_000), event, outcome: index === 3 ? 'denied' : 'success', ip: index === 2 ? null : '2001:db8::1234', metadata: {} }));
const optionsJson = JSON.stringify({ challenge: Buffer.from('synthetic-challenge-not-valid-in-production').toString('base64url'), rp: { name: 'Engine Accounts fixture', id: '127.0.0.1' }, user: { id: Buffer.from(account.id).toString('base64url'), name: 'synthetic@example.test', displayName: 'Persona sintetica' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], timeout: 60000, attestation: 'none', authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }, excludeCredentials: [] });

app.addHook('onSend', async (_req, reply) => { reply.header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; form-action 'self'; object-src 'none'; frame-ancestors 'none'"); });
app.get('/static/:file', async (req, reply) => {
  const { file } = req.params as { file: string };
  if (!['app.css', 'app.js', 'preferences.js', 'logout.js', 'header-controls.css', 'header-controls.js', 'select-controls.css', 'select-controls.js'].includes(file)) return reply.code(404).send();
  return reply.type(file.endsWith('.css') ? 'text/css' : 'text/javascript').send(await readFile(new URL(`../../src/ui/static/${file}`, import.meta.url)));
});
app.get('/static/fonts/:family/:file', async (req, reply) => {
  const { family, file } = req.params as { family: string; file: string };
  if (!['geist', 'inter'].includes(family) || file !== `${family}-latin-wght-normal.woff2`) return reply.code(404).send();
  return reply.type('font/woff2').send(await readFile(fileURLToPath(new URL(`../../node_modules/@fontsource-variable/${family}/files/${file}`, import.meta.url))));
});
app.get('/fixture/export.json', async () => ({ synthetic: true, profile: { id: account.id, email: 'synthetic@example.test' } }));
app.post('/fixture/delete', async (_req, reply) => reply.type('text/html').send('<!doctype html><html lang="it"><title>Esito sintetico</title><h1>Invio sintetico ricevuto</h1><p>Nessun account eliminato.</p></html>'));
// Every other form is safely intercepted by this fixture, never by production handlers.
app.post('/*', async (_req, reply) => reply.code(400).send({ synthetic: true, message: 'Rendering fixture: nessuna modifica eseguita.' }));

// Real administration renderers, with in-memory stubs and synthetic reauthentication only.
const adminApp = Fastify();
await adminApp.register(cookie);
await adminApp.register(formbody);
const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused/test', OIDC_CLIENTS_JSON: '[]', ARGON2_MEMORY_KIB: '8192', ARGON2_ITERATIONS: '1' });
const passwordHash = await hashPassword('synthetic-fixture-password', config);
const noMutation = async () => { throw new Error('Fixture refuses administration mutations'); };
let lastAccountFilters: unknown = null;
const deps = {
  config,
  sessions: { resolve: async (role: string) => ({ user: { ...account, email, passwordHash, totpEnabled: role !== 'mfa-required', id: role === 'service' ? 'service-actor' : 'global-actor' }, session: { id: `synthetic-${role}`, amr: role === 'mfa-required' || role === 'password-only' ? ['pwd'] : ['pwd', 'otp'] } }) },
  store: { listWebauthnCredentials: async () => [], appendAudit: async () => {} },
  admin: {
    isGlobalAdmin: async (id: string) => id !== 'service-actor',
    authorization: async (_id: string, serviceId: string) => ({ admin: serviceId === 'assigned', global: false, status: 'active' }),
    listServices: async () => services, findService: async (id: string) => services.find(s => s.id === id),
    assignments: async () => [{ userId: 'service-actor', email: 'service-admin@example.test', serviceId: 'assigned' }],
    accounts: async (filters: unknown) => { lastAccountFilters = filters; return { items: [{ ...account, email, displayName: 'Persona sintetica', mfa: true, role: 'Admin servizio' }, { id: 'blocked-target', email: 'blocked@example.test', status: 'blocked', mfa: false }], total: 42, pageSize: 25 }; },
    accountDetail: async () => ({ account: { ...account, email, displayName: 'Persona sintetica', mfa: true }, sessions, consents, services, assignments: [{ serviceId: 'assigned' }], mfa: { webauthnCount: 2, recoveryCodesRemaining: 8 }, audit: entries.map((e, i) => ({ ...e, id: `audit-${i}`, actor: 'global-actor', subjectId: account.id })) }),
    listAudit: async () => ({ entries: entries.map(e => ({ ...e, actor: 'global-actor', subjectId: account.id })), total: 42, pageSize: 25 }),
    getSettings: async () => [{ key: 'EMAIL_VERIFICATION_REQUIRED', value: true, editable: true, source: 'db' }, { key: 'REGISTRATION_MODE', value: 'open', editable: true, source: 'db' }, { key: 'SESSION_TTL', value: 86400, editable: true, source: 'db' }, { key: 'issuer', value: 'https://identity.example.test', editable: false, source: 'env' }],
    diagnostics: async () => ({ database: 'available', smtp: 'disabled', outbox: 'available', services: 2, sessions: 4, pendingEvents: 3, failedEvents: 1, issuer: 'https://identity.example.test', secureCookies: true, jwks: { status: 'available', fileAgeSeconds: 3600, keys: [{ kid: 'synthetic-public-key-id', alg: 'RS256' }] } }),
    mutateAccount: noMutation, setServiceEnabled: noMutation, grant: noMutation, revoke: noMutation, setGlobalRole: noMutation, setSetting: noMutation,
  }, accounts: { deleteAccountAsAdmin: noMutation }, purge: noMutation,
} as unknown as AdminDeps;
await registerAdminRoutes(adminApp, deps);
const adminHeaders = (role: string) => ({ cookie: `${sessionCookieName(config)}=${role}; ${csrfCookieName(config.cookiePrefix)}=${csrf}` });
const verifiedAt = new Map<string, number>();
async function ensureSyntheticReauth(role: 'global' | 'service') {
  if (Date.now() - (verifiedAt.get(role) ?? 0) < 240_000) return;
  const response = await adminApp.inject({ method: 'POST', url: role === 'global' ? '/admin/reauth' : '/admin/services/assigned/reauth', headers: adminHeaders(role), payload: { _csrf: csrf, password: 'synthetic-fixture-password' } });
  if (response.statusCode !== 303) throw new Error(`Synthetic reauthentication failed: ${response.statusCode}`);
  verifiedAt.set(role, Date.now());
}
await ensureSyntheticReauth('global');
await ensureSyntheticReauth('service');
app.get('/admin*', async (req, reply) => {
  await ensureSyntheticReauth('global');
  const response = await adminApp.inject({ url: req.url, headers: adminHeaders('global') });
  if (response.headers.location) reply.header('location', response.headers.location);
  return reply.code(response.statusCode).type('text/html').send(response.body);
});
app.get('/fixture/service-admin/*', async (req, reply) => {
  await ensureSyntheticReauth('service');
  const path = (req.params as { '*': string })['*'];
  const response = await adminApp.inject({ url: `/admin/services/assigned${path ? `/${path}` : ''}`, headers: adminHeaders('service') });
  return reply.code(response.statusCode).type('text/html').send(response.body);
});
app.get('/fixture/admin-mfa', async (_req, reply) => {
  const response = await adminApp.inject({ url: '/admin', headers: adminHeaders('mfa-required') });
  return reply.code(response.statusCode).type('text/html').send(response.body);
});
app.get('/fixture/admin-password-only', async (_req, reply) => {
  const response = await adminApp.inject({ url: '/admin', headers: adminHeaders('password-only') });
  return reply.code(response.statusCode).type('text/html').send(response.body);
});
app.get('/fixture/last-account-filters', async () => ({ synthetic: true, filters: lastAccountFilters }));
app.get('/fixture/select-result', async req => ({ synthetic: true, submitted: req.query }));
app.get('/fixture/selects', async (_req, reply) => reply.type('text/html').send(layout({
  title: 'Select sintetici', width: 'wide', userEmail: email, csrf, admin: true, currentPath: '/account',
  body: `<header class="page-header"><h1>Select sintetici</h1><p>Nessuna modifica a dati reali.</p></header>
<form id="select-fixture-form" class="stack panel" method="get" action="/fixture/select-result">
<div class="field"><label for="select-top">Scelta principale</label><p id="select-help" class="hint">Seleziona una voce sintetica.</p><select id="select-top" name="choice" aria-describedby="select-help"><optgroup label="Disponibili"><option value="alpha" selected>Alpha</option><option value="blocked" disabled>Bloccata</option><option value="beta">Beta</option><option value="gamma">Gamma</option></optgroup><optgroup label="Gruppo disabilitato" disabled><option value="group-disabled">Non disponibile nel gruppo</option></optgroup><option value="hidden" hidden>Nascosta</option></select></div>
<div class="field"><label for="select-required">Scelta obbligatoria</label><select id="select-required" name="requiredChoice" required><option value="" selected>Seleziona una voce</option><option value="yes">Confermata</option></select></div>
<div class="field"><label for="select-disabled">Scelta disabilitata</label><select id="select-disabled" name="disabledChoice" disabled><option value="excluded" selected>Non modificabile</option></select></div>
<fieldset disabled><legend>Gruppo controlli disabilitato</legend><label for="select-fieldset">Select nel fieldset disabilitato</label><select id="select-fieldset" name="fieldsetChoice"><option value="excluded">Non modificabile nel gruppo</option></select></fieldset>
<div class="row"><button type="submit" class="primary">Invia selezioni sintetiche</button><button type="reset">Ripristina selezioni</button></div>
${Array.from({ length: 12 }, (_, i) => `<p>Contenuto sintetico ${i + 1}: spazio per verificare scorrimento e posizionamento del menu.</p>`).join('')}
<div class="table-scroll" tabindex="0" aria-label="Contenitore con overflow"><div class="field"><label for="select-bottom">Lista lunga in fondo</label><select id="select-bottom" name="longChoice">${Array.from({ length: 24 }, (_, i) => `<option value="item-${i + 1}"${i === 0 ? ' selected' : ''}>${esc(`Elemento ${String(i + 1).padStart(2, '0')}`)}</option>`).join('')}</select></div></div>
</form>`,
})));

const renderers: Record<string, () => string | Promise<string>> = {
  account: () => pages.accountHomePage({ ...identity, displayName: 'Persona sintetica', emailVerified: true, createdAt: created, lastActivity: now, sessions: 4, consents: 2, hasTotp: true, passkeys: 2, recoveryLeft: 8, isGlobalAdmin: true }),
  profile: () => pages.accountProfilePage({ ...identity, displayName: 'Persona sintetica', emailVerified: true, account, serviceRoles: [{ serviceId: 'assigned', name: 'Engine Studio', admin: true }] }),
  security: () => pages.accountSecurityPage({ ...identity, hasTotp: true, totpConfirmed: true, passkeys, recoveryLeft: 8 }),
  sessions: () => pages.accountSessionsPage({ ...identity, sessions, sessionOverview: presentSessions(sessions, 'current', now.getTime()) }),
  apps: () => pages.accountAppsPage({ ...identity, consents }),
  services: () => pages.accountServicesPage({ ...identity, admin: true, services }),
  activity: () => pages.accountActivityPage({ ...identity, entries, total: 42 }),
  export: () => pages.accountExportPage({ ...identity, downloadUrl: '/fixture/export.json' }),
  delete: () => pages.accountDeletePage(identity).replace('action="/account/delete"', 'action="/fixture/delete"'),
  totp: async () => {
    const uri = 'otpauth://totp/Engine%20fixture:synthetic%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Engine%20fixture';
    return pages.totpSetupPage({ ...identity, secret: 'JBSWY3DPEHPK3PXP', uri, qrSvg: await renderTotpQrSvg(uri) });
  },
  passkey: () => pages.webauthnRegisterPage({ ...identity, optionsJson }),
  recovery: () => pages.recoveryCodesPage({ ...identity, codes: ['synthetic-0001', 'synthetic-0002', 'synthetic-0003', 'synthetic-0004'] }),
  login: () => pages.loginPage({ csrf }),
};
// Targeted Account polish fixtures: role comes exclusively from synthetic query data.
// These render real pages, not production account handlers or database records.
app.get('/fixture/account-polish/:page', async (req, reply) => {
  const { page } = req.params as { page: string };
  const { role = 'global' } = req.query as { role?: string };
  if (!['global', 'ordinary', 'assigned'].includes(role)) return reply.code(400).send({ synthetic: true });
  const auth = {
    ...identity,
    isGlobalAdmin: role === 'global',
    adminDestinations: role === 'assigned' ? [{ href: '/admin/services/assigned', label: 'Engine Studio' }] : [],
  };
  const targeted: Record<string, () => string> = {
    home: () => pages.accountHomePage({ ...auth, displayName: 'Persona sintetica', emailVerified: true, createdAt: created, lastActivity: now, sessions: 4, consents: 2, hasTotp: true, passkeys: 2, recoveryLeft: 8 }),
    profile: () => pages.accountProfilePage({ ...auth, displayName: 'Persona sintetica', emailVerified: true, account: { ...account, isGlobalAdmin: role === 'global' }, serviceRoles: role === 'assigned' ? [{ serviceId: 'assigned', name: 'Engine Studio', admin: true }] : [] }),
    security: () => pages.accountSecurityPage({ ...auth, hasTotp: true, totpConfirmed: true, passkeys, recoveryLeft: 8 }),
    export: () => pages.accountExportPage({ ...auth, downloadUrl: '/fixture/export.json' }),
  };
  const render = targeted[page];
  if (!render) return reply.code(404).send({ synthetic: true });
  return reply.type('text/html').send(render());
});
app.get('/fixture/delete', async (_req, reply) => reply.type('text/html').send(await renderers.delete!()));
app.get('/*', async (req, reply) => {
  const path = req.url.split('?')[0]!;
  const alias = path === '/account/security/totp/setup' ? 'totp' : path === '/account/security/webauthn/register' ? 'passkey' : path === '/account/security/recovery-codes' ? 'recovery' : path === '/ui/login' ? 'login' : path.replace(/^\/account\//, '').slice(path.startsWith('/account/') ? 0 : 1);
  const render = renderers[alias];
  if (!render) return reply.code(404).send({ synthetic: true, error: 'Unknown fixture page' });
  return reply.type('text/html').send(await render());
});
app.addHook('onClose', async () => { await adminApp.close(); });
await app.listen({ host: '127.0.0.1', port: 18081 });
console.log('Synthetic UI fixture: http://127.0.0.1:18081/account (auto-close 15 minutes)');
setTimeout(() => { void app.close(); }, 900_000).unref();
