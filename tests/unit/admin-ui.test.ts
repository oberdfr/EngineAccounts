import { describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { loadConfig } from '../../src/config.js';
import { registerAdminRoutes, type AdminDeps } from '../../src/ui/admin-routes.js';

import { hashPassword } from '../../src/security/password.js';

async function fixture(mode: 'global' | 'service' | 'ordinary' | 'anonymous' = 'global', mfa = true, amr = mfa ? ['pwd', 'otp'] : ['pwd']) {
  const calls: unknown[] = [];
  const admin = {
    isGlobalAdmin: async () => mode === 'global',
    authorization: async (_sub: string, id: string) => ({ admin: mode === 'service' && id === 'assigned', global: false, status: 'active' }),
    listServices: async () => [{ id: 'assigned', name: '<Service>', enabled: true }],
     findService: async (id: string) => ({ serviceId: id, name: 'Service', enabled: true, adminApiUrl: 'https://service.example.test/admin', scopes: [{ scope: 'profile:read', description: 'Legge il profilo del servizio' }] }),
    assignments: async () => [], accounts: async () => ({ items: [], total: 0 }),
     accountDetail: async () => ({ account: { id: 'target', email: 'target@example.test', displayName: '<Target>', status: 'active', isGlobalAdmin: true, mfa: true, totpEnabled: true, mustChangePassword: true, emailVerifiedAt: new Date('2026-01-02T12:00:00Z'), createdAt: new Date('2026-01-01T12:00:00Z'), updatedAt: new Date('2026-01-04T12:00:00Z'), lastLoginAt: new Date('2026-01-03T12:00:00Z'), passwordHash: 'NEVER-RENDER' }, mfa: { webauthnCount: 2, recoveryCodesRemaining: 3, secret: 'NEVER-MFA' }, assignments: [{ serviceId: 'assigned' }], services: [{ serviceId: 'assigned', clients: [{ clientId: 'assigned-client' }] }, { serviceId: 'unrelated-private-service', clients: [{ clientId: 'PRIVATE-CLIENT' }] }], consents: [{ clientId: 'assigned-client', scope: ['profile:read'], grantedAt: new Date('2026-01-01T12:00:00Z'), revokedAt: new Date('2026-01-02T12:00:00Z') }, { clientId: 'PRIVATE-CLIENT', scope: ['PRIVATE-SCOPE'] }], sessions: [{ deviceLabel: 'PRIVATE-SESSION', expiresAt: new Date('2020-01-01T12:00:00Z'), revokedAt: null, tokenDigest: 'NEVER-DIGEST' }] }),
    mutateAccount: async (...args: unknown[]) => { calls.push(args); },
    setServiceEnabled: async () => { calls.push('enable'); }, grant: async () => {}, revoke: async () => {},
     setGlobalRole: async () => { calls.push('global-role'); }, listAudit: async () => ({ items: [{ event: 'admin.account.ban', actor: 'admin:actor', outcome: 'success', subjectId: 'target', userAgent: '<Browser>', metadata: { serviceId: 'assigned', password: 'NEVER-AUDIT' } }], total: 1 }), getSettings: async () => [{ key: 'SESSION_TTL', value: 300, editable: true, source: 'db' }, { key: 'ADMIN_MFA_REQUIRED', value: true, editable: false, source: 'default' }], setSetting: async () => {}, diagnostics: async () => ({ database: true, pendingEvents: 2, failedEvents: 1, privateKey: 'NEVER-JWKS', jwks: { status: 'available', keys: [{ kid: 'public-key-id', alg: 'RS256', d: 'NEVER-JWKS' }] } }),
  };
  let sessionId = 'session-one';
  const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused/test', OIDC_CLIENTS_JSON: '[]', ARGON2_MEMORY_KIB: '8192', ARGON2_ITERATIONS: '1' });
  const passwordHash = await hashPassword('correct', config);
  const deps = {
    config, admin,
     sessions: { resolve: async () => mode === 'anonymous' ? undefined : ({ user: { id: 'actor', email: 'actor@example.test', status: 'active', totpEnabled: mfa, passwordHash }, session: { id: sessionId, amr } }) },
    store: { listWebauthnCredentials: async () => [], appendAudit: async () => {} },
    accounts: { deleteAccount: async () => { calls.push('delete'); return { ok: true, message: '' }; } },
    purge: async (...args: unknown[]) => { calls.push(args); },
  } as unknown as AdminDeps;
  const app = Fastify(); await app.register(cookie); await app.register(formbody); await registerAdminRoutes(app, deps);
  const token = 'x'.repeat(43);
  const headers = { cookie: `ea_sid=synthetic; ea_csrf=${token}` };
  const post = (url: string, payload: Record<string, unknown>) => app.inject({ method: 'POST', url, headers, payload });
  const reauth = (url = '/admin/reauth') => post(url, { _csrf: token, password: 'correct' });
  return { app, calls, token, headers, post, reauth, changeSession: () => { sessionId = 'session-two'; } };
}

describe('isolated administration UI guards', () => {
  it.each(['ordinary', 'anonymous'] as const)('returns 404 for every route to %s', async mode => {
    const f = await fixture(mode);
    try {
      for (const url of ['/admin', '/admin/reauth', '/admin/accounts', '/admin/accounts/target', '/admin/services', '/admin/services/assigned', '/admin/services/assigned/reauth', '/admin/services/assigned/accounts', '/admin/services/assigned/accounts/target', '/admin/settings', '/admin/audit', '/admin/diagnostics']) {
        expect((await f.app.inject({ url, headers: f.headers })).statusCode, url).toBe(404);
      }
      for (const url of ['/admin/reauth', '/admin/accounts/target', '/admin/services/assigned', '/admin/services/assigned/reauth', '/admin/services/assigned/accounts/target', '/admin/settings']) expect((await f.post(url, {})).statusCode, url).toBe(404);
      expect(f.calls).toEqual([]);
    } finally { await f.app.close(); }
  });
  it('requires enabled MFA before administrative access', async () => {
    const f = await fixture('global', false);
     try {
       for (const response of [await f.app.inject({ url: '/admin', headers: f.headers }), await f.reauth()]) {
         expect(response.statusCode).toBe(403); expect(response.headers.location).toBeUndefined();
         expect(response.body).toContain('MFA richiesta'); expect(response.body).toContain('Configura MFA');
         expect(response.body).toContain('/account/security?admin=mfa-required');
       }
       expect(f.calls).toEqual([]);
     } finally { await f.app.close(); }
  });
  it('checks CSRF on reauth and mutations; checks confirmation; binds reauth to the session', async () => {
    const f = await fixture();
    try {
      expect((await f.app.inject({ url: '/admin', headers: f.headers })).headers.location).toBe('/admin/reauth');
      expect((await f.post('/admin/reauth', { password: 'correct' })).statusCode).toBe(403);
      expect((await f.reauth()).statusCode).toBe(303);
      expect((await f.app.inject({ url: '/admin', headers: f.headers })).statusCode).toBe(200);
      expect((await f.post('/admin/accounts/target', { action: 'ban', confirm: 'CONFERMA' })).statusCode).toBe(403);
      expect((await f.post('/admin/accounts/target', { _csrf: f.token, action: 'ban' })).statusCode).toBe(400);
      expect((await f.post('/admin/accounts/target', { _csrf: f.token, action: 'ban', confirm: 'CONFERMA' })).statusCode).toBe(303);
      expect(f.calls).toHaveLength(1);
      f.changeSession();
      expect((await f.app.inject({ url: '/admin', headers: f.headers })).headers.location).toBe('/admin/reauth');
    } finally { await f.app.close(); }
  });
  it('rejects enrolled but password-only sessions on reads, reauth and mutations', async () => {
    const f = await fixture('global', true, ['pwd']);
    try {
      const responses = [await f.app.inject({ url: '/admin', headers: f.headers }), await f.reauth(), await f.post('/admin/accounts/target', { _csrf: f.token, action: 'ban', confirm: 'CONFERMA' })];
      for (const response of responses) {
        expect(response.statusCode).toBe(403); expect(response.headers.location).toBeUndefined();
        expect(response.body).toContain('Completa secondo fattore'); expect(response.body).toContain('href="/ui/login"');
      }
      expect(f.calls).toEqual([]);
    } finally { await f.app.close(); }
  });
  it.each(['otp', 'webauthn', 'recovery_code'])('accepts a verified %s session with an enrolled factor', async method => {
    const f = await fixture('global', true, ['pwd', method]);
    try {
      expect((await f.reauth()).statusCode).toBe(303);
      expect((await f.app.inject({ url: '/admin', headers: f.headers })).statusCode).toBe(200);
    } finally { await f.app.close(); }
  });
  it('expires verification after five minutes', async () => {
    const f = await fixture(); const clock = vi.spyOn(Date, 'now'); const now = Date.now();
    try { clock.mockReturnValue(now); await f.reauth(); clock.mockReturnValue(now + 300_000); expect((await f.app.inject({ url: '/admin', headers: f.headers })).headers.location).toBe('/admin/reauth'); } finally { clock.mockRestore(); await f.app.close(); }
  });
  it('rate limits password verification', async () => {
    const f = await fixture();
    try { for (let i = 0; i < 5; i++) expect((await f.post('/admin/reauth', { _csrf: f.token, password: 'wrong' })).statusCode).toBe(403); expect((await f.reauth()).statusCode).toBe(429); } finally { await f.app.close(); }
  });
  it('service admins access only their service and cannot ban, change settings, or grant roles', async () => {
    const f = await fixture('service');
    try {
      await f.reauth('/admin/services/assigned/reauth');
      expect((await f.app.inject({ url: '/admin/services/assigned', headers: f.headers })).statusCode).toBe(200);
      for (const url of ['/admin', '/admin/settings', '/admin/accounts', '/admin/services/other']) expect((await f.app.inject({ url, headers: f.headers })).statusCode).toBe(404);
      expect((await f.post('/admin/services/assigned/accounts/target', { _csrf: f.token, confirm: 'CONFERMA', action: 'ban' })).statusCode).toBe(404);
      expect((await f.post('/admin/services/assigned', { _csrf: f.token, confirm: 'CONFERMA', action: 'grant', sub: 'target' })).statusCode).toBe(404);
      expect((await f.post('/admin/services/assigned/accounts/target', { _csrf: f.token, confirm: 'CONFERMA', action: 'purge' })).statusCode).toBe(303);
      expect(f.calls).toEqual([['actor', 'target', 'assigned', { ip: '127.0.0.1', userAgent: 'lightMyRequest' }]]);
      const detail = await f.app.inject({ url: '/admin/services/assigned/accounts/target', headers: f.headers });
       expect(detail.body).not.toContain('unrelated-private-service'); expect(detail.body).not.toContain('PRIVATE-SESSION'); expect(detail.body).not.toContain('NEVER-RENDER'); expect(detail.body).not.toContain('Admin globale'); expect(detail.body).not.toContain('PRIVATE-CLIENT'); expect(detail.body).not.toContain('PRIVATE-SCOPE'); expect(detail.body).not.toContain('NEVER-MFA');
    } finally { await f.app.close(); }
  });
  it('rate limits all administrative POST routes, not just verification', async () => {
    const f = await fixture();
    try { await f.reauth(); for (let i = 0; i < 29; i++) expect((await f.post('/admin/settings', { _csrf: f.token })).statusCode).toBe(400); expect((await f.post('/admin/accounts/target', { _csrf: f.token, confirm: 'CONFERMA', action: 'ban' })).statusCode).toBe(429); expect(f.calls).toEqual([]); } finally { await f.app.close(); }
  });
  it('provides actionable dashboard navigation and explicit scope', async () => {
    const f = await fixture();
    try {
      await f.reauth(); const response = await f.app.inject({ url: '/admin', headers: f.headers });
      expect(response.body).toContain('class="page-header"'); expect(response.body).toContain('Amministrazione globale');
      expect(response.body).toContain('Cosa vuoi gestire?'); expect(response.body).toContain('Diagnostica e coda eventi');
      expect(response.body).toContain('aria-current="page"'); expect(response.body).toContain('&lt;Service&gt;');
      for (const path of ['/admin/accounts', '/admin/services', '/admin/settings', '/admin/audit', '/admin/diagnostics']) expect(response.body).toContain(`href="${path}"`);
    } finally { await f.app.close(); }
  });
  it('shows safe identity, security, roles, consent and session fields with explanatory actions', async () => {
    const f = await fixture();
    try {
      await f.reauth(); const response = await f.app.inject({ url: '/admin/accounts/target', headers: f.headers });
      for (const label of ['Email verificata', 'Creato il', 'Ultimo accesso', 'Ultimo aggiornamento', 'Cambio password obbligatorio', 'App di autenticazione TOTP', 'Passkey registrate', 'Codici di recupero disponibili', 'Ruoli di servizio', 'Consensi per client', 'Scaduto', 'Revocato', 'CONFERMA', 'La tua password amministratore']) expect(response.body).toContain(label);
      expect(response.body).toContain('2026-01-04T12:00:00.000Z'); expect(response.body).toContain('&lt;Target&gt;');
      expect(response.body).toContain('Rimuove TOTP, passkey e codici di recupero');
      for (const secret of ['NEVER-RENDER', 'NEVER-MFA', 'NEVER-DIGEST']) expect(response.body).not.toContain(secret);
    } finally { await f.app.close(); }
  });
  it('labels audit events and renders only allowlisted operational details', async () => {
    const f = await fixture();
    try {
      await f.reauth(); const response = await f.app.inject({ url: '/admin/audit', headers: f.headers });
      for (const label of ['Account bloccato', 'admin.account.ban', 'Mostra dettagli', '&lt;Browser&gt;', 'Identificatore account interessato', 'Azzera filtri']) expect(response.body).toContain(label);
      expect(response.body).not.toContain('NEVER-AUDIT');
    } finally { await f.app.close(); }
  });
  it('explains settings, service scopes and diagnostics without exposing key material', async () => {
    const f = await fixture();
    try {
      await f.reauth();
      const settings = await f.app.inject({ url: '/admin/settings', headers: f.headers });
      expect(settings.body).toContain('Durata sessioni'); expect(settings.body).toContain('(secondi)'); expect(settings.body).toContain('Sola lettura');
      const service = await f.app.inject({ url: '/admin/services/assigned', headers: f.headers });
      expect(service.body).toContain('profile:read'); expect(service.body).toContain('Legge il profilo del servizio');
      const diagnostics = await f.app.inject({ url: '/admin/diagnostics', headers: f.headers });
      expect(diagnostics.body).toContain('Connessione database'); expect(diagnostics.body).toContain('public-key-id'); expect(diagnostics.body).not.toContain('NEVER-JWKS');
    } finally { await f.app.close(); }
  });
  it('shows visible confirmation after successful mutations', async () => {
    const f = await fixture();
    try {
      await f.reauth(); const response = await f.post('/admin/accounts/target', { _csrf: f.token, action: 'ban', confirm: 'CONFERMA' });
      expect(response.headers.location).toBe('/admin/accounts/target?notice=saved');
      const result = await f.app.inject({ url: String(response.headers.location), headers: f.headers });
      expect(result.body).toContain('Operazione completata e registrata');
    } finally { await f.app.close(); }
  });
  it('does not offer self privilege assignment or removal', async () => {
    const f = await fixture();
    try {
      await f.reauth(); const response = await f.app.inject({ url: '/admin/accounts/actor', headers: f.headers });
      for (const action of ['global-grant', 'global-revoke', 'service-grant', 'service-revoke']) expect(response.body).not.toContain(`value="${action}"`);
      expect(response.body).toContain('tuoi stessi privilegi');
      expect(response.body).toContain('value="revoke-consent"');
    } finally { await f.app.close(); }
  });
  it('does not offer self privilege edits but preserves service consent actions', async () => {
    const f = await fixture();
    try {
      await f.reauth(); const response = await f.app.inject({ url: '/admin/accounts/actor', headers: f.headers });
      for (const action of ['global-grant', 'global-revoke', 'service-grant', 'service-revoke']) expect(response.body).not.toContain(`value="${action}"`);
      expect(response.body).toContain('Revoca consenso · assigned');
      expect(response.body).toContain('tuoi stessi privilegi');
    } finally { await f.app.close(); }
  });
});
