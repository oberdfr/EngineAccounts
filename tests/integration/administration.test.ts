import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import { setupHarness, createTestUser, CONF_CLIENT_ID, CONF_CLIENT_SECRET, type Harness } from '../helpers/harness.js';
import { AdministrationService } from '../../src/services/administration.js';
import { accessTokenProfileClaims } from '../../src/oidc/account-adapter.js';
import { serviceAuthorizationFromAdministration } from '../../src/services/service-authz.js';
import { table } from '../../src/db/pool.js';
import { createAccountDeletedEmitter, verifyAccountDeletedEvent, ACCOUNT_DATA_PURGE } from '../../src/services/account-deleted-event.js';
import http from 'node:http';

describe('administration isolated persistence and authorization', () => {
  let h: Harness;
  let admin: AdministrationService;
  let global: Awaited<ReturnType<typeof createTestUser>>;
  let assigned: Awaited<ReturnType<typeof createTestUser>>;
  beforeAll(async () => {
    h = await setupHarness();
    admin = new AdministrationService(h);
    global = await createTestUser(h);
    assigned = await createTestUser(h);
    await admin.setGlobalRole('admin:cli', global.id, true);
    await admin.grant('admin:cli', 'streaming', assigned.id);
    const confidential = (await h.store.findClient(CONF_CLIENT_ID))!;
    await h.store.upsertClient({ ...confidential, scope: [...confidential.scope, 'engine:admin'] });
  });
  afterAll(async () => { await h?.close(); });
  it('inherits roles and restricts assigned claims to token audience', async () => {
    expect(await admin.authorization(global.id, 'streaming')).toMatchObject({ admin: true, global: true, status: 'active' });
    expect(await admin.authorization(assigned.id, 'other')).toMatchObject({ admin: false, global: false });
    const authorization = serviceAuthorizationFromAdministration(admin);
    const resourceServer = { audience: h.client.audience };
    const token = { accountId: assigned.id, clientId: CONF_CLIENT_ID, scope: 'engine:admin', resourceServer };
    expect(await accessTokenProfileClaims(h.store, token, authorization)).toEqual({ engine_roles: ['admin'] });
    expect(await accessTokenProfileClaims(h.store, { ...token, accountId: global.id }, authorization)).toEqual({ engine_roles: ['admin', 'global'] });
    expect(await accessTokenProfileClaims(h.store, { ...token, resourceServer: { audience: 'https://other.example/api' } }, authorization)).toEqual({});
    expect(await accessTokenProfileClaims(h.store, { ...token, scope: 'openid' }, authorization)).toEqual({});
  });
  it('protects the last active global administrator on every DB path', async () => {
    await expect(admin.setGlobalRole('admin:cli', global.id, false)).rejects.toThrow('last_active_global_admin');
    await expect(admin.mutateAccount('admin:cli', global.id, 'ban')).rejects.toThrow('last_active_global_admin');
    await expect(h.store.setUserStatus(global.id, 'blocked', null, 'system')).rejects.toThrow('last_active_global_admin');
    const result = await h.accounts.deleteAccount(global.id, { password: global.password }, { ip: null, userAgent: null });
    expect(result.ok).toBe(false);
    expect((await h.store.findUserById(global.id))?.status).toBe('active');
  });
  it('denies admin resources anonymously, including POST', async () => {
    expect((await h.app.inject('/admin')).statusCode).toBe(404);
    expect((await h.app.inject('/admin/services/streaming')).statusCode).toBe(404);
    expect((await h.app.inject({ method: 'POST', url: '/admin/settings', payload: { action: 'set' } })).statusCode).toBe(404);
  });
  it('explains the MFA enrollment redirect to a promoted administrator', async () => {
    const session = await h.sessions.create({ userId: global.id, amr: ['pwd'], ip: null, userAgent: null });
    const headers = { cookie: `ea_sid=${session.cookieValue}` };
    const denied = await h.app.inject({ url: '/admin', headers });
    expect(denied.statusCode).toBe(403);
    expect(denied.body).toContain('Il ruolo amministrativo è assegnato');
    expect(denied.body).toContain('Configura MFA');
    const security = await h.app.inject({ url: '/account/security?admin=mfa-required', headers });
    expect(security.statusCode).toBe(200);
    expect(security.body).toContain('Per accedere all’Amministrazione');
    expect(security.body).toContain('TOTP oppure una passkey');
  });
  it('takes an authenticated home request directly to the account dashboard', async () => {
    const anonymous = await h.app.inject('/');
    expect(anonymous.statusCode).toBe(200);
    expect(anonymous.body).toContain('Accedi al tuo account');
    const session = await h.sessions.create({ userId: global.id, amr: ['pwd'], ip: null, userAgent: null });
    const signedIn = await h.app.inject({ url: '/', headers: { cookie: `ea_sid=${session.cookieValue}` } });
    expect(signedIn.statusCode).toBe(303);
    expect(signedIn.headers.location).toBe('/account');
    expect(signedIn.headers['cache-control']).toBe('no-store');
  });
  it('references an assigned administration area in the header, not the account profile or sidebar', async () => {
    const user = await createTestUser(h);
    await admin.grant('admin:cli', 'streaming', user.id);
    const session = await h.sessions.create({ userId: user.id, amr: ['pwd'], ip: null, userAgent: null });
    const profile = await h.app.inject({ url: '/account/profile', headers: { cookie: `ea_sid=${session.cookieValue}` } });
    expect(profile.statusCode).toBe(200);
    expect(profile.body.split('<main')[0]).toContain('/admin/services/streaming');
    const sidebar = /<nav class="sidebar account-sidebar"[^>]*>([^]*?)<\/nav>/.exec(profile.body)?.[1];
    expect(sidebar).toBeTruthy();
    expect(sidebar).not.toContain('/admin');
    expect(profile.body).not.toContain('<h3>Amministrazione servizi</h3>');
  });
  it('renders a local QR for TOTP and retains the pending key after a bad code', async () => {
    const user = await createTestUser(h);
    const session = await h.sessions.create({ userId: user.id, amr: ['pwd'], ip: null, userAgent: null });
    const headers = { cookie: `ea_sid=${session.cookieValue}` };
    const first = await h.app.inject({ url: '/account/security/totp/setup', headers });
    expect(first.statusCode).toBe(200);
    expect(first.body).toContain('Codice QR per configurare TOTP');
    expect(first.body).toContain('<svg');
    expect(first.headers['cache-control']).toBe('no-store');
    const pending = await h.store.getTotp(user.id);
    const repeated = await h.app.inject({ url: '/account/security/totp/setup?invalid=1', headers });
    expect(repeated.body).toContain('Codice non valido');
    expect((await h.store.getTotp(user.id))?.secretCt).toBe(pending?.secretCt);
  });
  it('provides passkey options and fails expired/cross-session registration honestly', async () => {
    const user = await createTestUser(h);
    const one = await h.sessions.create({ userId: user.id, amr: ['pwd'], ip: null, userAgent: null });
    const two = await h.sessions.create({ userId: user.id, amr: ['pwd'], ip: null, userAgent: null });
    const headers = { cookie: `ea_sid=${one.cookieValue}; ea_csrf=${'x'.repeat(32)}` };
    const setup = await h.app.inject({ url: '/account/security/webauthn/register', headers });
    expect(setup.statusCode).toBe(200);
    const embedded = /<script type="application\/json" id="wa-options">([^]*?)<\/script>/.exec(setup.body)?.[1];
    expect(embedded).toBeTruthy();
    expect(JSON.parse(embedded!).authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
    const posted = await h.app.inject({ method: 'POST', url: '/account/security/webauthn/verify',
      headers: { cookie: `ea_sid=${two.cookieValue}; ea_csrf=${'x'.repeat(32)}` },
      payload: { _csrf: 'x'.repeat(32), webauthnResponse: '{}' } });
    expect(posted.statusCode).toBe(303);
    expect(posted.headers.location).toBe('/account/security?error=passkey');
    expect(await h.store.listWebauthnCredentials(user.id)).toHaveLength(0);
    const error = await h.app.inject({ url: '/account/security?error=passkey', headers });
    expect(error.body).toContain('La passkey non è stata registrata');
  });
  it('authenticates a confidential client and immediately reflects role revocation', async () => {
    const headers = { authorization: `Basic ${Buffer.from(`${CONF_CLIENT_ID}:${CONF_CLIENT_SECRET}`).toString('base64')}` };
    const payload = { sub: assigned.id, serviceId: 'streaming' };
    let res = await h.app.inject({ method: 'POST', url: '/services/authz', headers, payload });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ admin: true, global: false, status: 'active' });
    await admin.revoke('admin:cli', 'streaming', assigned.id);
    res = await h.app.inject({ method: 'POST', url: '/services/authz', headers, payload });
    expect(res.json()).toEqual({ admin: false, global: false, status: 'active' });
    expect((await h.app.inject({ method: 'POST', url: '/services/authz', headers: { ...headers, origin: 'https://untrusted.example' }, payload })).statusCode).toBe(403);
    expect((await h.app.inject({ method: 'POST', url: '/services/authz', headers, payload: { ...payload, serviceId: 'other' } })).statusCode).toBe(404);
  });
  it('ban removes sessions and prevents new sessions', async () => {
    const user = await createTestUser(h);
    const session = await h.sessions.create({ userId: user.id, amr: ['pwd'], ip: null, userAgent: null });
    await admin.mutateAccount(global.id, user.id, 'ban');
    expect(await h.sessions.resolve(session.cookieValue)).toBeUndefined();
    await expect(h.sessions.create({ userId: user.id, amr: ['pwd'], ip: null, userAgent: null })).rejects.toThrow();
  });
  it('admin deletion verifies the actor rather than the target and reuses the tombstone path', async () => {
    const target = await createTestUser(h, { password: 'DifferentTargetPassword123!' });
    await expect(admin.setGlobalRole(global.id, global.id, false)).rejects.toThrow('forbidden');
    const denied = await h.accounts.deleteAccountAsAdmin(global.id, target.id, { password: target.password }, { ip: null, userAgent: null });
    expect(denied.ok).toBe(false);
    expect((await h.store.findUserById(target.id))?.status).toBe('active');
    const deleted = await admin.mutateAccount(global.id, target.id, 'delete', {
      accountService: h.accounts, reauth: { password: global.password },
    });
    expect(deleted.ok).toBe(true);
    const record = await h.store.findUserById(target.id);
    expect(record?.status).toBe('deleted');
    expect(record?.email).toMatch(/@deleted\.invalid$/);
    expect((await h.store.listAudit(target.id, 20)).some((entry) => entry.event === 'admin.account.delete')).toBe(true);
  });
  it('DB settings override defaults but never explicit env', async () => {
    await admin.setSetting(global.id, 'REGISTRATION_MODE', 'closed');
    expect((await admin.getSettings()).find((s) => s.key === 'REGISTRATION_MODE')).toMatchObject({ value: 'closed', source: 'db' });
    await expect(admin.setSetting(global.id, 'OIDC_EVENT_SIGNING_SECRET', 'never-save')).rejects.toThrow();
    await h.db.query(`DELETE FROM ${table(h.db, 'administration_settings')} WHERE key='REGISTRATION_MODE'`);
    await admin.setSetting(global.id, 'SESSION_TTL', 300);
    try {
      const short = await h.sessions.create({ userId: assigned.id, amr: ['pwd'], ip: null, userAgent: null });
      expect(short.maxAgeSeconds).toBe(300);
      // DB timestamps can differ by a few milliseconds from the application clock.
      expect(Math.abs(short.record.expiresAt.getTime() - short.record.createdAt.getTime() - 300_000)).toBeLessThan(1000);
    } finally {
      await h.db.query(`DELETE FROM ${table(h.db, 'administration_settings')} WHERE key='SESSION_TTL'`);
    }
  });
  it('queues purge, uses a distinct signature and retries the same idempotency key', async () => {
    const events: Record<string, unknown>[] = [];
    let status = 500;
    const receiver = http.createServer(async (req, res) => {
      const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
      events.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.statusCode = status; res.end();
    });
    await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
    const port = (receiver.address() as { port: number }).port;
    try {
      const emitter = createAccountDeletedEmitter(h.db, h.config);
      const service = { serviceId: 'streaming', audience: h.client.audience, adminApiUrl: `http://127.0.0.1:${port}/purge` };
      await h.db.query(`UPDATE ${table(h.db, 'services')} SET admin_api_url=$1 WHERE service_id='streaming'`, [service.adminApiUrl]);
      const queued = await emitter.emitDataPurge(assigned.id, service);
      expect(queued.failed).toBe(1);
      expect((await verifyAccountDeletedEvent(events[0], h.config.serviceAdminSigningKey,
        { iss: h.config.issuer, aud: h.client.audience, event: ACCOUNT_DATA_PURGE })).valid).toBe(true);
      expect((await verifyAccountDeletedEvent(events[0], h.config.eventSigningKey,
        { iss: h.config.issuer, event: ACCOUNT_DATA_PURGE })).valid).toBe(false);
      status = 409;
      expect((await emitter.flushPending()).delivered).toBe(1);
      expect(events[1]?.jti).toBe(queued.jti);
      const saved = await h.db.one<{ delivered_at: Date | null; attempts: number }>(`SELECT delivered_at,attempts FROM ${table(h.db, 'outbox_events')} WHERE jti=$1`, [queued.jti]);
      expect(saved?.delivered_at).toBeInstanceOf(Date);
      expect(saved?.attempts).toBe(2);
    } finally {
      await h.db.query(`UPDATE ${table(h.db, 'services')} SET admin_api_url=NULL WHERE service_id='streaming'`);
      await new Promise<void>((resolve, reject) => receiver.close((err) => err ? reject(err) : resolve()));
    }
  });
});
