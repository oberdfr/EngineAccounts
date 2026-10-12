import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { accessTokenProfileClaims, findAccount, profileClaims, CORE_SCOPES } from '../../src/oidc/account-adapter.js';
import { TokenAdapter } from '../../src/oidc/adapter.js';
import { registerServiceAuthzRoute } from '../../src/services/service-authz.js';
import { SessionManager } from '../../src/services/session-manager.js';
import { hashPassword } from '../../src/security/password.js';
import { RateLimiter } from '../../src/security/rate-limit.js';
import type { AccountsStore, OidcTokenStore } from '../../src/domain/ports.js';
import type { ClientRecord, User } from '../../src/domain/types.js';
import type { Config } from '../../src/config.js';

const sub = '11111111-2222-3333-4444-555555555555';
const audience = 'https://service.example.test/api';
const argon = { ARGON2_MEMORY_KIB: 1024, ARGON2_ITERATIONS: 1, ARGON2_PARALLELISM: 1, PASSWORD_MAX_LENGTH: 128, PASSWORD_MIN_LENGTH: 12 };
const user = (patch: Partial<User> = {}): User => ({ id: sub, status: 'active', email: 'person@example.test', emailVerifiedAt: new Date(), updatedAt: new Date(), ...patch } as User);
const client = (patch: Partial<ClientRecord> = {}): ClientRecord => ({ clientId: 'machine', audience, enabled: true, scope: ['openid', 'engine:admin'], clientType: 'confidential', tokenEndpointAuthMethod: 'client_secret_basic', ...patch } as ClientRecord);
const store = (u = user(), c = client(), enabled = true): AccountsStore => ({
  findUserById: vi.fn(async () => u), findClient: vi.fn(async () => c),
  listServices: vi.fn(async () => [{ serviceId: 'service', audience, name: 'Service', enabled }]),
} as unknown as AccountsStore);
const limiter = () => new RateLimiter({ ipMax: 30, ipWindowMs: 60000, accountMax: 5, accountWindowMs: 60000, lockBaseMs: 1000, lockMaxMs: 60000 });

describe('engine:admin access-token-only additive roles', () => {
  it('is a core scope and adds audience-scoped admin/global roles', async () => {
    expect(CORE_SCOPES).toContain('engine:admin');
    const authorization = { rolesFor: vi.fn(async () => ['admin', 'global']) };
    const claims = await accessTokenProfileClaims(store(), { accountId: sub, clientId: 'machine', scope: 'engine:admin email', resourceServer: { audience } }, authorization);
    expect(claims).toEqual({ engine_roles: ['admin', 'global'], email: 'person@example.test', email_verified: true });
    expect(authorization.rolesFor).toHaveBeenCalledWith(sub, audience);
    expect(profileClaims(user(), 'openid email engine:admin')).not.toHaveProperty('engine_roles');
  });
  it.each([
    { scope: 'email' }, { clientId: 'unknown' }, { resourceServer: { audience: 'https://other.example.test' } },
  ])('does not add roles outside the granted scope/client/audience', async (patch) => {
    const s = store();
    if ('clientId' in patch) s.findClient = vi.fn(async () => undefined);
    expect(await accessTokenProfileClaims(s, { accountId: sub, clientId: 'machine', scope: 'engine:admin', resourceServer: { audience }, ...patch }, { rolesFor: async () => ['admin'] })).not.toHaveProperty('engine_roles');
  });
  it.each([{ status: 'blocked' }, { status: 'deleted' }, { mustChangePassword: true }] as Partial<User>[])(
    'refuses roles for an account requiring attention: %o', async (patch) => {
      expect(await accessTokenProfileClaims(store(user(patch)), { accountId: sub, clientId: 'machine', scope: 'engine:admin', resourceServer: { audience } }, { rolesFor: async () => ['admin'] })).toEqual({});
      expect(await findAccount(store(user(patch)), null, sub)).toBeUndefined();
    },
  );
  it('disabled services and clients and non-admin assignments do not yield roles', async () => {
    const token = { accountId: sub, clientId: 'machine', scope: 'engine:admin', resourceServer: { audience } };
    for (const s of [store(user(), client(), false), store(user(), client({ enabled: false })), store(user(), client({ scope: ['openid'] }))]) {
      expect(await accessTokenProfileClaims(s, token, { rolesFor: async () => ['admin'] })).toEqual({});
    }
    expect(await accessTokenProfileClaims(store(), token, { rolesFor: async () => [] })).toEqual({});
  });
});

describe('code/refresh issuance and session account rechecks', () => {
  it.each(['AuthorizationCode', 'RefreshToken', 'AccessToken'])('rejects a live disabled service or client for cached %s', async (name) => {
    const payload = { accountId: sub, clientId: 'machine' };
    for (const s of [store(user(), client(), false), store(user(), client({ enabled: false }))]) {
      const tokens = { find: vi.fn(async () => payload), upsert: vi.fn() } as unknown as OidcTokenStore;
      const adapter = new TokenAdapter(name, tokens, s);
      await expect(adapter.find('cached')).rejects.toMatchObject({ error: 'invalid_grant' });
      await expect(adapter.upsert('new', payload, 900)).rejects.toMatchObject({ error: 'invalid_grant' });
      expect(tokens.upsert).not.toHaveBeenCalled();
    }
  });
  it.each(['AuthorizationCode', 'RefreshToken', 'AccessToken'])('rejects stale blocked/must-change %s on read and write', async (name) => {
    for (const patch of [{ status: 'blocked' }, { mustChangePassword: true }] as Partial<User>[]) {
      const payload = { accountId: sub };
      const tokens = { find: vi.fn(async () => payload), upsert: vi.fn() } as unknown as OidcTokenStore;
      const adapter = new TokenAdapter(name, tokens, store(user(patch)));
      await expect(adapter.find('stale')).rejects.toMatchObject({ error: 'invalid_grant' });
      await expect(adapter.upsert('new', payload, 900)).rejects.toMatchObject({ error: 'invalid_grant' });
      expect(tokens.upsert).not.toHaveBeenCalled();
    }
  });
  it('does not resolve or create a blocked account session', async () => {
    const s = store(user({ status: 'blocked' }));
    s.findSessionByTokenDigest = vi.fn(async () => ({ userId: sub, expiresAt: new Date(Date.now() + 60000) } as never));
    s.createSession = vi.fn(); s.touchSession = vi.fn();
    const manager = new SessionManager({ store: s, tokens: {} as OidcTokenStore, config: { dataKey: Buffer.alloc(32), SESSION_TTL: 3600 } as Config });
    expect(await manager.resolve('synthetic-cookie')).toBeUndefined();
    await expect(manager.create({ userId: sub, amr: ['pwd'], ip: null, userAgent: null })).rejects.toThrow('Account non attivo');
    expect(s.createSession).not.toHaveBeenCalled(); expect(s.touchSession).not.toHaveBeenCalled();
  });
});

describe('machine authorization endpoint (isolated Fastify inject; no DB/server)', () => {
  async function fixture(patch: Partial<ClientRecord> = {}, u = user(), enabled = true) {
    const app = Fastify();
    const secret = 'synthetic-client-secret';
    const s = store(u, client({ clientSecretHash: await hashPassword(secret, argon), ...patch }), enabled);
    await registerServiceAuthzRoute(app, { store: s, argon, limiter: limiter(), authorization: { rolesFor: async () => ['admin', 'global'] } });
    const headers = { authorization: `Basic ${Buffer.from(`machine:${secret}`).toString('base64')}` };
    return { app, s, headers, payload: { sub, serviceId: 'service' } };
  }
  it('uses Basic hash verifier and returns only the authorization contract', async () => {
    const f = await fixture();
    try {
      const r = await f.app.inject({ method: 'POST', url: '/services/authz', headers: f.headers, payload: f.payload });
      expect(r.statusCode).toBe(200); expect(r.json()).toEqual({ admin: true, global: true, status: 'active' });
      expect(r.headers['set-cookie']).toBeUndefined(); expect(r.headers['cache-control']).toBe('no-store');
    } finally { await f.app.close(); }
  });
  it.each([{ origin: 'https://browser.test' }, { cookie: 'ea_sid=synthetic' }, { 'sec-fetch-site': 'same-origin' }])('rejects browser/session credentials %o', async (extra) => {
    const f = await fixture();
    try { expect((await f.app.inject({ method: 'POST', url: '/services/authz', headers: { ...f.headers, ...extra }, payload: f.payload })).statusCode).toBe(403); }
    finally { await f.app.close(); }
  });
  it.each([{ enabled: false }, { clientType: 'public' }, { scope: ['openid'] }] as Partial<ClientRecord>[])('rejects disabled/public/non-admin client %o', async (patch) => {
    const f = await fixture(patch);
    try { expect((await f.app.inject({ method: 'POST', url: '/services/authz', headers: f.headers, payload: f.payload })).statusCode).toBe(401); }
    finally { await f.app.close(); }
  });
  it('rejects wrong service/audience, wrong password and disabled service', async () => {
    const f = await fixture({ audience: 'https://wrong.example.test' });
    try {
      expect((await f.app.inject({ method: 'POST', url: '/services/authz', headers: f.headers, payload: f.payload })).statusCode).toBe(404);
      expect((await f.app.inject({ method: 'POST', url: '/services/authz', headers: { authorization: `Basic ${Buffer.from('machine:wrong').toString('base64')}` }, payload: f.payload })).statusCode).toBe(401);
    } finally { await f.app.close(); }
    const disabled = await fixture({}, user(), false);
    try { expect((await disabled.app.inject({ method: 'POST', url: '/services/authz', headers: disabled.headers, payload: disabled.payload })).statusCode).toBe(404); }
    finally { await disabled.app.close(); }
  });
  it.each([{ status: 'blocked' }, { status: 'deleted' }, { mustChangePassword: true }] as Partial<User>[])('never authorizes inactive/pending users %o', async (patch) => {
    const f = await fixture({}, user(patch));
    try {
      const r = await f.app.inject({ method: 'POST', url: '/services/authz', headers: f.headers, payload: f.payload });
      expect(r.json()).toEqual({ admin: false, global: false, status: patch.status ?? 'active' });
    } finally { await f.app.close(); }
  });
  it('rate limits repeated machine requests', async () => {
    const f = await fixture();
    try {
      for (let i = 0; i < 30; i++) await f.app.inject({ method: 'POST', url: '/services/authz', payload: f.payload });
      expect((await f.app.inject({ method: 'POST', url: '/services/authz', headers: f.headers, payload: f.payload })).statusCode).toBe(429);
    } finally { await f.app.close(); }
  });
});
