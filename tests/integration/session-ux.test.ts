import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestUser, HttpClient, setupHarness, type Harness } from '../helpers/harness.js';
import { SessionManager, sessionCookieName } from '../../src/services/session-manager.js';

let h: Harness;
beforeAll(async () => { h = await setupHarness({ overrides: { DB_SCHEMA: 'engine_accounts_test' } }); });
afterAll(async () => { await h?.close(); });

describe('account session UX integration', () => {
  it('preserves history, renders account/profile, reuses standalone login, and revokes only other credentials', async () => {
    const user = await createTestUser(h);
    const sessions = new SessionManager({ config: h.config, store: h.store, tokens: h.tokens });
    const make = () => sessions.create({ userId: user.id, amr: ['pwd'], ip: '192.0.2.1', userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/140.0' });
    const current = await make();
    const other = await make();
    const expired = await make();
    await h.db.query(`UPDATE "engine_accounts_test"."sessions" SET expires_at = now() - interval '1 second' WHERE id = $1`, [expired.record.id]);
    const revoked = await make();
    await sessions.revoke(revoked.record.id, 'test_history', user.id);
    const overview = await sessions.overview(user.id, current.record.id);
    expect(overview.counts).toEqual({ total: 4, active: 2, expired: 1, revoked: 1, browserGroups: 1 });
    expect((await h.store.listSessions(user.id)).length).toBe(2);
    expect((await h.store.listSessions(user.id, true)).length).toBe(4);

    const client = new HttpClient(h.baseUrl);
    client.setCookie(sessionCookieName(h.config), current.cookieValue);
    for (const path of ['/account', '/account/profile', '/account/sessions']) {
      const page = await client.get(path);
      expect(page.status).toBe(200);
      expect(page.headers.get('cache-control')).toContain('no-store');
      const html = await page.text();
      expect(html).not.toContain(current.record.tokenDigest);
      expect(html).not.toContain('undefined');
    }
    const csrf = await client.csrfFrom('/account');
    const login = await client.postForm('/ui/login', { _csrf: csrf, email: user.email, password: user.password });
    expect(login.status).toBe(303);
    expect((await h.store.listSessions(user.id, true)).length).toBe(4);

    const outsider = await createTestUser(h);
    const foreign = await sessions.create({ userId: outsider.id, amr: ['pwd'], ip: null, userAgent: null });
    const forbidden = await client.postForm('/account/sessions/revoke', { _csrf: csrf, sessionId: foreign.record.id });
    expect(forbidden.status).toBe(404);
    expect((await h.store.findSession(foreign.record.id))?.revokedAt).toBeNull();
    expect((await client.postForm('/account/sessions/revoke-all', {})).status).toBe(403);
    const revoke = await client.postForm('/account/sessions/revoke-all', { _csrf: csrf });
    expect(revoke.status).toBe(303);
    expect(revoke.headers.get('location')).toBe('/account/sessions?revoked=all');
    expect(await sessions.resolve(current.cookieValue)).toBeDefined();
    expect(await sessions.resolve(other.cookieValue)).toBeUndefined();
    expect((await h.store.findSession(foreign.record.id))?.revokedAt).toBeNull();
  });
});
