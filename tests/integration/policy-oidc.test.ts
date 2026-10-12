import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, jwtVerify, type JWK } from 'jose';
import { confirmTotpEnrolment, currentTotpCode, startTotpEnrolment } from '../../src/services/mfa.js';
import { AdministrationService } from '../../src/services/administration.js';
import {
  HttpClient, TEST_AUDIENCE, TEST_CLIENT_ID, TEST_REDIRECT_URI,
  createTestUser, pkce, setupHarness, type Harness,
} from '../helpers/harness.js';

// Only the guarded harness: dedicated schema, synthetic JWKS, loopback port 0.
// Never follow the relying-party callback or contact the configured issuer port.
let h: Harness;
beforeAll(async () => {
  h = await setupHarness({ overrides: {
    DB_SCHEMA: 'engine_accounts_test',
    ENGINE_ACCOUNTS_JWKS_PATH: 'var/jwks-test.json',
    EMAIL_VERIFICATION_REQUIRED: 'true',
    REGISTRATION_MODE: 'closed',
  } });
  const client = (await h.store.findClient(TEST_CLIENT_ID))!;
  await h.store.upsertClient({ ...client, scope: [...client.scope, 'engine:admin'] });
}, 120_000);
afterAll(async () => { await h?.close(); });

function csrf(html: string): string {
  const value = /name="_csrf" value="([^"]+)"/.exec(html)?.[1];
  expect(value, 'form CSRF token').toBeTruthy();
  return value!;
}

async function begin(scope = 'openid profile email offline_access streaming:account') {
  const client = new HttpClient(h.baseUrl);
  const pair = pkce();
  const query = new URLSearchParams({
    response_type: 'code', client_id: TEST_CLIENT_ID, redirect_uri: TEST_REDIRECT_URI,
    resource: TEST_AUDIENCE, scope, state: 'policy-state', nonce: 'policy-nonce',
    prompt: 'consent', code_challenge: pair.challenge, code_challenge_method: 'S256',
  });
  const start = await client.get(`/auth?${query}`);
  const location = start.headers.get('location') ?? '';
  expect(location).toContain('/ui/interaction/');
  const uid = /\/ui\/interaction\/([^/?#]+)/.exec(location)?.[1];
  expect(uid).toBeTruthy();
  const html = await (await client.get(location)).text();
  return { client, pair, uid: uid!, csrf: csrf(html) };
}

async function noCredentialsIssued(sub: string) {
  expect(await h.store.listSessions(sub)).toHaveLength(0);
  for (const table of ['oidc_codes', 'oidc_tokens', 'oidc_sessions']) {
    const row = await h.db.one<{ count: string }>(
      `SELECT count(*)::text AS count FROM "engine_accounts_test"."${table}" WHERE account_id=$1`, [sub],
    );
    expect(row?.count, `${table}: no authenticated credentials before completion`).toBe('0');
  }
}

async function exchange(flow: Awaited<ReturnType<typeof begin>>, first: Response) {
  let response = first;
  let code = '';
  for (let hop = 0; hop < 12; hop++) {
    const location = response.headers.get('location');
    if (location) {
      const url = new URL(flow.client.resolve(location));
      if (url.origin + url.pathname === TEST_REDIRECT_URI) {
        expect(url.searchParams.get('error')).toBeNull();
        expect(url.searchParams.get('state')).toBe('policy-state');
        code = url.searchParams.get('code') ?? '';
        break;
      }
      response = await flow.client.get(location);
      continue;
    }
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(html).toContain('Autorizza');
    const uid = /action="\/ui\/interaction\/([^/]+)\/consent"/.exec(html)?.[1];
    expect(uid, 'actual consent interaction').toBeTruthy();
    response = await flow.client.postForm(`/ui/interaction/${uid}/consent`, { _csrf: csrf(html), decision: 'allow' });
  }
  expect(code, 'code only after completing login and consent').toBeTruthy();
  const tokens = await flow.client.postForm('/token', {
    grant_type: 'authorization_code', code, client_id: TEST_CLIENT_ID,
    redirect_uri: TEST_REDIRECT_URI, code_verifier: flow.pair.verifier,
  });
  expect(tokens.status).toBe(200);
  return await tokens.json() as { access_token: string; id_token: string; refresh_token: string };
}

async function verifiedPayload(token: string, audience: string) {
  const jwks = await (await new HttpClient(h.baseUrl).get('/jwks')).json() as { keys: JWK[] };
  return (await jwtVerify(token, createLocalJWKSet(jwks), {
    issuer: h.config.issuer, audience, algorithms: ['EdDSA', 'RS256'],
  })).payload;
}

describe('effective account policy through actual OIDC interactions', () => {
  it('puts audience roles only in the access JWT and reflects revocation on refresh', async () => {
    const user = await createTestUser(h);
    const administration = new AdministrationService(h);
    await administration.grant('admin:cli', 'streaming', user.id);
    const flow = await begin('openid engine:admin offline_access');
    const login = await flow.client.postForm(`/ui/interaction/${flow.uid}/login`, {
      _csrf: flow.csrf, email: user.email, password: user.password,
    });
    const tokens = await exchange(flow, login);
    expect((await verifiedPayload(tokens.access_token, TEST_AUDIENCE)).engine_roles).toEqual(['admin']);
    expect((await verifiedPayload(tokens.id_token, TEST_CLIENT_ID)).engine_roles).toBeUndefined();
    await administration.revoke('admin:cli', 'streaming', user.id);
    const refreshed = await flow.client.postForm('/token', {
      grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: TEST_CLIENT_ID,
    });
    expect(refreshed.status).toBe(200);
    const next = await refreshed.json() as { access_token: string };
    expect((await verifiedPayload(next.access_token, TEST_AUDIENCE)).engine_roles).toBeUndefined();
  });
  it.each([false, true])('must-change blocks code/session until a different password; enrolled MFA=%s', async (mfa) => {
    const user = await createTestUser(h);
    let secret = '';
    if (mfa) {
      ({ secret } = await startTotpEnrolment(h.store, h.config, user));
      expect(await confirmTotpEnrolment(h.store, h.config, user.id, await currentTotpCode(secret))).toBe(true);
      await h.store.setTotpEnabled(user.id, true);
    }
    await h.store.updateUser(user.id, { mustChangePassword: true });
    const flow = await begin(mfa ? 'openid profile offline_access streaming:account' : undefined);
    const login = await flow.client.postForm(`/ui/interaction/${flow.uid}/login`, {
      _csrf: flow.csrf, email: user.email, password: user.password,
    });
    const forceUrl = `/ui/interaction/${flow.uid}/force-password-change`;
    expect(login.status).toBe(303);
    expect(login.headers.get('location')).toBe(forceUrl);
    await noCredentialsIssued(user.id);

    // Direct consent cannot bypass the pending password challenge.
    const bypass = await flow.client.postForm(`/ui/interaction/${flow.uid}/consent`, {
      _csrf: flow.csrf, decision: 'allow',
    });
    expect(bypass.headers.get('location') ?? '').not.toContain('code=');
    await noCredentialsIssued(user.id);

    for (const fields of [
      { currentPassword: 'incorrect-current-password', newPassword: 'DifferentStrongPassword123!', confirm: 'DifferentStrongPassword123!' },
      { currentPassword: user.password, newPassword: user.password, confirm: user.password },
      { currentPassword: user.password, newPassword: 'DifferentStrongPassword123!', confirm: 'MismatchStrongPassword123!' },
    ]) {
      const form = await flow.client.csrfFrom(forceUrl);
      const denied = await flow.client.postForm(forceUrl, { _csrf: form, ...fields });
      expect(denied.status).toBe(400);
      expect(denied.headers.get('location')).toBeNull();
      expect((await h.store.findUserById(user.id))?.mustChangePassword).toBe(true);
      await noCredentialsIssued(user.id);
    }

    let completed = await flow.client.postForm(forceUrl, {
      _csrf: await flow.client.csrfFrom(forceUrl), currentPassword: user.password,
      newPassword: 'DifferentStrongPassword123!', confirm: 'DifferentStrongPassword123!',
    });
    expect(completed.status).toBe(303);
    expect((await h.store.findUserById(user.id))?.mustChangePassword).toBe(false);
    if (mfa) {
      expect(completed.headers.get('location')).toBe(`/ui/interaction/${flow.uid}/mfa?method=totp`);
      await noCredentialsIssued(user.id);
      const mfaCsrf = await flow.client.csrfFrom(completed.headers.get('location')!);
      const denied = await flow.client.postForm(`/ui/interaction/${flow.uid}/mfa`, {
        _csrf: mfaCsrf, method: 'totp', code: 'not-an-otp',
      });
      expect(denied.status).toBe(401);
      await noCredentialsIssued(user.id);
      completed = await flow.client.postForm(`/ui/interaction/${flow.uid}/mfa`, {
        _csrf: csrf(await denied.text()), method: 'totp', code: await currentTotpCode(secret),
      });
      expect(completed.status).toBe(303);
    }
    const tokens = await exchange(flow, completed);
    const access = await verifiedPayload(tokens.access_token, TEST_AUDIENCE);
    const id = await verifiedPayload(tokens.id_token, TEST_CLIENT_ID);
    expect(access.sub).toBe(user.id);
    expect(id.amr).toEqual(mfa ? ['pwd', 'otp'] : ['pwd']);
    expect(id.engine_roles).toBeUndefined();
    expect(access.engine_roles).toBeUndefined();
    expect(access.email).toBe(mfa ? undefined : user.email);
    expect(access.email_verified).toBe(mfa ? undefined : true);
    expect(await h.store.listSessions(user.id)).toHaveLength(1);
  }, 60_000);

  it.each(['blocked', 'unverified'] as const)('rejects %s login without code, token or account session', async (status) => {
    const user = await createTestUser(h, { verified: status !== 'unverified' });
    if (status === 'blocked') await h.store.setUserStatus(user.id, 'blocked', 'test', 'system');
    const flow = await begin();
    const denied = await flow.client.postForm(`/ui/interaction/${flow.uid}/login`, {
      _csrf: flow.csrf, email: user.email, password: user.password,
    });
    expect(denied.status).toBe(401);
    expect(denied.headers.get('location')).toBeNull();
    await noCredentialsIssued(user.id);
  });

  it('closed registration remains neutral but creates no identity or email', async () => {
    const client = new HttpClient(h.baseUrl);
    const email = 'closed-registration-policy@example.test';
    const count = await h.store.countUsers();
    const sent = h.mailer.sent?.length;
    const response = await client.postForm('/ui/register', {
      _csrf: await client.csrfFrom('/ui/register'), email,
      password: 'RegistrationStrongPassword123!', displayName: 'Closed Test',
    });
    expect(response.status).toBe(303);
    expect(await h.store.findUserByEmail(email)).toBeUndefined();
    expect(await h.store.countUsers()).toBe(count);
    expect(h.mailer.sent?.length).toBe(sent);
  });

  it('disabling a service after client caching rejects refresh and explicit resource authorization', async () => {
    const user = await createTestUser(h);
    const flow = await begin();
    const login = await flow.client.postForm(`/ui/interaction/${flow.uid}/login`, {
      _csrf: flow.csrf, email: user.email, password: user.password,
    });
    const tokens = await exchange(flow, login);
    expect(tokens.refresh_token).toBeTruthy();
    await h.db.query(`UPDATE "engine_accounts_test"."services" SET enabled=false WHERE service_id='streaming'`);
    try {
      const refreshed = await flow.client.postForm('/token', {
        grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: TEST_CLIENT_ID,
      });
      expect(refreshed.status).toBeGreaterThanOrEqual(400);
      const error = await refreshed.json() as { error: string; access_token?: string };
      expect(['invalid_grant', 'invalid_client', 'invalid_target']).toContain(error.error);
      expect(error.access_token).toBeUndefined();

      const pair = pkce();
      const query = new URLSearchParams({ response_type: 'code', client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI, resource: TEST_AUDIENCE, scope: 'openid',
        code_challenge: pair.challenge, code_challenge_method: 'S256' });
      const denied = await flow.client.get(`/auth?${query}`);
      const location = denied.headers.get('location') ?? '';
      expect(location).not.toContain('code=');
      expect(location).not.toContain('/ui/interaction/');
      if (location) {
        const callback = new URL(flow.client.resolve(location));
        expect(callback.searchParams.get('error')).toBeTruthy();
      } else {
        expect(denied.status).toBeGreaterThanOrEqual(400);
      }
    } finally {
      await h.db.query(`UPDATE "engine_accounts_test"."services" SET enabled=true WHERE service_id='streaming'`);
    }
  }, 60_000);
});
