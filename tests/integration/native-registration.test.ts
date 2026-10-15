import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { setupHarness, registerTestClientViaCli, testEnv, type Harness } from '../helpers/harness.js';

let h: Harness;
const id = 'streamingengine-android-test';
beforeAll(async () => {
  h = await setupHarness();
  const registration = registerTestClientViaCli(testEnv(), ['client', 'add', id, '--type', 'public',
    '--application-type', 'native', '--cors-origin', 'https://localhost',
    '--redirect-uri', 'streamingengine://auth/callback', '--post-logout-uri', 'streamingengine://',
    '--scope', 'openid,profile,email,offline_access,streaming:account',
    '--audience', 'https://api.engine.local/streaming']);
  expect(registration.status, registration.stdout).toBe(0);
});
afterAll(async () => { await h?.close(); });

describe('native registration and real provider transport, isolated test schema', () => {
  it('persists native policy and loads the custom scheme through oidc-provider validation', async () => {
    const stored = await h.store.findClient(id);
    expect(stored).toMatchObject({ applicationType: 'native', corsOrigins: ['https://localhost'], clientSecretHash: null });
    const client = await h.provider.Client.find(id);
    expect(client?.applicationType).toBe('native');
    expect(client?.redirectUriAllowed('streamingengine://auth/callback')).toBe(true);
    expect(client?.redirectUriAllowed('streamingengine://evil/callback')).toBe(false);
    expect(client?.postLogoutRedirectUriAllowed('streamingengine://')).toBe(true);
  });

  it.each([['https://localhost', true], ['null', false], ['https://evil.example', false]])(
    'allows token CORS only for the registered app origin: %s', async (origin, allowed) => {
      const response = await fetch(`${h.baseUrl}/token`, { method: 'POST', headers: { Origin: origin },
        body: new URLSearchParams({ client_id: id, grant_type: 'authorization_code', code: 'nonexistent-synthetic-code',
          code_verifier: 'a'.repeat(64), redirect_uri: 'streamingengine://auth/callback' }) });
      expect(response.headers.get('access-control-allow-origin')).toBe(allowed ? origin : null);
      expect(response.status).toBeGreaterThanOrEqual(400);
    });

  it('does not widen existing web clients to the native WebView origin', async () => {
    const response = await fetch(`${h.baseUrl}/token`, { method: 'POST', headers: { Origin: 'https://localhost' },
      body: new URLSearchParams({ client_id: 'streamingengine-web', grant_type: 'authorization_code', code: 'synthetic',
        code_verifier: 'a'.repeat(64), redirect_uri: 'http://localhost:5173/auth/callback' }) });
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });
});
