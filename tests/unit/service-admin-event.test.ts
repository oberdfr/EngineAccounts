import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { makeAccountDataPurgeEvent, verifyAccountDeletedEvent, ACCOUNT_DATA_PURGE } from '../../src/services/account-deleted-event.js';

const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused/unused', OIDC_EVENT_SIGNING_SECRET: 'synthetic-unit-test-signing-material' });
describe('service admin purge contract', () => {
  it('uses a distinct signing purpose, audience and event', async () => {
    const event = await makeAccountDataPurgeEvent('synthetic-sub', 'https://service.example/api', {
      issuer: config.issuer, signingKey: config.serviceAdminSigningKey, now: () => 1000,
    });
    const expected = { iss: config.issuer, aud: 'https://service.example/api', event: ACCOUNT_DATA_PURGE as typeof ACCOUNT_DATA_PURGE, now: 1001 };
    expect((await verifyAccountDeletedEvent(event, config.serviceAdminSigningKey, expected)).valid).toBe(true);
    expect((await verifyAccountDeletedEvent(event, config.eventSigningKey, expected)).valid).toBe(false);
    expect((await verifyAccountDeletedEvent(event, config.serviceAdminSigningKey, { ...expected, aud: 'https://other.example/api' })).valid).toBe(false);
    expect((await verifyAccountDeletedEvent(event, config.serviceAdminSigningKey, { ...expected, now: 1300 })).valid).toBe(false);
    expect((await verifyAccountDeletedEvent(event, config.serviceAdminSigningKey, { ...expected, now: 900 })).valid).toBe(false);
  });
  it('does not accept tampered subjects or deletion event confusion', async () => {
    const event = await makeAccountDataPurgeEvent('synthetic-sub', 'https://service.example/api', {
      issuer: config.issuer, signingKey: config.serviceAdminSigningKey,
    });
    expect((await verifyAccountDeletedEvent({ ...event, sub: 'other-sub' }, config.serviceAdminSigningKey,
      { iss: config.issuer, event: ACCOUNT_DATA_PURGE })).valid).toBe(false);
    expect((await verifyAccountDeletedEvent(event, config.serviceAdminSigningKey, { iss: config.issuer })).valid).toBe(false);
  });
  it('allows the base admin scope for multiple audiences', () => {
    const clients = ['one', 'two'].map((name) => ({ clientId: name, audience: `https://${name}.example/api`,
      redirectUris: [`https://${name}.example/callback`], scope: ['openid', 'engine:admin'] }));
    expect(loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused/unused', OIDC_CLIENTS_JSON: JSON.stringify(clients) }).OIDC_CLIENTS_JSON).toHaveLength(2);
  });
});
