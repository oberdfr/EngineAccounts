import { describe, expect, it } from 'vitest';
import { ensureDefaultClients } from '../../src/db/seed.js';
import { loadConfig, isAllowedBackchannelUri } from '../../src/config.js';
import type { Db } from '../../src/db/pool.js';

const client = {
  clientId: 'independent-app', clientName: 'Independent App',
  redirectUris: ['https://app.example.test/auth/callback'],
  postLogoutRedirectUris: ['https://app.example.test/'],
  scope: ['openid', 'profile', 'app:read'],
  audience: 'https://api.example.test',
  backchannelEventsUri: 'https://api.example.test/internal/events/account-deleted',
};
function config(value = JSON.stringify([client])) {
  return loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused/test', OIDC_CLIENTS_JSON: value });
}
async function capture(value?: string) {
  const calls: Array<{ text: string; values: unknown[] }> = [];
  const db = { schema: 'engine_accounts_test', async query(text: string, values: unknown[]) {
    calls.push({ text, values }); return [];
  } } as unknown as Db;
  await ensureDefaultClients(db, config(value));
  return calls;
}
describe('client pubblici dichiarati in .env', () => {
  it('permits loopback backchannel, requires TLS elsewhere and pins explicit HTTP origins', () => {
    expect(isAllowedBackchannelUri('http://127.0.0.1:8081/internal/events/account-deleted')).toBe(true);
    expect(isAllowedBackchannelUri('https://api.example.test/events')).toBe(true);
    expect(isAllowedBackchannelUri('http://api.example.test/events')).toBe(false);
    expect(isAllowedBackchannelUri('http://proxy:8081/events', 'http://proxy:8081')).toBe(true);
    expect(isAllowedBackchannelUri('http://proxy:8082/events', 'http://proxy:8081')).toBe(false);
    expect(isAllowedBackchannelUri('https://user:password@api.example.test/events')).toBe(false);
  });
  it('registra URI, scope, audience e backchannel senza domini nel codice', async () => {
    const calls = await capture();
    expect(calls).toHaveLength(3);
    expect(calls[2]!.values).toEqual([client.clientId, client.clientName, client.redirectUris,
      client.postLogoutRedirectUris, client.scope, client.audience, client.backchannelEventsUri]);
    expect(calls[2]!.text).toContain('ON CONFLICT (client_id) DO UPDATE SET');
    expect(calls[2]!.text).toContain("WHERE clients.client_type = 'public'");
    expect(calls[2]!.text).not.toContain('streaming.oberdfr.top');
  });
  it('Accounts senza consumer non semina alcun client', async () => {
    expect(await capture('[]')).toEqual([]);
  });
  it('registra scope di servizio prima del provider', async () => {
    expect((await capture())[1]!.values).toEqual(['app:read', client.audience]);
  });
  it.each(['not-json', '{}', JSON.stringify([{ ...client, redirectUris: [] }]),
    JSON.stringify([{ ...client, redirectUris: ['https://*.example.test/callback'] }]),
    JSON.stringify([{ ...client, scope: ['profile'] }]), JSON.stringify([client, client]),
    JSON.stringify([client, { ...client, clientId: 'other-app', audience: 'https://other.example.test' }])])(
    'rifiuta configurazione invalida: %s', (value) => {
      expect(() => config(value)).toThrow();
    });
});
