import { describe, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import type { Db } from '../../src/db/pool.js';
import type { Config } from '../../src/config.js';
import type { AccountsStore, OidcTokenStore } from '../../src/domain/ports.js';
import type { SessionManager } from '../../src/services/session-manager.js';
import { AdministrationService, guardLastGlobalAdmin, getEffectiveSettings, validateSetting, withGlobalAdminProtection } from '../../src/services/administration.js';

function fixture() {
  const query = vi.fn().mockResolvedValue([]);
  const one = vi.fn().mockResolvedValue(undefined);
  const clientQuery = vi.fn().mockResolvedValue({ rows: [] });
  const client = { query: clientQuery } as unknown as PoolClient;
  const db = { schema: 'unit_test', query, one, tx: vi.fn((fn) => fn(client)) } as unknown as Db;
  const config = { explicitEnvKeys: [], EMAIL_VERIFICATION_REQUIRED: false } as unknown as Config;
  const store = { appendAudit: vi.fn(), findUserById: vi.fn().mockResolvedValue({ id: 'target', status: 'active' }), listClients: vi.fn().mockResolvedValue([]) } as unknown as AccountsStore;
  const tokens = { revokeUserGrants: vi.fn() } as unknown as OidcTokenStore;
  const sessions = { revokeAll: vi.fn() } as unknown as SessionManager;
  return { db, query, one, client, clientQuery, config, store, tokens, sessions, admin: new AdministrationService({ db, config, store, tokens, sessions }) };
}
describe('administration isolated unit policy', () => {
  it('rejects detached last-admin guard and serializes protected writes', async () => {
    const f = fixture();
    await expect(guardLastGlobalAdmin(f.db, 'target')).rejects.toThrow('transaction client');
    f.clientQuery.mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ id: 'target' }] });
    const mutation = vi.fn();
    await expect(withGlobalAdminProtection(f.db, 'target', mutation)).rejects.toThrow('last_active_global_admin');
    expect(mutation).not.toHaveBeenCalled();
    expect(f.clientQuery.mock.calls[0]![0]).toContain('pg_advisory_xact_lock');
  });
  it('uses only transaction-local force override', async () => {
    const f = fixture();
    await guardLastGlobalAdmin(f.db, 'target', { client: f.client, force: true });
    expect(f.clientQuery.mock.calls[1]![0]).toContain("set_config('engine_accounts.force_admin','on',true)");
  });
  it('rejects role mutations from ordinary users, including force', async () => {
    const f = fixture();
    await expect(f.admin.setGlobalRole('user', 'target', true, { force: true })).rejects.toThrow('forbidden');
    expect(f.db.tx).not.toHaveBeenCalled();
  });
  it('never gives blocked global users administrative privileges', async () => {
    const f = fixture(); f.one.mockResolvedValue({ status: 'blocked', global: true });
    expect(await f.admin.authorization('user', 'service')).toEqual({ admin: false, global: false, status: 'blocked' });
  });
  it('block revokes own and provider sessions and grants with redacted audit', async () => {
    const f = fixture();
    await f.admin.mutateAccount('admin:cli', 'target', 'block', { reason: 'secret reason' });
    expect(f.sessions.revokeAll).toHaveBeenCalledWith('target', 'admin_block');
    expect(f.tokens.revokeUserGrants).toHaveBeenCalledWith('target');
    expect(f.store.appendAudit).toHaveBeenCalledWith(expect.objectContaining({ event: 'admin.account.block', metadata: {} }));
  });
  it('protects settings whitelist and strict ranges', () => {
    expect(() => validateSetting('SMTP_PASSWORD', 'secret')).toThrow('invalid_input');
    expect(() => validateSetting('EMAIL_VERIFICATION_REQUIRED', 'false')).toThrow('invalid_input');
    expect(() => validateSetting('PASSWORD_MIN_LENGTH', 7)).toThrow('invalid_input');
    expect(() => validateSetting('REGISTRATION_MODE', 'open')).not.toThrow();
    expect(() => validateSetting('REGISTRATION_MODE', 'unknown')).toThrow('invalid_input');
  });
  it('uses explicit env keys over DB over defaults, not ambient process.env', async () => {
    const f = fixture();
    f.config.explicitEnvKeys = ['EMAIL_VERIFICATION_REQUIRED'];
    f.config.EMAIL_VERIFICATION_REQUIRED = true;
    f.query.mockResolvedValue([{ key: 'EMAIL_VERIFICATION_REQUIRED', value: false }, { key: 'REGISTRATION_MODE', value: 'closed' }]);
    const settings = await getEffectiveSettings(f.db, f.config);
    expect(settings.find(s => s.key === 'EMAIL_VERIFICATION_REQUIRED')).toMatchObject({ value: true, source: 'env', editable: false });
    expect(settings.find(s => s.key === 'REGISTRATION_MODE')).toMatchObject({ value: 'closed', source: 'db' });
    expect(settings.find(s => s.key === 'ADMIN_MFA_REQUIRED')).toMatchObject({ value: true, source: 'default' });
  });
  it('parameterizes service-linked account search without unused placeholders', async () => {
    const f = fixture(); f.one.mockResolvedValue({ total: '0' });
    await f.admin.accounts({ q: "' OR true --", service: 'audience-service' });
    const [sql, values] = f.query.mock.calls[0]!;
    expect(sql).toContain('client_consents');
    expect(sql).not.toContain("' OR true --");
    expect(values).toEqual(["%' OR true --%", 'audience-service', 25, 0]);
  });
});
