import { describe, expect, it, vi } from 'vitest';
import { browserDescription, presentSessions, SessionManager } from '../../src/services/session-manager.js';
import type { SessionRecord } from '../../src/domain/types.js';
import type { AccountsStore, OidcTokenStore } from '../../src/domain/ports.js';
import type { Config } from '../../src/config.js';

const now = Date.now();
function record(id: string, patch: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id, userId: 'user', tokenDigest: 'secret-digest', providerSessionId: 'provider-secret', providerSessionUid: 'uid-secret',
    deviceLabel: 'Legacy device label', userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0', ip: '192.0.2.1', amr: ['pwd'],
    createdAt: new Date(now - 1_000), lastSeenAt: new Date(now - 100), expiresAt: new Date(now + 60_000),
    revokedAt: null, revokeReason: null, ...patch,
  };
}

describe('honest session presentation', () => {
  it('groups descriptive browser families but preserves every independent credential', () => {
    const result = presentSessions([
      record('first'), record('current', { userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0', ip: '192.0.2.2' }),
      record('firefox', { userAgent: 'Mozilla/5.0 (X11; Linux) Firefox/140.0' }),
      record('expired', { expiresAt: new Date(now) }),
      record('revoked', { revokedAt: new Date(now - 50), expiresAt: new Date(now - 20) }),
    ], 'current', now);
    expect(result.counts).toEqual({ total: 5, active: 3, expired: 1, revoked: 1, browserGroups: 2 });
    expect(result.groups[0]?.activeCount).toBe(2);
    expect(result.groups[0]?.sessions.map((s) => s.id)).toEqual(['current', 'first']);
    expect(result.groups[0]?.current).toBe(true);
    expect(result.history.map((s) => s.status).sort()).toEqual(['expired', 'revoked']);
    expect(JSON.stringify(result)).not.toMatch(/secret|tokenDigest|providerSession|userAgent|deviceLabel/);
  });

  it('honors shortened effective session lifetime and treats the expiration boundary as expired', () => {
    const result = presentSessions([record('current', { createdAt: new Date(now - 2_000) })], 'current', now, 2);
    expect(result.counts.expired).toBe(1);
    expect(result.counts.active).toBe(0);
    expect(result.history[0]?.expiresAt.getTime()).toBe(now);
  });

  it('handles absent and iOS browser user agents without asserting a distinct device', () => {
    expect(browserDescription(null)).toEqual({ browser: 'Browser', platform: 'Sistema sconosciuto', label: 'Browser su Sistema sconosciuto' });
    expect(browserDescription('Mozilla/5.0 (iPhone) CriOS/140.0 Safari/604.1').browser).toBe('Chrome');
    expect(browserDescription('Mozilla/5.0 (iPad) FxiOS/140.0 Safari/604.1').browser).toBe('Firefox');
    expect(browserDescription('Mozilla/5.0 (Windows) Chrome/140.0 Edg/140.0').browser).toBe('Edge');
  });
});

describe('standalone credential reuse', () => {
  function manager(session = record('current')) {
    const store = {
      findSessionByTokenDigest: vi.fn().mockResolvedValue(session),
      findUserById: vi.fn().mockResolvedValue({ id: 'user', status: 'active', mustChangePassword: false }),
      touchSession: vi.fn(),
    } as unknown as AccountsStore;
    return new SessionManager({ config: { dataKey: Buffer.alloc(32, 1) } as Config, store, tokens: {} as OidcTokenStore });
  }

  it('reuses only an authenticated same-account credential with unchanged assurance', async () => {
    const sessions = manager();
    expect((await sessions.reusableStandalone('opaque', 'user', ['pwd']))?.id).toBe('current');
    expect(await sessions.reusableStandalone('opaque', 'other-user', ['pwd'])).toBeUndefined();
    expect(await sessions.reusableStandalone('opaque', 'user', ['pwd', 'otp'])).toBeUndefined();
    expect(await sessions.reusableStandalone(undefined, 'user', ['pwd'])).toBeUndefined();
  });

  it('does not reuse expired or revoked credentials', async () => {
    expect(await manager(record('old', { expiresAt: new Date(0) })).reusableStandalone('opaque', 'user', ['pwd'])).toBeUndefined();
    expect(await manager(record('old', { revokedAt: new Date() })).reusableStandalone('opaque', 'user', ['pwd'])).toBeUndefined();
  });

  it('all-other revocation preserves shared provider linkage of the retained credential', async () => {
    const current = record('current');
    const shared = record('shared');
    const independent = record('independent', { providerSessionId: 'other-provider', providerSessionUid: 'other-uid' });
    const records = new Map([current, shared, independent].map((s) => [s.id, s]));
    const revokeAllSessions = vi.fn().mockResolvedValue(['shared', 'independent']);
    const store = { findSession: vi.fn(async (id: string) => records.get(id)), revokeAllSessions } as unknown as AccountsStore;
    const destroyProviderSession = vi.fn();
    const revokeUserGrants = vi.fn();
    const sessions = new SessionManager({
      config: { dataKey: Buffer.alloc(32, 1) } as Config, store,
      tokens: { destroyProviderSession, revokeUserGrants } as unknown as OidcTokenStore,
    });
    expect(await sessions.revokeAll('user', 'user_revoked_all', 'current')).toBe(2);
    expect(revokeAllSessions).toHaveBeenCalledWith('user', 'user_revoked_all', 'current');
    expect(destroyProviderSession).toHaveBeenCalledExactlyOnceWith('other-provider');
    expect(revokeUserGrants).toHaveBeenCalledExactlyOnceWith('user', 'other-uid');
  });
});
