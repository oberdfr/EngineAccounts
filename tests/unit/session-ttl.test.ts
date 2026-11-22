import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { slideSessionExpiry } from '../../src/oidc/adapter.js';
import { SETTING_DEFAULTS } from '../../src/services/administration.js';
import { presentSessions } from '../../src/services/session-manager.js';

/**
 * Fix D dell'audit (`AUTH-AUDIT.md`): la vita reale dell'accesso era limitata
 * a 14 giorni dal `SESSION_TTL` (il refresh token pur essendo 30 giorni
 * moriva prima, perche' legato alla sessione), e nulla era scorrevole.
 *
 * Le regole testate qui:
 *  - default: access/id 15 minuti (restano corti: la revoca deve mordere in
 *    fretta), refresh token e sessione **90 giorni**;
 *  - sessione e refresh **scorrevoli**: a ogni uso l'orizzonte riparte;
 *  - il logout esplicito resta un revoca o distruzione esplicita, non un TTL.
 */

const GIORNI = 24 * 60 * 60;
/** Configurazione minima: la URL non viene mai aperta, serve solo a `loadConfig`. */
const BASE = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://test:test@127.0.0.1:1/test',
} as const;

describe('TTL: i default del servizio', () => {
  const config = loadConfig({ ...BASE } as NodeJS.ProcessEnv);

  it('access e id token restano 15 minuti', () => {
    expect(config.ACCESS_TOKEN_TTL).toBe(900);
    expect(config.ID_TOKEN_TTL).toBe(900);
  });

  it('refresh token e sessione: 90 giorni', () => {
    expect(config.REFRESH_TOKEN_TTL).toBe(90 * GIORNI);
    expect(config.SESSION_TTL).toBe(90 * GIORNI);
  });

  it('il refresh non muore prima della sessione (era il difetto a 14 giorni)', () => {
    expect(config.REFRESH_TOKEN_TTL).toBeGreaterThanOrEqual(config.SESSION_TTL);
  });

  it("`SESSION_TTL` modificabile dall'admin ha lo stesso default del servizio", () => {
    expect(SETTING_DEFAULTS.SESSION_TTL).toBe(config.SESSION_TTL);
  });

  it('.env puo\' ancora scegliere valori diversi, nei limiti', () => {
    const custom = loadConfig({
      ...BASE, SESSION_TTL: '2592000', REFRESH_TOKEN_TTL: '2592000',
    } as NodeJS.ProcessEnv);
    expect(custom.SESSION_TTL).toBe(30 * GIORNI);
    expect(custom.REFRESH_TOKEN_TTL).toBe(30 * GIORNI);
    expect(() => loadConfig({ ...BASE, REFRESH_TOKEN_TTL: '60' } as NodeJS.ProcessEnv)).toThrow();
  });
});

describe('sessione scorrevole: slideSessionExpiry', () => {
  const now = Date.parse('2026-06-01T12:00:00Z');
  const NOW = Math.floor(now / 1000);

  it('una sessione appena creata ha orizzonte pieno', () => {
    expect(slideSessionExpiry({}, 90 * GIORNI, now)).toEqual({ exp: NOW + 90 * GIORNI, extended: true });
  });

  it("a ogni uso l'orizzonte riparte da capo", () => {
    const usato = NOW + 30 * GIORNI;
    const { exp, extended } = slideSessionExpiry({ exp: now / 1000 + 90 * GIORNI }, 90 * GIORNI, usato * 1000);
    expect(exp).toBe(usato + 90 * GIORNI);
    expect(extended).toBe(true);
  });

  it("mai accorcia (orologio all'indietro o TTL ridotto a caldo)", () => {
    const avanti = NOW + 200 * GIORNI;
    expect(slideSessionExpiry({ exp: avanti }, 90 * GIORNI, now)).toEqual({ exp: avanti, extended: false });
  });

  it('una `exp` assente o invalida viene ripristinata', () => {
    expect(slideSessionExpiry({ exp: 'x' }, 90 * GIORNI, now).exp).toBe(NOW + 90 * GIORNI);
    expect(slideSessionExpiry({ exp: Number.NaN }, 90 * GIORNI, now).exp).toBe(NOW + 90 * GIORNI);
  });

  it('il TTL viene comunque arrotondato a un intero >= 1', () => {
    expect(slideSessionExpiry({}, 0.4, now).exp).toBe(NOW + 1);
  });
});

describe('sessione locale scorrevole: presentazione coerente', () => {
  const now = Date.parse('2026-06-01T12:00:00Z');
  const record = {
    id: 's1', userId: 'u1', tokenDigest: 'x', providerSessionId: null, providerSessionUid: null,
    deviceLabel: 'Chrome su Linux', ip: '127.0.0.1', userAgent: null, amr: ['pwd'],
    createdAt: new Date(now - 100 * GIORNI), lastSeenAt: new Date(now - 1_000),
    // La riga e' gia' stata spostata avanti dall'ultimo uso.
    expiresAt: new Date(now + 89 * GIORNI), revokedAt: null, revokeReason: null,
  } as never;

  it('una sessione usata di recente resta attiva anche oltre il vecchio tetto dei 14 giorni', () => {
    const view = presentSessions([record], 's1', now, 90 * GIORNI);
    expect(view.counts.active).toBe(1);
    expect(view.counts.expired).toBe(0);
  });

  it("la scadenza esposta non supera `creazione + TTL` (tetto del tetto)", () => {
    const view = presentSessions([record], 's1', now, 90 * GIORNI);
    expect(view.groups[0]!.sessions[0]!.expiresAt.getTime()).toBeLessThanOrEqual((now - 100 * GIORNI) + 90 * GIORNI * 1000);
  });

  it('una sessione revocata resta revocata, qualunque sia la scadenza', () => {
    const revoked = { ...(record as unknown as Record<string, unknown>), revokedAt: new Date(now - 5_000) } as never;
    const view = presentSessions([revoked], 's1', now, 90 * GIORNI);
    expect(view.counts.revoked).toBe(1);
    expect(view.counts.active).toBe(0);
  });
});
