import { describe, expect, it } from 'vitest';
import { accessTokenProfileClaims, resourceServerFor } from '../../src/oidc/account-adapter.js';
import type { AccountsStore } from '../../src/domain/ports.js';
import type { ClientRecord, ServiceRecord, User } from '../../src/domain/types.js';

/**
 * I claim dell'access token, al livello della funzione.
 *
 * L'integrazione (`tests/integration/access-token-claims.test.ts`) prova il
 * token firmato che esce davvero dal provider; qui si isolano i rifiuti, quelli
 * che devono valere **prima** di firmare: nessuna query su un account che non
 * esiste, nessun claim fuori dallo scope concesso, nessuna stringa inventata al
 * posto di un indirizzo che l'utente non ha.
 *
 * `email` e' dato personale: il caso peggiore non e' perderlo, e' espanderlo a
 * chi non lo ha chiesto o inventarlo.
 */

const SUB = '11111111-2222-3333-4444-555555555555';

function user(overrides: Partial<User> = {}): User {
  return {
    id: SUB,
    email: 'persona@example.test',
    passwordHash: '$argon2id$vuoto$',
    displayName: 'Persona di Test',
    emailVerifiedAt: new Date('2026-01-01T00:00:00Z'),
    status: 'active',
    blockedReason: null,
    totpEnabled: false,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
    lastLoginAt: null,
    deletedAt: null,
    failedLogins: 0,
    lockedUntil: null,
    ...overrides,
  };
}

/** Store finto: conta le query, cosi' si vede che non si legge nulla a caso. */
function storeWith(row: User | undefined, queries: string[]): AccountsStore {
  return {
    async findUserById(id: string) {
      queries.push(id);
      return row && row.id === id ? row : undefined;
    },
  } as unknown as AccountsStore;
}

describe('accessTokenProfileClaims', () => {
  it('con scope `email` restituisce `email` ed `email_verified`', async () => {
    const queries: string[] = [];
    const claims = await accessTokenProfileClaims(
      storeWith(user({ emailVerifiedAt: new Date('2026-01-02T00:00:00Z') }), queries),
      { accountId: SUB, scope: 'openid profile email streaming:account' },
    );
    expect(claims).toEqual({ email: 'persona@example.test', email_verified: true });
    expect(queries).toEqual([SUB]);
  });

  it('senza scope `email` non restituisce nulla e non legge il database', async () => {
    const queries: string[] = [];
    const store = storeWith(user(), queries);
    // Lo scope e' gia' stato concesso e ristretto: il token che arriva qui puo'
    // non chiedere l'email, e la risposta deve essere "niente", non "provo a
    // chiedere e poi vedo".
    expect(await accessTokenProfileClaims(store, { accountId: SUB, scope: 'openid profile streaming:account' })).toEqual({});
    // `email` dentro una parola piu' lunga non e' lo scope `email`.
    expect(await accessTokenProfileClaims(store, { accountId: SUB, scope: 'streaming:email' })).toEqual({});
    expect(queries, 'senza scope `email` nessuna query').toEqual([]);

    expect(await accessTokenProfileClaims(store, { accountId: SUB, scope: 'openid email' })).toEqual({
      email: 'persona@example.test',
      email_verified: true,
    });
    expect(queries, 'con scope `email` la query c\'e\'').toEqual([SUB]);
  });

  it('non restituisce `sub`: il token lo mette la libreria', async () => {
    const claims = await accessTokenProfileClaims(storeWith(user(), []), {
      accountId: SUB,
      scope: 'email',
    });
    expect(claims).not.toHaveProperty('sub');
  });

  it('senza `accountId` (client credentials) non c\'e\' claim personale', async () => {
    const queries: string[] = [];
    const store = storeWith(user(), queries);
    expect(await accessTokenProfileClaims(store, { scope: 'openid profile email' })).toEqual({});
    expect(await accessTokenProfileClaims(store, { accountId: '', scope: 'email' })).toEqual({});
    expect(queries, 'nessuna query senza soggetto').toEqual([]);
  });

  it('un token senza `scope` non ottiene claim, anche con lo scope richiesto altrove', async () => {
    const claims = await accessTokenProfileClaims(storeWith(user(), []), { accountId: SUB });
    expect(claims).toEqual({});
  });

  it('account cancellato, bloccato o inesistente: nessun claim', async () => {
    for (const status of ['deleted', 'blocked'] as const) {
      const claims = await accessTokenProfileClaims(storeWith(user({ status }), []), {
        accountId: SUB,
        scope: 'email',
      });
      expect(claims, `status ${status}`).toEqual({});
    }
    expect(await accessTokenProfileClaims(storeWith(undefined, []), { accountId: SUB, scope: 'email' })).toEqual({});
  });

  it('un account senza indirizzo non riceve una stringa inventata', async () => {
    // `users.email` e' NOT NULL, quindi il caso non si verifica dal database:
    // il guard serve perche' il claim non deve mai dipendere da una
    // concatenazione, da un fallback o da un default. Il proxy dichiara `''`
    // quando il claim manca, e il chiamante deve poter distinguere "non so" da
    // "non ce l'ha".
    for (const email of ['', '   ']) {
      const claims = await accessTokenProfileClaims(storeWith(user({ email }), []), {
        accountId: SUB,
        scope: 'email',
      });
      expect(claims, `email ${JSON.stringify(email)}`).toEqual({});
      expect(claims).not.toHaveProperty('email');
    }
  });

  it('`email_verified` false resta false: il claim non viene promosso', async () => {
    const claims = await accessTokenProfileClaims(storeWith(user({ emailVerifiedAt: null }), []), {
      accountId: SUB,
      scope: 'email',
    });
    expect(claims).toEqual({ email: 'persona@example.test', email_verified: false });
  });
});

describe('resourceServerFor: gli scope dichiarati dalla risorsa', () => {
  const service: ServiceRecord = {
    serviceId: 'streaming',
    audience: 'https://api.engine.local/streaming',
    name: 'StreamingCommunityProxyApi',
    enabled: true,
  } as unknown as ServiceRecord;
  const client = { clientId: 'web', audience: service.audience, enabled: true } as unknown as ClientRecord;
  const store = {
    async listServiceScopes() {
      return [
        { scope: 'streaming:catalog', serviceId: 'streaming', description: 'catalogo' },
        { scope: 'streaming:playback', serviceId: 'streaming', description: 'playback' },
        { scope: 'streaming:account', serviceId: 'streaming', description: 'account' },
      ];
    },
  } as unknown as AccountsStore;

  it('dichiara gli scope di servizio e anche quelli core', async () => {
    const info = await resourceServerFor(store, [client], [service], service.audience, 'web');
    const declared = (info?.scope ?? '').split(' ').filter(Boolean);
    // Gli scope core devono restare: al refresh la libreria restringe lo scope
    // del token a quelli dichiarati qui, e senza di essi il token rinnovato
    // perderebbe `email` (e `/userinfo` risponderebbe solo `sub`).
    for (const scope of ['openid', 'profile', 'email', 'offline_access']) {
      expect(declared, `scope core ${scope} dichiarato`).toContain(scope);
    }
    for (const scope of ['streaming:catalog', 'streaming:playback', 'streaming:account']) {
      expect(declared, `scope di servizio ${scope} dichiarato`).toContain(scope);
    }
    expect(new Set(declared).size, 'nessuno scope duplicato').toBe(declared.length);
    expect(info?.accessTokenFormat).toBe('jwt');
    expect(info?.audience).toBe(service.audience);
  });

  it('non accetta un audience sconosciuto', async () => {
    expect(await resourceServerFor(store, [client], [service], 'https://altro.example/api')).toBeUndefined();
  });
});