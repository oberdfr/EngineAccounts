import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import type { AdapterPayload } from 'oidc-provider';
import type { OidcEntry, OidcTokenStore } from '../../src/domain/ports.js';

/**
 * Grace window della rotazione del refresh token (audit `AUTH-AUDIT.md`, Fix C).
 *
 * Il difetto coperto: il riuso di un RT gia' consumato **entro pochi secondi**
 * — due schede, o un retry dopo un timeout in cui il server aveva gia'
 * risposto — revocava l'intera famiglia (`invalid_grant` da li' in poi) e
 * disconnetteva l'utente.
 *
 * Il test e' end-to-end sul **vero** `oidc-provider`: il **vero** adapter
 * (`createFullAdapter`) e il **vero** hook (`refreshGraceHook`) di
 * `src/oidc/adapter.ts`. Adapter e libreria condividono la stessa istanza,
 * perche' il modulo di `oidc-provider` e' lo stesso (import normale qui, e
 * `tsx` per caricare vecchio e nuovo modulo — sono due SPECCHI: `oidc-provider`
 * non ha side effect di registro, quindi le due istanze restano compatibili
 * solo se sono **la stessa**. Per questo l'adapter si carica con `import()`
 * dinamico, che qui risolve lo stesso pacchetto del test).
 *
 * Lo store e' in memoria, ma implementa `OidcTokenStore` con la stessa
 * semantica di quello su Postgres: `consume` atomico, `successor` e
 * `consumedAtMs` in colonna, flag di rotazione fuori dal payload.
 *
 * Il tempo e' **finto** (`vi.setSystemTime`): la grace e' una decisione sul
 * tempo, e aspettarla davvero renderebbe la suite lenta e casuale.
 */

/* -------------------------------------------------------------------------- */
/* Store in memoria con la semantica di quella su Postgres                     */
/* -------------------------------------------------------------------------- */

interface Row {
  payload: OidcEntry;
  grantId: string | null;
  consumedAtMs: number | null;
  revoked: boolean;
  successor?: string;
}

class MemoryTokenStore implements OidcTokenStore {
  readonly tokens = new Map<string, Row>();

  private row(id: string): Row {
    let row = this.tokens.get(id);
    if (!row) {
      row = { payload: {}, grantId: null, consumedAtMs: null, revoked: false };
      this.tokens.set(id, row);
    }
    return row;
  }

  async upsert(_kind: string, id: string, payload: OidcEntry): Promise<void> {
    const row = this.row(id);
    // `ON CONFLICT ... DO UPDATE` dello store reale: il payload vince, ma il
    // `consumed` scritto da `consume()` (che l'upsert della libreria non
    // porta) resta. `successor` e `consumedAtMs` sono colonne, fuori payload.
    row.payload = {
      ...payload,
      ...(typeof row.payload.consumed === 'number' && payload.consumed === undefined
        ? { consumed: row.payload.consumed }
        : {}),
    };
    row.grantId = typeof payload.grantId === 'string' ? payload.grantId : null;
    row.revoked = false;
  }

  async find(_kind: string, id: string): Promise<OidcEntry | undefined> {
    const row = this.tokens.get(id);
    if (!row || row.revoked) return undefined;
    return { ...row.payload };
  }

  async findByUid(): Promise<undefined> { return undefined; }
  async findByUserCode(): Promise<undefined> { return undefined; }

  async consume(_kind: string, id: string): Promise<void> {
    const row = this.tokens.get(id);
    // Atomico: il secondo consumo non tocca niente (`WHERE consumed_at IS NULL`).
    if (!row || row.revoked || typeof row.payload.consumed === 'number') return;
    row.payload = { ...row.payload, consumed: Math.floor(Date.now() / 1000) };
    row.consumedAtMs = Date.now();
  }

  async setSuccessor(_kind: string, id: string, successor: string): Promise<void> {
    const row = this.tokens.get(id);
    if (!row || row.successor) return; // il primo legame vince
    row.successor = successor;
  }

  async findSuperseded(id: string) {
    const row = this.tokens.get(id);
    if (!row) return undefined;
    return {
      payload: { ...row.payload },
      grantId: row.grantId,
      consumedAt: row.consumedAtMs === null ? null : new Date(row.consumedAtMs),
      consumedAtMs: row.consumedAtMs,
      revokedAt: row.revoked ? new Date() : null,
      successorId: row.successor ?? null,
    };
  }

  async destroy(_kind: string, id: string): Promise<void> {
    const row = this.tokens.get(id);
    if (row) row.revoked = true;
  }

  async revokeByGrantId(grantId: string): Promise<number> {
    let count = 0;
    for (const row of this.tokens.values()) {
      if (row.grantId === grantId && !row.revoked) { row.revoked = true; count++; }
    }
    return count;
  }

  async listGrantTokens() { return []; }
  async listUserTokens() { return []; }
  async revokeUserGrants() { return 0; }
  async destroyProviderSession() {}
  async findProviderSessionByUid() { return undefined; }
}

/* -------------------------------------------------------------------------- */
/* Provider reale, adapter nostro, tempo finto                                 */
/* -------------------------------------------------------------------------- */

const clientId = 'grace-test-rp';
const subject = 'grace-subject';
let store: MemoryTokenStore;
let provider: InstanceType<typeof import('oidc-provider').Provider>;
let server: Server;
let origin: string;

const client: OidcEntry = {
  clientId,
  clientName: clientId,
  clientType: 'public',
  clientSecretHash: null,
  redirectUris: ['https://rp.example.test/callback'],
  postLogoutRedirectUris: [],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scope: ['openid', 'offline_access'],
  audience: 'https://api.example.test',
  backchannelEventsUri: null,
  tokenEndpointAuthMethod: 'none',
  applicationType: 'web',
  corsOrigins: [],
  enabled: true,
};

beforeAll(async () => {
  store = new MemoryTokenStore();
  // L'adapter di produzione: stesso pacchetto `oidc-provider` del test.
  const { createFullAdapter, wrapRefreshTokenGrant } = await import('../../src/oidc/adapter.ts' as string) as {
    createFullAdapter: (deps: Record<string, unknown>) => (name: string) => unknown;
    wrapRefreshTokenGrant: (provider: unknown) => Promise<void>;
  };
  const { Provider } = await import('oidc-provider');
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  // Chiave di test sintetica: generata qui, mai scritta su disco.
  const key: JWK = { ...await exportJWK(privateKey), ...await exportJWK(publicKey),
    kid: 'grace-test-key', alg: 'EdDSA', use: 'sig' };
  provider = new Provider('https://issuer.example.test', {
    adapter: createFullAdapter({
      store: {
        findClient: async (id: string) => (id === clientId ? client : undefined),
        listServices: async () => [{ serviceId: 's', audience: client.audience, enabled: true }],
        findUserById: async (id: string) => (id === subject ? { id, status: 'active', mustChangePassword: false } : undefined),
      } as never,
      tokens: store,
      config: { cookieSecret: 'synthetic-test-cookie-secret-for-grace', secureCookies: false } as never,
      argon: { memoryCost: 8192, timeCost: 1, parallelism: 1 },
    }) as never,
    jwks: { keys: [key] } as never,
    // Gli stessi default del servizio (`provider.ts`): chiave EdDSA => id token EdDSA.
    clientDefaults: { id_token_signed_response_alg: 'EdDSA', response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none' },
    findAccount: (_ctx, id) => ({ accountId: id, async claims() { return { sub: id }; } }),
    rotateRefreshToken: true,
    features: { devInteractions: { enabled: false }, resourceIndicators: { enabled: false },
      userinfo: { enabled: false }, revocation: { enabled: true } },
    ttl: { Session: 3600, Grant: 3600, AccessToken: 900, RefreshToken: 3600, IdToken: 900, AuthorizationCode: 60 },
    claims: { openid: ['sub'] },
  });
  // Grace window: l'handler di `refresh_token` della libreria viene sostituito
  // da uno che, entro i 30 s, ripresenta il successore gia' emesso. E' l'unico
  // punto con i parametri pronti e il token non ancora giudicato.
  await wrapRefreshTokenGrant(provider);
  const callback = provider.callback();
  server = createServer((request, response) => { void callback(request, response); });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('porta di test non disponibile');
  origin = `http://127.0.0.1:${address.port}`;
}, 60_000);

afterAll(async () => {
  vi.useRealTimers();
  await new Promise<void>((resolve, reject) => server?.close((error) => (error ? reject(error) : resolve())));
});

/** Un refresh token emesso come farebbe il flusso: grant gia' autorizzato. */
async function issueRefreshToken(): Promise<string> {
  const model = (await provider.Client.find(clientId))!;
  const grant = new provider.Grant({ accountId: subject, clientId });
  grant.addOIDCScope('openid');
  const grantJti = await grant.save();
  const token = new provider.RefreshToken({ accountId: subject, client: model, grantId: grantJti, scope: 'openid', gty: 'authorization_code' } as never);
  return token.save();
}

/**
 * Rinnovo sul `tokenEndpoint` vero. Il middleware di grace si registra con
 * `provider.use()`, che agisce sulla catena Koa **interna**: qui esiste sempre
 * `ctx.oidc` (creato da `ensureOIDC` prima del router), mentre `use()` di un
 * provider esterno arriverebbe prima di quel wrapper e non vedrebbe `ctx.oidc`.
 */
async function refresh(token: string, clientIdUsed = clientId): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${origin}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token, client_id: clientIdUsed }).toString(),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

/** Avanza il tempo **finto**: store e adapter leggono lo stesso orologio. */
function advance(seconds: number): void {
  vi.setSystemTime(new Date(Date.now() + seconds * 1000));
}

/** Lo store vero, in memoria: i flag li legge dalla riga, non dal payload. */
function adapterOf(): { successorOf: (id: string) => string | undefined } {
  return (provider as unknown as { RefreshToken: { adapter: { successorOf(id: string): string | undefined } } }).RefreshToken.adapter;
}

void (null as unknown as AdapterPayload);

describe('rotazione del refresh token: grace window di 30 s', () => {
  it('ruota il token e annota il successore sul predecessore', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const rt0 = await issueRefreshToken();
    const first = await refresh(rt0);
    expect(first.status).toBe(200);
    const rt1 = String(first.body.refresh_token);
    expect(rt1).not.toBe(rt0);
    // Il legame `RT_n -> RT_n+1` e' il dato su cui si regge la grace.
    expect(store.tokens.get(rt0)?.successor).toBe(rt1);
    expect(store.tokens.get(rt0)?.consumedAtMs).toBe(Date.now());
    // Il payload che la libreria rilegge non si sporca dei flag interni.
    expect(store.tokens.get(rt0)?.payload.supersededBy).toBeUndefined();
  });

  it('entro 30 s il riuso riceve la STESSA risposta idempotente, senza revoca', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-02T00:00:00Z'));
    const rt0 = await issueRefreshToken();
    const first = await refresh(rt0);
    expect(first.status).toBe(200);
    const rt1 = String(first.body.refresh_token);

    advance(5);
    const retry = await refresh(rt0);
    expect(retry.status, 'schede sorelle / retry entro la grace: niente invalid_grant').toBe(200);
    // Stesso RT successore, nuovo access token dello stesso grant.
    expect(retry.body.refresh_token).toBe(rt1);
    expect(retry.body.access_token).toBeTruthy();
    expect(store.tokens.get(rt0)?.revoked).toBe(false);
    expect(store.tokens.get(rt1)?.revoked).toBe(false);
    // Il successore resta utilizzabile dal client che lo possiede.
    expect((await refresh(rt1)).status).toBe(200);
  });

  it("la grace e' inclusiva fino a 30 s e chiusa oltre: la reuse detection revoca la famiglia", async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-03T00:00:00Z'));
    const rt0 = await issueRefreshToken();
    const rt1 = String((await refresh(rt0)).body.refresh_token);

    vi.setSystemTime(new Date(Date.now() + 30_000));
    expect((await refresh(rt0)).status).toBe(200);

    vi.setSystemTime(new Date(Date.now() + 31_000));
    const late = await refresh(rt0);
    expect(late.status).toBe(400);
    expect(late.body.error).toBe('invalid_grant');
    // Oltre la grace e' riuso: la famiglia muore, incluso il successore.
    expect(store.tokens.get(rt1)?.revoked).toBe(true);
    expect((await refresh(rt1)).status).toBe(400);
  });

  it("se il successore e' gia' consumato il riuso NON viene perdonato", async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-04T00:00:00Z'));
    const rt0 = await issueRefreshToken();
    const rt1 = String((await refresh(rt0)).body.refresh_token);
    expect((await refresh(rt1)).status).toBe(200); // il client e' avanti: RT2

    advance(2);
    const replay = await refresh(rt0);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
  });

  it('un token presentato da un altro client non entra nella grace', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-05T00:00:00Z'));
    const rt0 = await issueRefreshToken();
    const rt1 = String((await refresh(rt0)).body.refresh_token);
    const other = await refresh(rt0, 'altro-client');
    expect(other.status).toBeGreaterThanOrEqual(400);
    // E la famiglia resta viva per il client legittimo.
    expect(store.tokens.get(rt1)?.revoked).toBe(false);
  });

  it("senza rotazione registrata (token mai consumato) non c'e' nessuna grace: si rinnova normalmente", async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-06T00:00:00Z'));
    const rt0 = await issueRefreshToken();
    expect(store.tokens.get(rt0)?.successor).toBeUndefined();
    const first = await refresh(rt0);
    expect(first.status).toBe(200);
    expect(first.body.refresh_token).not.toBe(rt0);
  });
});
