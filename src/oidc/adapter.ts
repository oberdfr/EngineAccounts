import { errors, type AdapterPayload, type Provider } from 'oidc-provider';
import type { Config } from '../config.js';
import type { AccountsStore, OidcEntry, OidcTokenStore } from '../domain/ports.js';
import type { ClientRecord, User } from '../domain/types.js';
import { verifyPassword } from '../security/password.js';
import type { ArgonConfig } from '../security/argon.js';
import { validateClientApplication } from './native-client.js';

/**
 * Adapter di persistenza per oidc-provider.
 *
 * E' l'unico punto in cui i tipi della libreria entrano nel servizio. Tutto il
 * resto parla con `OidcTokenStore` e `ClientRecord`, che sono nostri
 * (ADR-0008: l'adapter resta nostro e dietro un'interfaccia sottile).
 *
 * `Adapter` e' una fabbrica per **nome modello**. Ogni modello e' una tabella
 * diversa, ma l'implementazione e' generica: la libreria non deve sapere
 * niente del nostro schema.
 */

interface ModelRoute {
  kind: 'codes' | 'tokens' | 'grants' | 'sessions' | 'interactions' | 'replay';
}

/** Modello della libreria -> tabella nostra. */
const ROUTES: Record<string, ModelRoute> = {
  AccessToken: { kind: 'tokens' },
  AuthorizationCode: { kind: 'codes' },
  RefreshToken: { kind: 'tokens' },
  DeviceCode: { kind: 'codes' },
  BackchannelAuthenticationRequest: { kind: 'codes' },
  PreAuthorizedCode: { kind: 'codes' },
  PushedAuthorizationRequest: { kind: 'codes' },
  ClientCredentials: { kind: 'tokens' },
  InitialAccessToken: { kind: 'tokens' },
  RegistrationAccessToken: { kind: 'tokens' },
  Grant: { kind: 'grants' },
  Session: { kind: 'sessions' },
  Interaction: { kind: 'interactions' },
  ReplayDetection: { kind: 'replay' },
};

export function createAdapter(tokens: OidcTokenStore): (name: string) => TokenAdapter {
  return (name: string) => new TokenAdapter(name, tokens);
}

/**
 * Grace window del refresh token, in secondi.
 *
 * `rotateRefreshToken: true` consuma il vecchio RT a ogni rinnovo e il riuso
 * successivo revoca **l'intera famiglia** (reuse detection). Due schede sullo
 * stesso RT, o un retry dopo un timeout in cui il server aveva gia' risposto,
 * sono riusi legittimi: senza grace window costano la sessione. Entro 30 s il
 * riuso riceve la **stessa** risposta idempotente (stesso successore gia'
 * emesso, nuovo access token dello stesso grant); oltre, la reuse detection
 * resta attiva e revoca la famiglia.
 */
export const REFRESH_TOKEN_GRACE_SECONDS = 30;

/** Contesto minimo di `oidc-provider` che serve alla grace (solo cio' che leggiamo). */
interface GraceCtx {
  oidc: {
    params?: Record<string, unknown>;
    client?: { clientId?: string; grantTypeAllowed?(grant: string): boolean };
    entities: Record<string, unknown>;
    provider?: unknown;
  };
}

/**
 * Grace window del rinnovo, dentro l'handler di `grant_type=refresh_token`.
 *
 * `oidc-provider` non ha una grace nativa: la libreria controlla
 * `refreshToken.consumed` e, se il token e' gia' stato usato, **revoca l'intera
 * famiglia**. Ma quel controllo arriva solo dopo la lettura dei parametri,
 * quindi l'unico punto con i parametri pronti e il token non ancora giudicato e'
 * l'handler del grant. Lo si sostituisce con l'**handler di produzione della
 * libreria stessa**, avvolto: `registerGrantType` e' l'API pubblica che la
 * libreria usa per installarlo, e ri-registrare lo stesso nome lo rimpiazza.
 *
 * Entro la grace il riuso e' **idempotente**: si presenta alla libreria il
 * successore gia' emesso (stesso RT in risposta, nuovo access token dello
 * stesso grant). Fuori dalla grace non si tocca nulla e la reuse detection fa
 * il suo lavoro.
 */
export async function wrapRefreshTokenGrant(provider: Provider): Promise<void> {
  const { handler } = await import('oidc-provider/lib/actions/grants/refresh_token.js' as string) as {
    handler: (provider: Provider, helpers: Record<string, unknown>, ctx: GraceCtx) => Promise<unknown>;
  };
  const grantHelpers = await import('oidc-provider/lib/helpers/grants.js' as string) as Record<string, unknown>;
  // Come `initializeApp`: ogni helper legato al provider. Sono quelli che
  // l'handler usa (`validateLegacyScope`, `openidScope`, `issueIdToken`, ...).
  const bound = Object.fromEntries(Object.entries(grantHelpers)
    .map(([name, fn]) => [name, (fn as (...args: unknown[]) => unknown).bind(undefined, provider)]));
  provider.registerGrantType('refresh_token', async (ctx) => {
    await resumeAfterConsumption(provider, ctx as unknown as GraceCtx);
    await handler(provider, bound, ctx as unknown as GraceCtx);
    // Dentro la grace la risposta e' **idempotente**: la si riporta al
    // successore presentato (la libreria, per sicurezza, lo ruota comunque).
    const answered = takenSuccessor.get(ctx as unknown as object);
    if (answered) {
      takenSuccessor.delete(ctx as unknown as object);
      const body = ctx.body as Record<string, unknown> | undefined;
      if (body && typeof body === 'object') body.refresh_token = answered;
    }
  }, new Set(['refresh_token', 'scope']), new Set(['resource']));
}

/**
 * **Sliding della sessione** (`Session`/`Grant`), complemento del Fix D.
 *
 * `oidc-provider` non ha una sessione scorrevole: calcola `exp` la prima volta
 * e lo conserva, quindi un utente attivo verrebbe disconnesso comunque allo
 * scadere del TTL. Qui l'orizzonte viene riportato avanti a ogni **uso** della
 * sessione: `slideSessionExpiry` e' l'unica regola (pura, provabile senza
 * provider), applicata da `TokenAdapter.slide()` quando la libreria salva la
 * sessione. Il logout esplicito la distrugge come sempre.
 */
export function slideSessionExpiry(
  payload: { exp?: unknown },
  ttlSeconds: number,
  nowMs = Date.now(),
): { exp: number; extended: boolean } {
  const now = Math.floor(nowMs / 1000);
  const target = now + Math.max(1, Math.floor(ttlSeconds));
  // Una `exp` non finita (NaN, Infinity) vale come assente: si ripristina.
  const current = typeof payload.exp === 'number' && Number.isFinite(payload.exp) ? payload.exp : undefined;
  // Mai accorciare (orologio del server all'indietro, TTL ridotto a caldo):
  // si estende solo se l'orizzonte scorrevole e' piu' avanti.
  const exp = current === undefined ? target : Math.max(current, target);
  return { exp, extended: exp !== current };
}

/** Successore ripresentato alla libreria dentro la grace, per richiesta. */
const takenSuccessor = new WeakMap<object, string>();

async function resumeAfterConsumption(provider: Provider, ctx: GraceCtx): Promise<void> {
  const presented = ctx.oidc.params?.refresh_token;
  const clientId = ctx.oidc.client?.clientId;
  const adapter = refreshTokenAdapter(provider);
  if (!adapter || typeof presented !== 'string' || !presented || typeof clientId !== 'string' || !clientId) return;
  const tokens = adapter.tokens;
  // Vivo: percorso normale, la libreria ruota da sola.
  const alive = await tokens.find('tokens', presented);
  if (alive && alive.consumed === undefined) return;
  const consumed = await tokens.findSuperseded(presented);
  if (!consumed || consumed.payload.kind !== 'RefreshToken') return;
  if (consumed.payload.clientId !== clientId || !consumed.grantId) return;
  if (consumed.revokedAt) return;
  // L'eta' del consumo: millisecondi registrati da `consume()`; il timestamp
  // della colonna e' il ripiego per righe anteriori al fix.
  const consumedAtMs = consumed.consumedAtMs ?? consumed.consumedAt?.getTime();
  if (typeof consumedAtMs !== 'number') return;
  const age = Date.now() - consumedAtMs;
  if (!(age >= 0 && age <= REFRESH_TOKEN_GRACE_SECONDS * 1000)) return;
  // Il successore: quello che la libreria ha gia' emesso per questo token.
  const successorId = adapter.successorOf(presented) ?? consumed.successorId;
  if (typeof successorId !== 'string' || !successorId || successorId === presented) return;
  const successor = await tokens.find('tokens', successorId);
  if (!successor || successor.kind !== 'RefreshToken') return;
  // Se il successore e' gia' stato consumato il client e' **avanti** (e non e'
  // un riuso da perdonare): la reuse detection fa il suo lavoro.
  if (successor.consumed !== undefined) return;
  if (successor.grantId !== consumed.grantId || successor.clientId !== clientId) return;
  if (typeof successor.exp === 'number' && successor.exp * 1000 <= Date.now()) return;
  // Entro la grace il riuso e' **idempotente**: si presenta alla libreria il
  // successore gia' emesso (stesso RT in risposta, nuovo access token dello
  // stesso grant). `TokenAdapter` ne ha registrato il legame su `consume()`.
  ctx.oidc.entities.RefreshToken = undefined;
  if (ctx.oidc.params) ctx.oidc.params.refresh_token = successorId;
  takenSuccessor.set(ctx as unknown as object, successorId);
}

/**
 * L'adapter del modello `RefreshToken` (`provider.RefreshToken.adapter`): e'
 * quello che ha scritto il legame di rotazione e conserva il successore.
 */
function refreshTokenAdapter(provider: Provider): TokenAdapter | undefined {
  const model = (provider as unknown as { RefreshToken?: { adapter?: unknown } }).RefreshToken;
  const adapter = model?.adapter;
  return adapter instanceof TokenAdapter ? adapter : undefined;
}

/** Adapter per i modelli che la libreria tratta come "oggetti" (token, code, grant). */
export class TokenAdapter {
  protected readonly route: ModelRoute;

  constructor(
    protected readonly name: string,
    readonly tokens: OidcTokenStore,
    private readonly accounts?: AccountsStore,
    private readonly eligible?: (user: User) => Promise<boolean>,
  ) {
    this.route = ROUTES[name] ?? { kind: 'tokens' };
  }

  protected kind(): OidcModelKindName {
    return this.route.kind;
  }

  /**
   * Rotazione dei refresh token, in memoria quanto basta.
   *
   * `oidc-provider` non offre un punto con entrambi gli id di una rotazione:
   * consuma il vecchio (`consume`) e in un secondo tempo salva il nuovo
   * (`upsert`). Le due metà del legame si raccolgono qui, senza toccare il
   * payload che la libreria rilegge:
   *   - `consumedIds`: chi e' stato consumato in questo processo. La libreria
   *     genera l'id del successore **prima** di consumare, quindi il `consume`
   *     che trova un id gia' noto e' quello del successore: li' il legame si
   *     chiude (`setSuccessor(consumato -> id)`);
   *   - `successors`: successore emesso per ciascun consumato, in memoria. E'
   *     quello che la grace restituisce in modo idempotente.
   *
   * Entrambe le cose non sono un problema di multi-processo: la grace risponde
   * **nei primi 30 secondi**, e il servizio gira in un solo processo (`node
   * dist/server.js`). Se un giorno ne girasse piu' di uno, il DB ha comunque
   * `oidc_tokens.payload.supersededBy` e `rotation.successor` come traccia.
   */
  private readonly consumedIds = new Set<string>();
  private readonly successors = new Map<string, string>();

  /** Il successore emesso per `id`, se questo processo lo conosce. */
  successorOf(id: string): string | undefined {
    return this.successors.get(id);
  }

  /** Attiva lo sliding della sessione (solo `Session`/`Grant`). */
  slide(ttlSeconds: () => number): void {
    if (this.route.kind === 'sessions' || this.route.kind === 'grants') this.slideTtl = ttlSeconds;
  }

  private slideTtl?: () => number;

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    await this.checkAccount(payload);
    /*
     * Sessione **scorrevole**: ogni scrittura del modello (la libreria la fa
     * quando la sessione viene usata) riporta l'orizzonte in avanti. `expiresIn`
     * va allineato, altrimenti lo store userebbe `exp - now` del valore vecchio.
     */
    let ttl = expiresIn;
    if (this.slideTtl && payload.kind === 'Session') {
      const { exp, extended } = slideSessionExpiry(payload as { exp?: unknown }, this.slideTtl());
      (payload as { exp?: number }).exp = exp;
      if (extended) ttl = Math.max(1, exp - Math.floor(Date.now() / 1000));
    }
    /*
     * Il successore di una rotazione e' salvato con `payload` **senza**
     * `consumed`; il predecessore, quando e' risalvato, arriva da `consume()`
     * (che scrive `consumed`). Quindi "il token salvato non ha `consumed` ma
     * uno e' stato consumato poco fa in questo processo" e' la firma del
     * successore: se ne annota il legame, che e' cio' che la grace usa.
     */
    const rotation = this.route.kind === 'tokens' && payload.kind === 'RefreshToken';
    if (rotation) {
      const pending = [...this.consumedIds].filter((consumed) => !this.successors.has(consumed));
      const predecessor = pending.length === 1 ? pending[0] : undefined;
      if (predecessor) {
        this.successors.set(predecessor, id);
        await this.tokens.setSuccessor('tokens', predecessor, id);
      }
    }
    await this.tokens.upsert(this.kind(), id, payload as OidcEntry, ttl);
  }

  async find(id: string): Promise<OidcEntry | undefined> {
    const payload = await this.tokens.find(this.kind(), id);
    if (payload) await this.checkAccount(payload);
    return payload;
  }

  private async checkAccount(payload: OidcEntry): Promise<void> {
    if (!this.accounts || !['AuthorizationCode', 'RefreshToken', 'AccessToken'].includes(this.name)) return;
    if (typeof payload.clientId === 'string') {
      const client = await this.accounts.findClient(payload.clientId);
      const services = await this.accounts.listServices();
      if (!client?.enabled || services.some((service) => service.audience === client.audience && !service.enabled)) {
        throw new errors.InvalidGrant('Client o servizio non disponibile');
      }
    }
    if (typeof payload.accountId !== 'string') return;
    const user = await this.accounts.findUserById(payload.accountId);
    if (!user || user.status !== 'active' || user.mustChangePassword) {
      throw new errors.InvalidGrant('Account non autorizzato: autenticazione richiesta');
    }
    if (this.eligible && !await this.eligible(user)) throw new errors.InvalidGrant('Account policy requires authentication');
  }

  async findByUid(uid: string): Promise<OidcEntry | undefined> {
    return this.tokens.findByUid(this.kind(), uid);
  }

  async findByUserCode(userCode: string): Promise<OidcEntry | undefined> {
    return this.tokens.findByUserCode(this.kind(), userCode);
  }

  async consume(id: string): Promise<void> {
    /*
     * Atomico nello store: un solo `UPDATE ... WHERE consumed_at IS NULL`.
     * Il secondo consumo non ha effetti — ed e' proprio il riuso che la reuse
     * detection deve vedere (fuori dalla grace la libreria revoca la famiglia).
     */
    await this.tokens.consume(this.kind(), id);
    if (this.route.kind === 'tokens') this.consumedIds.add(id);
  }

  async destroy(id: string): Promise<void> {
    await this.tokens.destroy(this.kind(), id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.tokens.revokeByGrantId(grantId);
  }

  get modelName(): string {
    return this.name;
  }
}

type OidcModelKindName = 'codes' | 'tokens' | 'grants' | 'sessions' | 'interactions' | 'replay';

/* -------------------------------------------------------------------------- */
/* Client: i client sono DATI, non codice (D2)                                  */
/* -------------------------------------------------------------------------- */

/**
 * Adapter del modello `Client`.
 *
 * I client vivono nella tabella `clients` e sono registrati dalla CLI. La
 * libreria li cerca qui quando risolve un `client_id`, e in questo modo
 * `Client.find()` funziona senza client statici in configurazione: aggiungere
 * un'applicazione alla suite non richiede di toccare il codice ne' riavviare.
 */
export class ClientAdapter {
  constructor(
    private readonly store: AccountsStore,
    private readonly config: Config,
    private readonly argon: ArgonConfig,
  ) {}

  async find(id: string): Promise<Record<string, unknown> | undefined> {
    const client = await this.store.findClient(id);
    if (!client || !client.enabled) return undefined;
    if ((await this.store.listServices()).some((service) => service.audience === client.audience && !service.enabled)) return undefined;
    return toClientMetadata(client, this.config);
  }

  async findByUid(): Promise<undefined> {
    return undefined;
  }

  async findByUserCode(): Promise<undefined> {
    return undefined;
  }

  async upsert(id: string, payload: Record<string, unknown>): Promise<void> {
    // Usato solo dalla registrazione dinamica, che e' disabilitata. Se arrivasse
    // comunque, il secret non verrebbe memorizzato in chiaro: si hasha.
    const secretHash =
      typeof payload.client_secret === 'string'
        ? await verifyClientSecretFor(payload.client_secret, this.argon)
        : null;
    await this.store.upsertClient({
      clientId: id,
      clientName: String(payload.client_name ?? id),
      clientType: payload.token_endpoint_auth_method === 'none' ? 'public' : 'confidential',
      clientSecretHash: secretHash,
      redirectUris: toStringArray(payload.redirect_uris),
      postLogoutRedirectUris: toStringArray(payload.post_logout_redirect_uris),
      grantTypes: toStringArray(payload.grant_types).length ? toStringArray(payload.grant_types) : ['authorization_code', 'refresh_token'],
      responseTypes: toStringArray(payload.response_types).length ? toStringArray(payload.response_types) : ['code'],
      scope: toStringArray(payload.scope),
      audience: typeof payload.audience === 'string' ? payload.audience : this.config.OIDC_AUDIENCE,
      backchannelEventsUri:
        typeof payload.backchannel_events_uri === 'string' ? payload.backchannel_events_uri : null,
      tokenEndpointAuthMethod:
        typeof payload.token_endpoint_auth_method === 'string'
          ? payload.token_endpoint_auth_method
          : 'client_secret_basic',
      enabled: true,
    });
  }

  async consume(): Promise<void> {
    throw new Error('i client sono dati: la registrazione dinamica e\' disabilitata');
  }

  async destroy(id: string): Promise<void> {
    // La registrazione dinamica e' disabilitata: si disabilita, non si cancella,
    // per non perdere lo storico dei token emessi a quel client.
    const client = await this.store.findClient(id);
    if (client) await this.store.upsertClient({ ...client, enabled: false });
  }

  async revokeByGrantId(): Promise<void> {
    /* niente da revocare: un client non ha grant */
  }
}

function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  if (typeof value === 'string') return value.split(' ').filter(Boolean);
  return [];
}

async function verifyClientSecretFor(plain: string, argon: ArgonConfig): Promise<string> {
  const { hashPassword } = await import('../security/password.js');
  return hashPassword(plain, argon);
}

/**
 * Traduce il record di dominio nel metadata OIDC che la libreria si aspetta.
 *
 * Nota sul segreto: qui non viene mai rimesso in chiaro. `secret_hash` e' un
 * metadata extra dichiarato in `extraClientMetadata.properties`, e il confronto
 * avviene in `patchClientSecretComparison` (vedi `provider.ts`). Nessun segreto
 * in chiaro attraversa il processo oltre il momento in cui la CLI lo genera.
 */
export function toClientMetadata(client: ClientRecord, _config: Config): Record<string, unknown> {
  validateClientApplication(client);
  return {
    client_id: client.clientId,
    client_name: client.clientName,
    // Client pubblici (SPA, TV): nessun secret, metodo di autenticazione `none`.
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    redirect_uris: client.redirectUris,
    post_logout_redirect_uris: client.postLogoutRedirectUris,
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    scope: client.scope.join(' '),
    application_type: client.applicationType ?? 'web',
    cors_origins: client.corsOrigins ?? [],
    // Metadata nostri: audience (RFC 8707), backchannel event (C11), hash del secret.
    audience: client.audience,
    ...(client.backchannelEventsUri ? { backchannel_events_uri: client.backchannelEventsUri } : {}),
    /*
     * Sul segreto, due fatti da tenere separati:
     *
     * 1. lo **schema** di `oidc-provider` pretende `client_secret` non vuoto per
     *    ogni client che usa un metodo di autenticazione con secret: senza, la
     *    validazione del metadata fallisce con `invalid_client_metadata` e il
     *    client diventa inutilizzabile anche per `/auth`;
     * 2. il confronto del segreto lo facciamo **noi**, in argon2id
     *    (`patchClientSecretComparison` in `provider.ts`): la libreria non
     *    confronta mai `clientSecret` con quello che arriva dalla richiesta.
     *
     * Quindi il campo che la libreria pretende contiene l'**hash**, non il
     * segreto: se per un errore di refactoring tornasse il confronto nativo
     * (confronto a tempo costante hash-vs-candidato) fallirebbe sempre, invece
     * di riuscire. Il segreto in chiaro non attraversa mai il processo.
     */
    ...(client.clientSecretHash
      ? { client_secret: client.clientSecretHash, secret_hash: client.clientSecretHash }
      : {}),
  };
}

/** Fabbrica unica: la libreria chiede l'adapter per nome modello. */
export function createFullAdapter(deps: {
  store: AccountsStore;
  tokens: OidcTokenStore;
  config: Config;
  argon: ArgonConfig;
  eligible?: (user: User) => Promise<boolean>;
}): (name: string) => TokenAdapter | ClientAdapter {
  return (name: string) =>
    name === 'Client'
      ? new ClientAdapter(deps.store, deps.config, deps.argon)
      : new TokenAdapter(name, deps.tokens, deps.store, deps.eligible);
}

export { verifyPassword };
