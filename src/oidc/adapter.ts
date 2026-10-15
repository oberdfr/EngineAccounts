import { errors, type AdapterPayload } from 'oidc-provider';
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

/** Adapter per i modelli che la libreria tratta come "oggetti" (token, code, grant). */
export class TokenAdapter {
  protected readonly route: ModelRoute;

  constructor(
    protected readonly name: string,
    protected readonly tokens: OidcTokenStore,
    private readonly store?: AccountsStore,
    private readonly eligible?: (user: User) => Promise<boolean>,
  ) {
    this.route = ROUTES[name] ?? { kind: 'tokens' };
  }

  protected kind(): OidcModelKindName {
    return this.route.kind;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    await this.checkAccount(payload);
    await this.tokens.upsert(this.kind(), id, payload as OidcEntry, expiresIn);
  }

  async find(id: string): Promise<OidcEntry | undefined> {
    const payload = await this.tokens.find(this.kind(), id);
    if (payload) await this.checkAccount(payload);
    return payload;
  }

  private async checkAccount(payload: OidcEntry): Promise<void> {
    if (!this.store || !['AuthorizationCode', 'RefreshToken', 'AccessToken'].includes(this.name)) return;
    if (typeof payload.clientId === 'string') {
      const client = await this.store.findClient(payload.clientId);
      const services = await this.store.listServices();
      if (!client?.enabled || services.some((service) => service.audience === client.audience && !service.enabled)) {
        throw new errors.InvalidGrant('Client o servizio non disponibile');
      }
    }
    if (typeof payload.accountId !== 'string') return;
    const user = await this.store.findUserById(payload.accountId);
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
    await this.tokens.consume(this.kind(), id);
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
