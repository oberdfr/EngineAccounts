import type { AccountsStore } from '../domain/ports.js';
import type { ClientRecord, ScopeRecord, ServiceRecord, User } from '../domain/types.js';
import type { ServiceAuthorization } from '../services/service-authz.js';

/**
 * Adapter `findAccount`: il nostro "modello account".
 *
 * Restituisce solo `accountId` (l'UUID opaco e stabile) e i claim che il
 * contratto elenca: `name` con scope `profile`, `email`/`email_verified` con
 * scope `email`, piu' `amr` (metodo di autenticazione) e `email_verified` come
 * booleano.
 *
 * `sub` non e' mai l'email e non cambia mai, anche dopo un cambio email.
 */
export interface AccountAdapter {
  accountId: string;
  /** La libreria accetta campi extra sul modello account: li teniamo qui. */
  [key: string]: unknown;
  claims(
    use: string,
    scope: string,
    claims: Record<string, unknown>,
    rejected: string[],
  ): Promise<Record<string, unknown> & { sub: string }>;
}

/**
 * Adapter `findAccount`: il nostro "modello account".
 *
 * Restituisce `accountId` (l'UUID opaco e stabile) e i claim che il contratto
 * elenca: `name` con scope `profile`, `email`/`email_verified` con scope
 * `email`. `sub` non e' mai l'email e non cambia mai, nemmeno dopo un cambio
 * email o una cancellazione — e' la chiave che il proxy usa per i dati.
 */
export async function findAccount(
  store: AccountsStore,
  _ctx: unknown,
  sub: string,
  eligible?: (user: User) => Promise<boolean>,
): Promise<AccountAdapter | undefined> {
  const user = await store.findUserById(sub);
  // `undefined` = account inesistente: la libreria risponde 401 senza dire altro.
  if (!user || user.status !== 'active' || user.mustChangePassword) return undefined;
  if (eligible && !await eligible(user)) return undefined;

  return {
    accountId: sub,
    async claims(_use: string, scope: string) {
      return profileClaims(user, scope);
    },
  };
}

/**
 * Claim del profilo per un insieme di scope.
 *
 * Unica sorgente: la usano sia l'adapter `findAccount` (id token e userinfo della
 * libreria) sia il nostro endpoint `/userinfo` (`oidc/userinfo.ts`), cosi' i due
 * non possono divergere.
 */
export function profileClaims(user: User, scope: string): Record<string, unknown> & { sub: string } {
  const scopes = new Set(scope.split(' ').filter(Boolean));
  const out: Record<string, unknown> & { sub: string } = { sub: user.id };
  if (scopes.has('profile')) {
    out.name = user.displayName ?? user.email.split('@')[0]!;
    out.preferred_username = user.email;
    out.updated_at = Math.floor(user.updatedAt.getTime() / 1000);
  }
  if (scopes.has('email')) {
    out.email = user.email;
    out.email_verified = Boolean(user.emailVerifiedAt);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* claim dell'access token                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Claim che il provider mette **nell'access token**.
 *
 * **Perche' una funzione dedicata e non la `claims` map.** La mappa `claims` di
 * `oidc-provider` (vedi `provider.ts`) governa l'id token e `/userinfo`: e' la
 * lista dei claim *ammessi* per uno scope, usata per mascherare l'id token
 * (`conformIdTokenClaims`) e per la raccolta in userinfo. L'access token e'
 * costruito altrove — `lib/models/formats/jwt.js` mette nel payload
 * `...extra` piu' i claim standard — e `extra` arriva **solo** da
 * `configuration.extraTokenClaims`, il cui default della libreria restituisce
 * `undefined` (`lib/helpers/defaults.js`). Senza dichiararlo, quindi, nell'access
 * token non finisce nessun claim dello scope: il provider non rispetta la riga
 * del contratto «`email` | access, id | se `email` scope».
 *
 * Il proxy e' il caso che soffre: possiede il solo access token (il refresh non
 * e' firmato, D1), verifica la firma localmente con la JWKS cacheata e non puo'
 * fare una chiamata di rete a `/userinfo` per ogni richiesta. Mettere il claim
 * nel token e' la strada che rispetta il contratto **e** la scelta di non
 * aggiungere un hop nel perimetro del proxy.
 *
 * Minimo privilegio, due condizioni **entrambe** necessarie:
 *   1. lo scope `email` deve essere nei `scope` del token (non basta che il
 *      client sia registrato con quel permesso: conta cio' che l'utente ha
 *      effettivamente concesso);
 *   2. l'account deve esistere ed essere `active`.
 *
 * E il claim si spiega da solo in un caso limite: se l'utente non ha un
 * indirizzo utilizzabile, il claim **non c'e'**. Il proxy dichiara `''` e il
 * chiamante distingue «non autorizzato a saperlo» da «non ce l'ha», mentre una
 * stringa inventata sarebbe un dato falso con l'aria di essere vero.
 */
export async function accessTokenProfileClaims(
  store: AccountsStore,
  token: { accountId?: unknown; scope?: unknown; clientId?: unknown; resourceServer?: { audience?: unknown } },
  authorization?: ServiceAuthorization,
): Promise<Record<string, unknown>> {
  // `accountId` assente = nessun utente (client credentials, o un token senza
  // soggetto): niente claim personali.
  if (typeof token.accountId !== 'string' || token.accountId.length === 0) return {};
  const scope = typeof token.scope === 'string' ? token.scope : '';
  if (!scope.split(' ').some((s) => s === 'email' || s === 'engine:admin')) return {};
  const user = await store.findUserById(token.accountId);
  if (!user || user.status !== 'active' || user.mustChangePassword) return {};
  const out: Record<string, unknown> = {};
  if (scope.split(' ').includes('engine:admin') && typeof token.clientId === 'string' && authorization) {
    const client = await store.findClient(token.clientId);
    const audience = token.resourceServer?.audience;
    const service = (await store.listServices()).find((s) => s.enabled && s.audience === audience);
    if (client?.enabled && client.scope.includes('engine:admin') && client.audience === audience && service) {
      const roles = await authorization.rolesFor(user.id, service.audience);
      if (roles.includes('admin')) out.engine_roles = roles.includes('global') ? ['admin', 'global'] : ['admin'];
    }
  }
  if (!scope.split(' ').includes('email')) return out;
  // Solo un indirizzo **utilizzabile**: il valore esce dal database cosi' com'e'
  // (nessuna normalizzazione qui, nessuna ricostruzione), ma una stringa vuota
  // o solo spazi non e' un indirizzo e non viene pubblicata come se lo fosse.
  // Il controllo viene prima di `profileClaims` perche' li l'indirizzo viene
  // usato come fallback del nome: una riga mezza vuota non deve far fallire
  // l'emissione del token.
  if (typeof user.email !== 'string' || user.email.trim().length === 0) return out;

  // Unica sorgente dei claim: id token, `/userinfo` e access token non possono
  // divergere, per costruzione.
  const profile = profileClaims(user, scope);
  return { ...out, email: profile.email, email_verified: profile.email_verified === true };
}

/* -------------------------------------------------------------------------- */
/* risoluzione scope e risorse                                                 */
/* -------------------------------------------------------------------------- */

/** Scope di base: vivono nel core (contratto 3). */
export const CORE_SCOPES = ['openid', 'profile', 'email', 'offline_access', 'engine:admin'] as const;

/**
 * Scope supportati = base + righe di `streaming_scopes`. Nessun codice da
 * toccare per aggiungere un servizio: basta una riga (D2).
 */
export async function resolveSupportedScopes(store: AccountsStore): Promise<{ scopes: string[]; serviceScopes: ScopeRecord[] }> {
  const serviceScopes = await store.listServiceScopes();
  return {
    scopes: [...CORE_SCOPES, ...serviceScopes.map((s) => s.scope)],
    serviceScopes,
  };
}

/**
 * Resource server (RFC 8707). `getResourceServerInfo` viene chiamata dalla
 * libreria per ogni resource indicator: accettiamo solo audience registrati,
 * e l'`aud` dell'access token e' **sempre** quello registrato per il client,
 * mai quello richiesto dall'esterno.
 */
export async function resourceServerFor(
  store: AccountsStore,
  clients: ClientRecord[],
  services: ServiceRecord[],
  resource: string,
  clientId?: string,
): Promise<{ scope: string; audience: string; accessTokenFormat: 'jwt' } | undefined> {
  if (services.some((s) => s.audience === resource && !s.enabled)) return undefined;
  const known = new Set(services.filter((s) => s.enabled).map((s) => s.audience));
  for (const client of clients) {
    if (client.enabled) known.add(client.audience);
  }
  if (!known.has(resource)) return undefined;
  if (clientId) {
    const client = clients.find((c) => c.clientId === clientId);
    // Un client puo' chiedere solo il proprio audience: niente confused deputy.
    if (!client || !client.enabled || client.audience !== resource) return undefined;
  }
  const service = services.find((s) => s.audience === resource && s.enabled);
  /*
   * Scope della risorsa: quelli **di servizio** piu' gli scope core del
   * provider.
   *
   * Gli scope di servizio sono quelli che il proxy pubblica e con cui protegge
   * i suoi endpoint (`streaming:catalog|playback|account`).
   *
   * Gli scope core (`openid`, `profile`, `email`, `offline_access`) sono qui per
   * una ragione precisa: al **refresh** la libreria restringe lo `scope` del
   * nuovo access token agli scope *dichiarati* dalla risorsa
   * (`lib/actions/grants/refresh_token.js`: `getResourceScopeFiltered` filtrato
   * per `at.resourceServer.scopes`), mentre sul flusso authorization code non lo
   * fa. Dichiarando solo gli scope di servizio, il token rinnovato perdeva
   * `openid` ed `email`: il claim `email` spariva dopo 15 minuti (e `/userinfo`
   * con quel token rispondeva solo `sub`), mentre il primo token li aveva. Un
   * token che cambia significato a ogni rinnovo e' un bug, non una semantica.
   *
   * Non e' un costo di sicurezza: dichiarare uno scope non lo concede. Il
   * consenso resta demandato a `recordConsent` (`ui/ui-routes.ts`), che registra
   * nel grant solo gli scope effettivamente approvati, e il check
   * `rs_scopes_missing` li confronta con quelli richiesti: la nostra pagina di
   * consenso mostra quindi esattamente gli scope che verranno concessi, come
   * prima. Nessun prompt in piu', perche' lo scope core mancante in un grant
   * manca anche nel bucket OIDC dello stesso grant (`op_scopes_missing` chiede
   * gia' il consenso).
   */
  const scopes = (await store.listServiceScopes()).filter((s) =>
    s.scope === 'engine:admin' ? Boolean(service) : Boolean(service && s.serviceId === service.serviceId));
  const scopeSet = new Set([...CORE_SCOPES.filter((s) => s !== 'engine:admin' || Boolean(service)), ...scopes.map((s) => s.scope)]);
  return {
    scope: [...scopeSet].join(' '),
    audience: resource,
    accessTokenFormat: 'jwt',
  };
}
