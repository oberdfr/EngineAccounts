import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createLocalJWKSet, jwtVerify, type JWK } from 'jose';
import type { Config } from '../config.js';
import type { AccountsStore } from '../domain/ports.js';
import { profileClaims } from './account-adapter.js';

/**
 * `/userinfo` — profilo dell'utente autenticato.
 *
 * **Perche' non lo fa la libreria.** Il contratto congelato chiede due cose che
 * `oidc-provider` v9 considera incompatibili:
 *   - §5: l'access token porta `aud`, e un JWT senza audience non e' possibile
 *     (la libreria lo dice esplicitamente: i token per il solo userinfo devono
 *     essere *opachi*);
 *   - §2: esiste `/userinfo`, che pero' la libreria rifiuta se il token ha
 *     `aud` (`token audience prevents accessing the userinfo endpoint`).
 * Non possiamo soddisfare entrambe usando la sua rotta, e il contratto non si
 * tocca: quindi l'endpoint e' nostro e fa esattamente cio' che deve fare —
 * verifica il Bearer con la **nostra** JWKS (nessuna chiamata di rete, come
 * chiede D1) e risponde con i claim che gli scope del token permettono.
 *
 * Il path e' quello del contratto e resta quello annunciato in discovery: la
 * discovery la genera la libreria da `routes.userinfo`, quindi continua a
 * corrispondere.
 */

/** Algoritmi ammessi: gli stessi della discovery, mai `none`, mai `HS*`. */
const ALGS = ['EdDSA', 'RS256'];

export interface UserinfoDeps {
  config: Config;
  store: AccountsStore;
  /**
   * Chiavi **pubbliche** correnti. Non passiamo mai il JWKS su disco (che
   * contiene le chiavi private) a un verificatore: una chiave privata
   * pubblicata per sbaglio e' l'errore piu' grave possibile qui.
   */
  jwks: () => Promise<JWK[]>;
  /**
   * Origini autorizzate a leggere `/userinfo` dal browser: le stesse dei
   * `redirect_uri` dei client registrati, con la stessa regola di `form-action`.
   * Vedi `corsHeaders` per il perche', e per quello che qui **non** facciamo.
   *
   * E' una funzione e non un elenco perche' i client si registrano a runtime
   * (CLI, altro processo): una lista congelata all'avvio romperebbe il frontend
   * appena si registra un client nuovo. Viene interrogata **solo** quando la
   * richiesta porta un `Origin`, quindi le chiamate server-to-server — il caso
   * normale — non pagano nessuna query.
   */
  allowedOrigins?: () => Promise<readonly string[]>;
}

export function registerUserinfoRoute(app: FastifyInstance, deps: UserinfoDeps): void {
  const { config, store, jwks } = deps;
  // Cache delle chiavi: si ricarica solo se la verifica fallisce, cosi' una
  // rotazione delle chiavi non richiede un riavvio (D1: nessuna chiamata al
  // provider per ogni richiesta, e nessun ricaricamento inutile).
  let cached: ReturnType<typeof createLocalJWKSet> | null = null;

  async function verify(token: string): Promise<Record<string, unknown> | null> {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        if (!cached) cached = createLocalJWKSet({ keys: await jwks() });
        const { payload } = await jwtVerify(token, cached, {
          issuer: config.issuer,
          algorithms: ALGS,
          requiredClaims: ['sub', 'iss', 'iat', 'exp', 'jti'],
        });
        return payload as Record<string, unknown>;
      } catch {
        // Secondo tentativo con le chiavi rilette: copre la rotazione avvenuta
        // mentre il processo era vivo.
        cached = null;
      }
    }
    return null;
  }

  /** 401 con `WWW-Authenticate`, come RFC 6750 §3. */
  function unauthorized(reply: FastifyReply, detail: string): FastifyReply {
    return reply
      .code(401)
      .header('WWW-Authenticate', `Bearer realm="userinfo", error="invalid_token", error_description="${detail}"`)
      .send({ error: 'invalid_token', error_description: detail });
  }

  async function handler(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply> {
    const header = request.headers.authorization;
    // Il token puo' arrivare anche come parametro `access_token` (RFC 6750 §2):
    // lo accettiamo, ma solo in POST e mai in un URL scritto nei log.
    const bearer = typeof header === 'string' && /^Bearer\s+/i.test(header) ? header.replace(/^Bearer\s+/i, '') : undefined;
    const body = (request.body ?? {}) as Record<string, unknown>;
    const token = bearer ?? (typeof body.access_token === 'string' ? body.access_token : undefined);
    if (!token) return unauthorized(reply, 'missing bearer token');

    const payload = await verify(token);
    if (!payload) return unauthorized(reply, 'token non valido o scaduto');

    const sub = String(payload.sub ?? '');
    // Scope del token: e' la base per decidere quali claim restituire. Un token
    // senza scope non autorizza nessun claim personale, solo `sub`.
    const scope = typeof payload.scope === 'string' ? payload.scope : '';

    const user = await store.findUserById(sub);
    if (!user || user.status !== 'active') {
      return unauthorized(reply, 'account non disponibile');
    }

    const claims = profileClaims(user, scope);
    return reply
      .header('Cache-Control', 'no-store, private')
      .header('Pragma', 'no-cache')
      .type('application/json; charset=utf-8')
      .send(claims);
  }

  /**
   * CORS di `/userinfo`.
   *
   * Una SPA chiama questo endpoint dal proprio browser, quindi senza CORS la
   * richiesta muore con `Failed to fetch` **prima** di arrivare a noi: il
   * frontend non puo' nemmeno arricchire il profilo.
   *
   * La allowlist e' la stessa di `form-action` — le origini dei `redirect_uri`
   * dei client registrati — perche' e' la stessa identita' di clienti di cui
   * parliamo. Niente `'*'`, e soprattutto niente
   * `Access-Control-Allow-Credentials`: `/userinfo` si autentica con il Bearer
   * nell'intestazione, non con i cookie, quindi concedere le credenziali
   * ambientali non servirebbe a nulla e aprirebbe `/userinfo` a qualunque
   * pagina che faccia credere all'utente di essere gia' autenticato.
   */
  const resolveAllowedOrigins = deps.allowedOrigins ?? (async () => [] as readonly string[]);

  async function corsHeaders(request: FastifyRequest, reply: FastifyReply): Promise<boolean> {
    const origin = request.headers.origin;
    // `Vary: Origin` sempre: la risposta dipende dall'origine, e senza questo
    // una cache condivisa puo' servire a un altro la risposta di un client.
    reply.header('Vary', 'Origin');
    // Nessun `Origin` (chiamata server-to-server) non e' una richiesta CORS:
    // niente da decidere e nessuna query sul database.
    if (typeof origin !== 'string' || origin === '') return false;
    if (!(await resolveAllowedOrigins()).includes(origin)) return false;
    reply.header('Access-Control-Allow-Origin', origin);
    reply.header('Access-Control-Expose-Headers', 'WWW-Authenticate');
    return true;
  }

  /** Preflight: senza, la richiesta con `Authorization` non parte mai. */
  app.options('/userinfo', async (request, reply) => {
    const consentito = await corsHeaders(request, reply);
    if (!consentito || request.headers['access-control-request-method'] === undefined) {
      // Nessuna intestazione CORS: il browser blocca, e non si lascia a terra
      // neanche la preflight di un'origine non autorizzata.
      return reply.code(403).send({ error: 'origin not allowed' });
    }
    return reply
      .code(204)
      .header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      .header('Access-Control-Allow-Headers', 'authorization, content-type')
      .header('Access-Control-Max-Age', '600')
      .send();
  });

  const withCors = async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply> => {
    await corsHeaders(request, reply);
    return handler(request, reply);
  };

  app.get('/userinfo', withCors);
  app.post('/userinfo', withCors);
}