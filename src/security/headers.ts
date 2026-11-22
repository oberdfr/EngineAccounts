import type { FastifyReply, FastifyRequest } from 'fastify';

/**
 * Header di sicurezza.
 *
 * CSP **senza `unsafe-inline`**: nessuno stile o script inline nelle nostre pagine,
 * per questo esiste `src/ui/static/app.css` e `app.js`. `frame-ancestors 'none'`
 * impedisce il clickjacking, anche dagli endpoint OIDC (i token non devono finire
 * in un iframe di terzi).
 *
 * **`form-action` e' l'unica direttiva che dipende da chi si sta autenticando**,
 * e il perche' merita due paragrafi.
 *
 * Un form che avvia una navigazione e' vincolato da `form-action` per **tutta la
 * catena di redirect**, non solo per il primo hop. Il form di consenso posting
 * a `/ui/interaction/:uid/consent` risponde `303` verso `/auth/:uid`, che a sua
 * volta risponde `303` verso il `redirect_uri` **del client**: se quel client
 * e' su un'altra origine (ed e' sempre cosi': `localhost:5173` contro
 * `localhost:8080`), la catena esce da `'self'` e Chrome **cancella la
 * navigazione**. Non e' un errore di rete e non lascia tracce sul server: la
 * richiesta parte, il server la lavora e restituisce il 303, ma il browser non
 * completa il passaggio e l'utente resta fermo sulla pagina di consenso con
 * l'unico sintomo visibile in console:
 *
 *   Sending form data to 'http://localhost:8080/ui/interaction/<uid>/consent'
 *   violates the following Content Security Policy directive: "form-action 'self'".
 *
 * Quindi `'self'` da solo **non basta**: il flusso OIDC finisce per legittima
 * causa fuori dall'origine del provider.
 *
 * La correzione non e' `form-action *` (che aprirebbe la porta a un XSS iniettato
 * in una nostra pagina che esfiltra dati verso un dominio arbitrario), ma una
 * **allowlist delle origini dei client registrati**: sono gia' dati in tabella,
 * sono gli unici destinatari che il contratto autorizza, e non richiedono che
 * nessuno se li inventi a mano. Nessun dominio estraneo, nessun `*`.
 *
 * **`frame-ancestors` ha una sola eccezione, e vale solo per il flusso
 * silenzioso** (`prompt=none` su `authorizationEndpoint`). Il rinnovo senza
 * interazione dell'utente passa dal browser come iframe del client: se il
 * provider risponde `frame-ancestors 'none'` l'iframe non carica mai e il
 * rinnovo fallisce *sempre*. L'eccezione e' ristretta al massimo:
 *   - si applica **solo** a `GET authorizationEndpoint`, e solo quando la
 *     richiesta porta `prompt=none` (e nessun `response_type` che il contratto
 *     non usi): sono le sole risposte che possono essere un redirect al
 *     `redirect_uri` di un client registrato;
 *   - le origini ammesse sono le **stesse** dei `redirect_uri` registrati
 *     (`redirectOriginsOf`), non un parametro del richiedente: un client non
 *     puo' chiedere di essere incorniciato da un'origine che non possiede;
 *   - su quella risposta `X-Frame-Options` **non** viene emesso (non sa
 *     esprimere un elenco e `DENY`/`SAMEORIGIN` annullerebbero la CSP).
 * Pagine di login, consenso e account restano `frame-ancestors 'none'` +
 * `X-Frame-Options: DENY`: il clickjacking su una pagina interattiva resta
 * impossibile.
 */

/** Origine (`scheme://host[:port]`) di una URL, oppure `null` se non e' URL. */
export function originOf(url: string): string | null {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol) && parsed.origin !== 'null' ? parsed.origin : null;
  } catch {
    return null;
  }
}

/**
 * Origini dei `redirect_uri` dei client registrati: gli unici destinatari che il
 * flusso di autorizzazione puo' legittimamente raggiungere dopo un form.
 *
 * I client disattivati sono esclusi: un client spento non deve poter piu'
 * ricevere navigazioni dal provider. I `redirect_uri` non sono URL (dati
 * corrotti) vengono scartati invece di far fallire l'avvio: una allowlist
 * incompleta blocca il login, una allowlist che non parte blocca tutto.
 */
export function redirectOriginsOf(clients: readonly { redirectUris: readonly string[]; enabled: boolean; applicationType?: string; corsOrigins?: readonly string[] }[]): string[] {
  const origins = new Set<string>();
  for (const client of clients) {
    if (!client.enabled) continue;
    // Un client device-only (TV, nessun redirect) non naviga mai verso l'app:
    // le sue origini CORS non entrano in form-action / frame-ancestors.
    if (client.applicationType === 'native' && client.redirectUris.length) {
      for (const origin of client.corsOrigins ?? []) {
        try { if (!origin.includes('*') && new URL(origin).protocol === 'https:' && new URL(origin).origin === origin) origins.add(origin); }
        catch { /* Invalid native origins never widen the allowlist. */ }
      }
    }
    for (const uri of client.redirectUris) {
      const origin = originOf(uri);
      if (origin) origins.add(origin);
    }
  }
  return [...origins].sort();
}

export function redirectFormActionsOf(clients: readonly { redirectUris: readonly string[]; enabled: boolean; applicationType?: string; corsOrigins?: readonly string[] }[]): string[] {
  const sources = new Set(redirectOriginsOf(clients));
  for (const client of clients) {
    if (!client.enabled || client.applicationType !== 'native') continue;
    for (const uri of client.redirectUris) {
      try {
        const protocol = new URL(uri).protocol;
        if (protocol === 'streamingengine:' || /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/.test(protocol)) sources.add(protocol);
      } catch { /* Fail closed for malformed persisted metadata. */ }
    }
  }
  return [...sources].sort();
}

/**
 * Elenco di origini da mettere in `form-action`, dato `'self'` piu' quelle che
 * il flusso di autorizzazione puo' legittimamente raggiungere.
 *
 * Deduplica e ordina in modo deterministico: l'header deve essere stabile, altrimenti
 * ogni richiesta avrebbe una CSP diversa (e i test diventerebbero casuali).
 */
export function formActionSources(extraOrigins: readonly string[] = []): string[] {
  const seen = new Set<string>();
  for (const raw of extraOrigins) {
    const origin = raw.trim();
    if (origin && origin !== "'self'") seen.add(origin);
  }
  return ["'self'", ...[...seen].sort()];
}

/**
 * Costruisce la CSP. `formActionOrigins` finisce in `form-action` e va passato
 * **solo** sulle pagine che possono davvero finire fuori origine (le pagine di
 * interazione); altrove resta `'self'`, per non allargare la politica di pagine
 * che non ne hanno bisogno. `frameAncestors` vale `'none'` ovunque tranne la
 * risposta silenziosa `/auth?prompt=none`: dettaglio in cima al file.
 */
export function buildCsp(formActionOrigins: readonly string[] = [], frameAncestors: readonly string[] | 'none' = 'none'): string {
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    `form-action ${formActionSources(formActionOrigins).join(' ')}`,
    `frame-ancestors ${frameAncestorsSources(frameAncestors).join(' ')}`,
    "base-uri 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
  ].join('; ');
}

/**
 * Valori di `frame-ancestors`. Accetta solo origini assolute `http(s)` e il
 * letterale `'none'`: qualunque altra stringa (incluso `*`, `http:`, un percorso)
 * viene scartata, e **se resta vuoto si torna a `'none'`**. Fail closed: un
 * elenco malformato non deve poter aprire l'embedding a tutti.
 */
export function frameAncestorsSources(frameAncestors: readonly string[] | 'none'): string[] {
  if (frameAncestors === 'none') return ["'none'"];
  const sources = new Set<string>();
  for (const raw of frameAncestors) {
    const origin = originOf(String(raw ?? '').trim());
    if (origin && origin === String(raw ?? '').trim()) sources.add(origin);
  }
  return sources.size ? [...sources].sort() : ["'none'"];
}

/**
 * La richiesta e' una **authorization request silenziosa**: `prompt=none`
 * (eventualmente fra altri valori separati da spazio) su `GET` del path di
 * autorizzazione configurato (`/auth`). E' l'unico caso in cui il provider puo'
 * rispondere con un redirect al `redirect_uri` senza che l'utente veda alcuna
 * pagina nostra — ed e' quindi l'unico caso che un client puo' incorniciare.
 */
export function isSilentAuthorizationRequest(method: string, rawUrl: string | undefined, authorizationEndpoint = '/auth'): boolean {
  if (method !== 'GET' && method !== 'HEAD') return false;
  const raw = rawUrl ?? '';
  const queryAt = raw.indexOf('?');
  const path = queryAt === -1 ? raw : raw.slice(0, queryAt);
  if (path !== authorizationEndpoint) return false;
  if (queryAt === -1) return false;
  return new URLSearchParams(raw.slice(queryAt + 1)).get('prompt')?.split(/\s+/).includes('none') === true;
}

/** CSP di base: `form-action 'self'`, per tutto cio' che non e' un flusso di autorizzazione. */
export const CSP = buildCsp();

export const PERMISSIONS_POLICY = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()';

export function isSecureRequest(request: FastifyRequest): boolean {
  if (request.protocol === 'https') return true;
  const forwarded = request.headers['x-forwarded-proto'];
  return typeof forwarded === 'string' && forwarded.split(',')[0]?.trim() === 'https';
}

/**
 * HSTS dietro interruttore.
 *
 * Lo si emette **solo** se la richiesta è già su https (mandarlo su http è
 * ignorato dai browser e serve a nulla) e solo se l'interruttore è acceso.
 * `includeSubDomains` è disattivabile: vale per i sottodomini dell'host che
 * serve, e metterlo a caso vincola anche host che non sono nostri.
 */
export function hstsHeader(request: FastifyRequest, options: { enabled: boolean; maxAge: number; includeSubDomains: boolean }): string | null {
  if (!options.enabled) return null;
  if (!isSecureRequest(request)) return null;
  const parts = [`max-age=${Math.max(0, Math.floor(options.maxAge))}`];
  if (options.includeSubDomains) parts.push('includeSubDomains');
  return parts.join('; ');
}

export interface SecurityHeaderOptions {
  isPage?: boolean;
  hsts?: { enabled: boolean; maxAge: number; includeSubDomains: boolean };
  /**
   * Origini aggiuntive autorizzate in `form-action`. Va valorizzato **solo** per
   * le pagine del flusso di autorizzazione: vedere la nota in cima al file.
   */
  formActionOrigins?: readonly string[];
  /**
   * `frame-ancestors`. Default `'none'`; le origini dei client registrati (o
   * `'none'`) vanno passate **solo** sulla risposta silenziosa `GET /auth?prompt=none`.
   * Con un elenco il messaggio `X-Frame-Options` non viene emesso: un browser
   * che capisce `DENY`/`SAMEORIGIN` annullerebbe la direttiva.
   */
  frameAncestors?: readonly string[] | 'none';
}

/**
 * Sposta su `reply.raw` gli header che Fastify tiene in sospeso.
 *
 * Serve per le risposte **non scritte da Fastify**: quando il provider OIDC (o
 * `interactionFinished`) scrive direttamente sulla `ServerResponse`, Fastify
 * non invia piu' nulla, quindi CSP, `nosniff` e `Referrer-Policy` andrebbero
 * persi. Senza questo, gli endpoint OIDC — cioe' `/auth`, `/token`, `/jwks`,
 * `/introspect` — rispondono senza nessun header di sicurezza.
 *
 * `writeHead()` unisce cio' che e' gia' stato impostato con `setHeader()`, quindi
 * non si perde nulla e non si duplica nulla. Gli header gia' presenti sulla
 * risposta grezza non vengono sovrascritti.
 */
export function flushReplyHeadersToRaw(reply: FastifyReply): void {
  const raw = reply.raw;
  if (raw.headersSent) return;
  for (const [key, value] of Object.entries(reply.getHeaders())) {
    if (value === undefined) continue;
    if (raw.hasHeader(key)) continue;
    raw.setHeader(key, value as string | string[]);
  }
}

export function applySecurityHeaders(request: FastifyRequest, reply: FastifyReply, options: SecurityHeaderOptions = {}): void {
  const { isPage = false } = options;
  const frameAncestors = frameAncestorsSources(options.frameAncestors ?? 'none');
  reply.header('Content-Security-Policy', buildCsp(options.formActionOrigins ?? [], options.frameAncestors ?? 'none'));
  reply.header('X-Content-Type-Options', 'nosniff');
  // `X-Frame-Options` non sa esprimere un elenco: quando c'e' un elenco di
  // origini ammesse (solo la risposta silenziosa) si omette, altrimenti un
  // browser legacy annullerebbe `frame-ancestors`. Ovunque altro resta `DENY`.
  if (frameAncestors.length === 1 && frameAncestors[0] === "'none'") reply.header('X-Frame-Options', 'DENY');
  // `no-referrer`: nessuna URL della UI (con `state`, `code`, `nonce`) deve
  // arrivare a un terzo, nemmeno per referrer.
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('Permissions-Policy', PERMISSIONS_POLICY);
  reply.header('Cross-Origin-Opener-Policy', 'same-origin');
  // Le app TV impacchettate (webOS 6: `Origin: file://<appId>-webos`, altre
  // versioni `file://` o `null`) chiamano /device/auth e /token: Chromium 79
  // (LG webOS 6) applica CORP anche a quelle risposte e con `same-origin` le
  // blocca (ERR_BLOCKED_BY_RESPONSE). L'accesso resta deciso dal CORS,
  // concesso solo al client device-flow che dichiara queste origini.
  const origin = request.headers.origin;
  const opaqueTv = typeof origin === 'string' && (origin === 'null' || origin.indexOf('file://') === 0);
  reply.header('Cross-Origin-Resource-Policy', opaqueTv ? 'cross-origin' : 'same-origin');
  reply.removeHeader('X-Powered-By');
  const hsts = options.hsts ? hstsHeader(request, options.hsts) : null;
  if (hsts) reply.header('Strict-Transport-Security', hsts);
  if (isPage) {
    // Pagine con dati utente: mai in cache condivisa.
    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');
  }
}
