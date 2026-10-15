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
    if (client.applicationType === 'native') {
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
 * che non ne hanno bisogno.
 */
export function buildCsp(formActionOrigins: readonly string[] = []): string {
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    `form-action ${formActionSources(formActionOrigins).join(' ')}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
  ].join('; ');
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
  reply.header('Content-Security-Policy', buildCsp(options.formActionOrigins ?? []));
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  // `no-referrer`: nessuna URL della UI (con `state`, `code`, `nonce`) deve
  // arrivare a un terzo, nemmeno per referrer.
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('Permissions-Policy', PERMISSIONS_POLICY);
  reply.header('Cross-Origin-Opener-Policy', 'same-origin');
  reply.header('Cross-Origin-Resource-Policy', 'same-origin');
  reply.removeHeader('X-Powered-By');
  const hsts = options.hsts ? hstsHeader(request, options.hsts) : null;
  if (hsts) reply.header('Strict-Transport-Security', hsts);
  if (isPage) {
    // Pagine con dati utente: mai in cache condivisa.
    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');
  }
}
