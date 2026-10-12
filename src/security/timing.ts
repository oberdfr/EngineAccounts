/**
 * Anti-enumerazione: tempi e risposte uniformi.
 *
 * Due difese diverse:
 *  1. **stesso lavoro**: quando l'utente non esiste si esegue comunque una
 *     verifica argon2id su un hash "morto" (stesso costo, stesso ordine di
 *     grandezza del caso reale);
 *  2. **stesso tempo**: `holdFor` fa in modo che la risposta non
 *     arrivi mai prima di `HTTP_LOGIN_SLOW_MS` dal momento in cui la richiesta
 *     e' stata accettata. Un attaccante non puo' distinguere "utente non
 *     esiste" dal "password sbagliata" guardando la latenza.
 */

function sleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    setTimeout(resolve, ms).unref?.();
  });
}

/** Orario di inizio: le rotte lo impostano appena la richiesta e' arrivata. */
export function markStart(): () => number {
  const start = performance.now();
  return () => performance.now() - start;
}

/** Attende il minimo tempo, anche se `fn` e' sincrona o lancia. */
export async function holdFor(minMs: number, fn: () => unknown): Promise<void> {
  const start = performance.now();
  try {
    await fn();
  } finally {
    const remaining = minMs - (performance.now() - start);
    if (remaining > 0) await sleep(remaining);
  }
}

/**
 * Messaggi di risposta neutri. L'utente non deve poter distinguere:
 *   - email inesistente        -> "Se l'indirizzo esiste, ti abbiamo scritto."
 *   - account bloccato         -> stesso messaggio
 *   - email gia' registrata    -> stesso messaggio alla registrazione
 */
export const NEUTRAL_DELIVERY = 'Se l\u2019indirizzo esiste, ti abbiamo scritto un\u2019email.';
export const NEUTRAL_LOGIN = 'Credenziali non valide.';
export const NEUTRAL_REGISTRATION = 'Se l\u2019indirizzo non e\u2019gia\u2019 in uso, la registrazione e\u2019 stata completata.';

/** Codice di accesso monouso: 6 cifre, casuali crittograficamente. */
export function formatMagicCode(digits: string): string {
  return digits.replace(/(\d{3})(?=\d)/g, '$1 ');
}
