import { createLogger } from '../logger.js';

const logger = createLogger((process.env.LOG_LEVEL as never) ?? 'info', { svc: 'engine-accounts' });

/**
 * Rate limiting e lockout progressivo.
 *
 * Due livelli, perche' attaccare gli account e' diverso dal martellare un IP:
 *  - per IP: sliding window, blocca il brute force contro account casuali;
 *  - per account: lockout progressivo, sopravvive al cambio di IP e colpisce
 *    l'attacco distribuito. Sblocco automatico con attesa che raddoppia a ogni
 *    fallimento (n, 2n, 4n, ... tetto `maxMs`).
 *
 * Stato in memoria del processo: sufficiente per una singola istanza (il
 * compose ne avvia una). Per piu' istanze serve uno store condiviso.
 */

export interface RateLimitVerdict {
  allowed: boolean;
  remaining: number;
  /** Secondi da aspettare quando `allowed` e' false. */
  retryAfterSeconds: number;
}

interface Window {
  hits: number[];
}

interface AccountState {
  failures: number;
  firstFailureAt: number;
  lockedUntil: number;
}

export class RateLimiter {
  private readonly windows = new Map<string, Window>();
  private readonly accounts = new Map<string, AccountState>();

  constructor(private readonly options: { ipMax: number; ipWindowMs: number; accountMax: number; accountWindowMs: number; lockBaseMs: number; lockMaxMs: number }) {}

  /* --- per IP (sliding window) ------------------------------------------ */

  checkIp(key: string, limit = this.options.ipMax, windowMs = this.options.ipWindowMs): RateLimitVerdict {
    const now = Date.now();
    const bucket = key;
    const window = this.windows.get(bucket) ?? { hits: [] };
    window.hits = window.hits.filter((t) => now - t < windowMs);
    if (window.hits.length >= limit) {
      const retryAfterMs = Math.max(0, window.hits[0]! + windowMs - now);
      this.windows.set(bucket, window);
      this.sweep(now);
      return { allowed: false, remaining: 0, retryAfterSeconds: Math.ceil(retryAfterMs / 1000) };
    }
    window.hits.push(now);
    this.windows.set(bucket, window);
    this.sweep(now);
    return { allowed: true, remaining: limit - window.hits.length, retryAfterSeconds: 0 };
  }

  /** Registra un tentativo fallito e calcola l'eventuale lockout progressivo. */
  registerAccountFailure(key: string): RateLimitVerdict & { lockMs: number } {
    const now = Date.now();
    const state = this.accounts.get(key) ?? { failures: 0, firstFailureAt: now, lockedUntil: 0 };
    if (now - state.firstFailureAt > this.options.accountWindowMs) {
      state.failures = 0;
      state.firstFailureAt = now;
    }
    state.failures += 1;

    let lockMs = 0;
    if (state.failures >= this.options.accountMax) {
      const exponent = state.failures - this.options.accountMax;
      lockMs = Math.min(this.options.lockMaxMs, this.options.lockBaseMs * 2 ** exponent);
      state.lockedUntil = now + lockMs;
      logger.warn('lockout progressivo per account', { lockMs, failures: state.failures });
    }
    this.accounts.set(key, state);

    const inWindow = state.failures < this.options.accountMax;
    return {
      allowed: inWindow,
      remaining: Math.max(0, this.options.accountMax - state.failures),
      retryAfterSeconds: lockMs ? Math.ceil(lockMs / 1000) : 0,
      lockMs,
    };
  }

  /** Account non bloccato? Ritorna il tempo residuo se lo e'. */
  checkAccount(key: string): RateLimitVerdict {
    const state = this.accounts.get(key);
    const now = Date.now();
    if (!state) return { allowed: true, remaining: this.options.accountMax, retryAfterSeconds: 0 };
    if (state.lockedUntil > now) {
      return { allowed: false, remaining: 0, retryAfterSeconds: Math.ceil((state.lockedUntil - now) / 1000) };
    }
    return { allowed: true, remaining: Math.max(0, this.options.accountMax - state.failures), retryAfterSeconds: 0 };
  }

  registerAccountSuccess(key: string): void {
    this.accounts.delete(key);
  }

  /** Forget esplicito (usato da CLI admin e dalla revoca di sessione). */
  reset(key: string): void {
    this.accounts.delete(key);
  }

  /** Pulisce le finestre scadute: senza, la mappa cresce indefinitamente. */
  private sweep(now: number): void {
    if (this.windows.size % 200 !== 0) return;
    for (const [key, window] of this.windows) {
      window.hits = window.hits.filter((t) => now - t < this.options.ipWindowMs);
      if (!window.hits.length) this.windows.delete(key);
    }
    for (const [key, state] of this.accounts) {
      if (state.lockedUntil < now - this.options.lockMaxMs && state.firstFailureAt < now - this.options.accountWindowMs) {
        this.accounts.delete(key);
      }
    }
  }

  /** Solo per i test. */
  stats(): { ipKeys: number; accounts: number } {
    return { ipKeys: this.windows.size, accounts: this.accounts.size };
  }
}

export function rateLimiterFromEnv(env: {
  LOGIN_RATE_IP_MAX: number;
  LOGIN_RATE_IP_WINDOW_MS: number;
  LOGIN_RATE_ACCOUNT_MAX: number;
  LOGIN_RATE_ACCOUNT_WINDOW_MS: number;
  ACCOUNT_LOCK_BASE_MS: number;
  ACCOUNT_LOCK_MAX_MS: number;
}): RateLimiter {
  return new RateLimiter({
    ipMax: env.LOGIN_RATE_IP_MAX,
    ipWindowMs: env.LOGIN_RATE_IP_WINDOW_MS,
    accountMax: env.LOGIN_RATE_ACCOUNT_MAX,
    accountWindowMs: env.LOGIN_RATE_ACCOUNT_WINDOW_MS,
    lockBaseMs: env.ACCOUNT_LOCK_BASE_MS,
    lockMaxMs: env.ACCOUNT_LOCK_MAX_MS,
  });
}
