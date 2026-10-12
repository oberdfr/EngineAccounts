import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLogger } from '../logger.js';

const logger = createLogger((process.env.LOG_LEVEL as never) ?? 'info', { svc: 'engine-accounts' });

/**
 * Controllo password compromesse.
 *
 * Modalita' primaria: **k-anonymity** con l'API Pwned Passwords. Al provider
 * va solo il prefisso di 5 caratteri dello SHA-1: il resto della password non
 * esce mai dalla macchina.
 *
 * Modalita' secondaria (documentata): se l'API non e' raggiungibile — rete
 * chiusa, air-gapped, rete aziendale filtrata — si ripiega su una blocklist
 * locale di password comuni. La degradazione e' esplicita nel risultato
 * (`source`), viene registrata in audit e non blocca l'utente.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
/** Funziona da `src/` (tsx) e da `dist/` (dopo `scripts/copy-assets.mjs`). */
const dataDir = existsSync(path.resolve(here, 'data'))
  ? path.resolve(here, 'data')
  : path.resolve(here, '../../src/security/data');

export type BreachSource = 'hibp' | 'local' | 'local-fallback';

export interface BreachVerdict {
  breached: boolean;
  source: BreachSource;
  /** Numero di occorrenze, quando noto. */
  count?: number;
}

export interface BreachedChecker {
  check(password: string): Promise<BreachVerdict>;
}

/** Blocklist locale: fallback quando l'API non risponde. */
export class LocalBlocklist {
  private readonly set: Set<string>;
  constructor(file = path.join(dataDir, 'common-passwords.txt')) {
    this.set = new Set(
      fs
        .readFileSync(file, 'utf8')
        .split('\n')
        .map((line) => line.trim().toLowerCase())
        .filter((line) => line.length > 0 && !line.startsWith('#')),
    );
  }
  has(password: string): boolean {
    return this.set.has(password.toLowerCase());
  }
  get size(): number {
    return this.set.size;
  }
}

interface CacheEntry {
  at: number;
  verdict: BreachVerdict;
}

export class PwnedPasswordChecker implements BreachedChecker {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly local: LocalBlocklist;
  private apiDown = false;

  constructor(
    private readonly options: {
      enabled: boolean;
      apiBase: string;
      timeoutMs: number;
      cacheTtlMs: number;
      local?: LocalBlocklist;
      fetchImpl?: typeof fetch;
    },
  ) {
    this.local = options.local ?? new LocalBlocklist();
  }

  async check(password: string): Promise<BreachVerdict> {
    // La blocklist locale si guarda sempre: e' gratuita e non dipende dalla rete.
    if (this.local.has(password)) return { breached: true, source: 'local' };

    if (!this.options.enabled) return { breached: false, source: 'local-fallback' };

    const digest = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);

    const cached = this.cache.get(digest);
    if (cached && Date.now() - cached.at < this.options.cacheTtlMs) {
      return cached.verdict;
    }

    try {
      const res = await this.fetchRange(prefix);
      const count = this.parseSuffix(res, suffix);
      const verdict: BreachVerdict = count > 0 ? { breached: true, source: 'hibp', count } : { breached: false, source: 'hibp' };
      this.cache.set(digest, { at: Date.now(), verdict });
      if (this.apiDown) {
        this.apiDown = false;
        logger.info('api pwned passwords di nuovo raggiungibile');
      }
      return verdict;
    } catch (err) {
      if (!this.apiDown) {
        this.apiDown = true;
        logger.warn('api pwned passwords non raggiungibile: uso la blocklist locale', {
          err: (err as Error).message,
        });
      }
      // Degradazione esplicita: la registrazione/il cambio password restano
      // possibili, ma l'utente non e' piu' protetto dai dati compromessi.
      return { breached: false, source: 'local-fallback' };
    }
  }

  private async fetchRange(prefix: string): Promise<string> {
    const doFetch = this.options.fetchImpl ?? fetch;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs);
    try {
      const res = await doFetch(`${this.options.apiBase}/range/${prefix}`, {
        // k-anonymity: la richiesta non contiene la password, solo 5 hash.
        headers: { 'User-Agent': 'engine-accounts/1.0', 'Add-Padding': 'true' },
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`status ${res.status}`);
      return await res.text();
    } finally {
      clearTimeout(timer);
    }
  }

  private parseSuffix(body: string, suffix: string): number {
    for (const line of body.split('\n')) {
      const [candidate, count] = line.split(':');
      if (candidate && count && candidate.trim().toUpperCase() === suffix) {
        return Number.parseInt(count.trim(), 10) || 0;
      }
    }
    return 0;
  }
}

/** Checker deterministico per i test (nessuna rete). */
export class FixedBreachedChecker implements BreachedChecker {
  private readonly breached = new Set<string>();
  constructor(breached: string[] = []) {
    for (const p of breached) this.breached.add(p.toLowerCase());
  }
  async check(password: string): Promise<BreachVerdict> {
    const hit = this.breached.has(password.toLowerCase());
    return hit ? { breached: true, source: 'hibp', count: 42 } : { breached: false, source: 'hibp' };
  }
}