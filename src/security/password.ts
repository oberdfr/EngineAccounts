import { Algorithm, hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import type { ArgonConfig } from './argon.js';
import { argonFromConfig } from './argon.js';
import type { Config } from '../config.js';

/**
 * Hash delle password: **argon2id** (OWASP ASVS 2.4.1), parametri da env
 * (`ARGON2_MEMORY_KIB`, `ARGON2_ITERATIONS`, `ARGON2_PARALLELISM`).
 *
 * Limite di lunghezza: `PASSWORD_MAX_LENGTH` (1024 di default). Non e' un limite
 * di prodotto — una passphrase da 300 caratteri passa — e' un tetto anti-DoS:
 * argon2 e' lento per scelta, e l'hashing di un input enorme e' un vettore di
 * denial of service. Nessun limite inferiore a 12 caratteri, nessuna composizione
 * obbligata: i requisiti di complessita' spostano il peso sull'utente e sul
 * controllo delle password compromesse, non su una lista di regole arbitrarie.
 *
 * Accettiamo sia `Config` sia il sottoinsieme `ArgonConfig`: il confronto dei
 * secret dei client usa solo i parametri di costo.
 */
export const ALGORITHM = Algorithm.Argon2id;

export function optionsFor(config: ArgonConfig) {
  return {
    algorithm: ALGORITHM,
    memoryCost: config.ARGON2_MEMORY_KIB,
    timeCost: config.ARGON2_ITERATIONS,
    parallelism: config.ARGON2_PARALLELISM,
  };
}

export class PasswordTooLongError extends Error {
  constructor(public readonly maxLength: number) {
    super(`password troppo lunga (massimo ${maxLength} caratteri)`);
    this.name = 'PasswordTooLongError';
  }
}

/** Hash della password. Rifiuta solo l'attacco DoS da input enorme. */
export async function hashPassword(password: string, config: Config | ArgonConfig): Promise<string> {
  const max = 'PASSWORD_MAX_LENGTH' in config ? config.PASSWORD_MAX_LENGTH : 1024;
  if (Buffer.byteLength(password, 'utf8') > max * 4) throw new PasswordTooLongError(max);
  return argonHash(password, optionsFor(config));
}

/** Verifica. Non distingue mai "utente inesistente" dal "password errata". */
export async function verifyPassword(
  hash: string,
  password: string,
  config: Config | ArgonConfig,
): Promise<boolean> {
  try {
    return await argonVerify(hash, password, optionsFor(config));
  } catch {
    return false;
  }
}

let decoyHash: string | undefined;

/**
 * Hash "morto" per equalizzare i tempi quando l'utente non esiste: stessa
 * operazione, stesso costo, risultato sempre falso.
 */
export async function decoyVerify(password: string, config: Config | ArgonConfig): Promise<boolean> {
  decoyHash ??= await hashPassword('password-che-non-esiste-mai', config);
  return verifyPassword(decoyHash, password, config);
}

export { argonFromConfig };