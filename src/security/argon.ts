/**
 * Configurazione argon2 in forma piatta: condivisa dal modulo password e dai
 * punti che hanno bisogno solo del costo (verifica dei secret dei client), senza
 * dover passare l'intero oggetto Config.
 */
export interface ArgonConfig {
  ARGON2_MEMORY_KIB: number;
  ARGON2_ITERATIONS: number;
  ARGON2_PARALLELISM: number;
  PASSWORD_MAX_LENGTH: number;
  PASSWORD_MIN_LENGTH: number;
}

export function argonFromConfig(config: {
  ARGON2_MEMORY_KIB: number;
  ARGON2_ITERATIONS: number;
  ARGON2_PARALLELISM: number;
  PASSWORD_MAX_LENGTH: number;
  PASSWORD_MIN_LENGTH: number;
}): ArgonConfig {
  return {
    ARGON2_MEMORY_KIB: config.ARGON2_MEMORY_KIB,
    ARGON2_ITERATIONS: config.ARGON2_ITERATIONS,
    ARGON2_PARALLELISM: config.ARGON2_PARALLELISM,
    PASSWORD_MAX_LENGTH: config.PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH: config.PASSWORD_MIN_LENGTH,
  };
}