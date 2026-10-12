/**
 * Logger minimale su stderr, senza dipendenze.
 *
 * Vincolo di sicurezza: **mai segreti nei log**. `redact()` copre i campi
 * piu' tipici; i caller passano solo dati gia' decifrati e non sensibili
 * (id, esito, motivo del rifiuto). I token monouso e le password non passano
 * mai dal logger.
 */

export type LogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';

const LEVELS: Record<LogLevel, number> = {
  fatal: 60,
  error: 50,
  warn: 40,
  info: 30,
  debug: 20,
  trace: 10,
  silent: 0,
};

const SECRET_KEYS = new Set([
  'password',
  'newpassword',
  'currentpassword',
  'passwordhash',
  'clientsecret',
  'secret',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'code',
  'codeverifier',
  'authorization',
  'cookie',
  'setcookie',
  'xcsrf',
  'csrftoken',
  'apikey',
  'authorizationcode',
  'signature',
  'otp',
  'totp',
]);

function redact(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[profondita]';
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    const lower = key.toLowerCase().replace(/[^a-z]/g, '');
    out[key] = SECRET_KEYS.has(lower) ? '[redatto]' : redact(val, depth + 1);
  }
  return out;
}

export interface Logger {
  fatal(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  debug(msg: string, fields?: Record<string, unknown>): void;
  trace(msg: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

export function createLogger(level: LogLevel = 'info', base: Record<string, unknown> = {}): Logger {
  const threshold = LEVELS[level];
  const emit = (lvl: Exclude<LogLevel, 'silent'>, msg: string, fields?: Record<string, unknown>) => {
    if (LEVELS[lvl] < threshold) return;
    const line = {
      ts: new Date().toISOString(),
      level: lvl,
      msg,
      ...(redact(base) as Record<string, unknown>),
      ...(fields ? (redact(fields) as Record<string, unknown>) : {}),
    };
    const out = JSON.stringify(line);
    process.stderr.write(`${out}\n`);
  };
  return {
    fatal: (msg, fields) => emit('fatal', msg, fields),
    error: (msg, fields) => emit('error', msg, fields),
    warn: (msg, fields) => emit('warn', msg, fields),
    info: (msg, fields) => emit('info', msg, fields),
    debug: (msg, fields) => emit('debug', msg, fields),
    trace: (msg, fields) => emit('trace', msg, fields),
    child: (fields) => createLogger(level, { ...base, ...fields }),
  };
}

export const logger: Logger = createLogger((process.env.LOG_LEVEL as LogLevel) || 'info', { svc: 'engine-accounts' });

export const nullLogger: Logger = createLogger('silent');