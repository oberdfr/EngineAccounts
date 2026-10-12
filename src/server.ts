import { migrate, pruneExpired } from './db/migrate.js';
import { ensureDefaultClients } from './db/seed.js';
import { createDb } from './db/pool.js';
import { loadConfig, type Config } from './config.js';
import { loadRepoEnv } from './env.js';
import { buildApp } from './app.js';
import { createLogger } from './logger.js';

/**
 * Avvio del servizio.
 *
 * Ordine: `.env` di sviluppo -> configurazione -> database -> migration ->
 * provider -> ascolto. Le migration girano all'avvio e sono idempotenti
 * (advisory lock + versioning): un riavvio non deve richiedere un passo manuale.
 */
async function main(): Promise<void> {
  // Prima di qualunque lettura di `process.env`: in sviluppo il percorso e'
  // `npm run dev` senza esportare niente, il `.env` e' alla radice del repo.
  // Sotto compose non trova nulla (il file non c'e' nel container) e va avanti
  // con l'ambiente, che li' e' gia' completo.
  loadRepoEnv();

  const config = loadConfig();
  const logger = createLogger(config.LOG_LEVEL, { svc: 'engine-accounts' });
  const db = createDb(config);

  const migrations = await migrate(db);
  await ensureDefaultClients(db, config);
  logger.info('schema pronto', {
    schema: config.DB_SCHEMA,
    applied: migrations.applied.length,
    present: migrations.alreadyApplied.length,
  });

  const { app } = await buildApp({ config, db, logger });

  // Manutenzione periodica: jti replay, token scaduti, interazioni abbandonate.
  const pruneTimer = setInterval(
    () => {
      pruneExpired(db)
        .then((pruned) => {
          if (Object.values(pruned).some((n) => n > 0)) logger.debug('pulizia periodica', pruned);
        })
        .catch((err) => logger.warn('pulizia periodica fallita', { err: (err as Error).message }));
    },
    15 * 60_000,
  );
  pruneTimer.unref();

  const shutdown = async (signal: string) => {
    logger.info('arresto in corso', { signal });
    clearInterval(pruneTimer);
    await app.close().catch((err) => logger.warn('chiusura app non pulita', { err: (err as Error).message }));
    await db.close().catch(() => undefined);
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ port: config.port, host: config.HOST });
  logger.info('in ascolto', {
    url: `http://${config.HOST}:${config.port}`,
    issuer: config.issuer,
    baseUrl: config.baseUrl,
    discovery: `${config.issuer}/.well-known/openid-configuration`,
    hsts: config.hsts.enabled ? 'attivo' : 'spento',
  });
  warnAboutIssuer(config, logger);
}

/**
 * L'errore piu' silenzioso di questa architettura: l'issuer sbagliato.
 *
 * `OIDC_ISSUER` finisce nel claim `iss` di **ogni** token e i consumer lo
 * confrontano con il proprio. Se resta `localhost` mentre il frontend e' su
 * `streaming.oberdfr.top`, qui tutto sembra funzionare — la discovery risponde,
 * il login va, il token arriva — e il fallimento arriva **dall'altra parte**,
 * come 401 su ogni richiesta API, senza che nessuno colleghi i due fatti.
 *
 * In produzione un issuer di loopback non ha senso (il browser non puo'
 * raggiungerlo da fuori), quindi si rifiuta di partire. Fuori produzione e' solo
 * un avviso: in sviluppo `localhost` e' la scelta giusta.
 */
function warnAboutIssuer(config: Config, logger: ReturnType<typeof createLogger>): void {
  if (config.baseUrl !== config.issuer) {
    logger.warn('PUBLIC_BASE_URL diverso da OIDC_ISSUER', {
      issuer: config.issuer,
      base_url: config.baseUrl,
      effetto: 'i link nelle email useranno PUBLIC_BASE_URL, i token porteranno OIDC_ISSUER',
    });
  }
  let host = '';
  try {
    host = new URL(config.issuer).hostname;
  } catch {
    return;
  }
  if (['localhost', '127.0.0.1', '::1', '[::1]'].includes(host)) {
    logger.warn('issuer di loopback: va bene in sviluppo, rotto in produzione', {
      issuer: config.issuer,
      ricorda: 'i consumer confrontano iss: se diverge, ogni richiesta API risponde 401',
    });
  }
}

main().catch((err) => {
  process.stderr.write(`engine-accounts: avvio fallito: ${(err as Error).message}\n`);
  process.exit(1);
});
