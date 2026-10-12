import { loadConfig } from '../config.js';
import { loadRepoEnv } from '../env.js';
import { createDb } from './pool.js';
import { migrate } from './migrate.js';

/** `npm run migrate` — applica le migration pendenti. */
async function main() {
  // Come `server.ts`: il `.env` della radice va letto prima di `process.env`.
  loadRepoEnv();
  const config = loadConfig();
  const db = createDb(config);
  try {
    const result = await migrate(db);
    console.log(
      `schema ${config.DB_SCHEMA}: ${result.applied.length} applicate, ${result.alreadyApplied.length} gia' presenti`,
    );
    for (const version of result.applied) console.log(`  + ${version}`);
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(`migrate: ${(err as Error).message}`);
  process.exit(1);
});