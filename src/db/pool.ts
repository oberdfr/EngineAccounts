import { Pool, type PoolClient, type QueryResultRow } from 'pg';
import type { Config } from '../config.js';
import { logger } from '../logger.js';

/**
 * Pool Postgres. Il database `engine` e' condiviso con il proxy: ogni query
 * porta il prefisso di schema, cosi' nessuna tabella esce da `DB_SCHEMA`.
 */

export interface Db {
  pool: Pool;
  schema: string;
  query<T extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]): Promise<T[]>;
  one<T extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]): Promise<T | undefined>;
  tx<T>(fn: (client: PoolClient) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/** Prefissa un identificatore di tabella con lo schema del servizio. */
export function table(db: Db, name: string): string {
  return `"${db.schema}"."${name}"`;
}

export function createDb(config: Config): Db {
  const pool = new Pool({
    connectionString: config.DATABASE_URL,
    max: config.DB_POOL_MAX,
    ssl: config.DB_SSL ? { rejectUnauthorized: false } : undefined,
    application_name: 'engine-accounts',
    // `it_IT` come nel compose: l'ordinamento dei test conta.
    options: `-c search_path=${config.DB_SCHEMA},public -c timezone=UTC`,
  });

  pool.on('error', (err) => {
    logger.error('errore pool postgres inatteso', { err: err.message });
  });

  const db: Db = {
    pool,
    schema: config.DB_SCHEMA,
    async query<T extends QueryResultRow>(text: string, params: unknown[] = []): Promise<T[]> {
      const result = await pool.query<T>(text, params as never[]);
      return result.rows;
    },
    async one<T extends QueryResultRow>(text: string, params: unknown[] = []): Promise<T | undefined> {
      const rows = await pool.query<T>(text, params as never[]);
      return rows.rows[0];
    },
    async tx<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await fn(client);
        await client.query('COMMIT');
        return out;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    },
    async close() {
      await pool.end();
    },
  };

  return db;
}