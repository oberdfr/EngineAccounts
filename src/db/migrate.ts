import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PoolClient } from 'pg';
import type { Db } from './pool.js';
import { logger } from '../logger.js';

const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

export interface MigrationResult {
  applied: string[];
  alreadyApplied: string[];
}

/**
 * Runner minimale: file SQL versionati in ordine, applicati dentro una
 * transazione e registrati in `schema_migrations`. Un advisory lock evita che
 * due processi (per esempio il server e la CLI) migrino in parallelo.
 */
export async function migrate(db: Db): Promise<MigrationResult> {
  const client = await db.pool.connect();
  const applied: string[] = [];
  const alreadyApplied: string[] = [];
  try {
    await client.query(`CREATE SCHEMA IF NOT EXISTS "${db.schema}"`);
    await client.query(`SET search_path TO "${db.schema}", public`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS "schema_migrations" (
        version    text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    // Advisory lock su una chiave fissa: serializza i runner.
    await client.query('SELECT pg_advisory_lock(hashtext($1))', [`${db.schema}:migrate`]);
    try {
      const files = (await fs.readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();
      const { rows } = await client.query<{ version: string }>('SELECT version FROM "schema_migrations"');
      const done = new Set(rows.map((r) => r.version));

      for (const file of files) {
        if (done.has(file)) {
          alreadyApplied.push(file);
          continue;
        }
        const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
        await client.query('BEGIN');
        try {
          // Keep the historical migration file/ledger identity for existing
          // databases, but do not register hardcoded consumer domains on a fresh
          // standalone installation. All new clients come from .env or the CLI.
          if (file !== '0006_default_web_client.sql') await client.query(sql);
          await client.query('INSERT INTO "schema_migrations" (version) VALUES ($1)', [file]);
          await client.query('COMMIT');
          applied.push(file);
          logger.info('migration registrata', { version: file, legacyClientSeedSkipped: file === '0006_default_web_client.sql' });
        } catch (err) {
          await client.query('ROLLBACK');
          throw new Error(`migration ${file} fallita: ${(err as Error).message}`, { cause: err });
        }
      }
    } finally {
      await client.query('SELECT pg_advisory_unlock(hashtext($1))', [`${db.schema}:migrate`]);
    }
  } finally {
    client.release();
  }
  return { applied, alreadyApplied };
}

/** Rimuove i jti replay scaduti e le sessioni/codici scaduti. */
export async function pruneExpired(db: Db): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  const q = async (name: string, sql: string) => {
    const client: PoolClient = await db.pool.connect();
    try {
      const res = await client.query(sql);
      out[name] = res.rowCount ?? 0;
    } finally {
      client.release();
    }
  };
  await q('jti_replay', 'DELETE FROM "jti_replay" WHERE expires_at < now()');
  await q(
    'oidc_codes',
    'DELETE FROM "oidc_codes" WHERE (expires_at IS NOT NULL AND expires_at < now()) OR (revoked_at IS NOT NULL AND revoked_at < now() - interval \'1 day\')',
  );
  await q(
    'oidc_tokens',
    'DELETE FROM "oidc_tokens" WHERE (expires_at IS NOT NULL AND expires_at < now()) OR (revoked_at IS NOT NULL AND revoked_at < now() - interval \'1 day\')',
  );
  await q('oidc_grants', 'DELETE FROM "oidc_grants" WHERE expires_at IS NOT NULL AND expires_at < now()');
  await q('oidc_sessions', 'DELETE FROM "oidc_sessions" WHERE (expires_at IS NOT NULL AND expires_at < now()) OR revoked_at IS NOT NULL');
  await q('oidc_interactions', 'DELETE FROM "oidc_interactions" WHERE expires_at IS NOT NULL AND expires_at < now()');
  await q('account_tokens', 'DELETE FROM "account_tokens" WHERE expires_at < now() OR consumed_at IS NOT NULL');
  return out;
}
