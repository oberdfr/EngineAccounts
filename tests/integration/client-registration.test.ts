import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { REPO_ROOT, testEnv } from '../helpers/harness.js';

/**
 * La CLI rifiuta i client che non potrebbero mai autenticarsi.
 *
 * `client add` e' il punto in cui l'operatore decide cosa esiste nel mondo:
 * un client che nasce senza `openid` e' un client che ricevera' `invalid_scope`
 * alla prima richiesta di autorizzazione, e il messaggio arrivera' a qualcuno
 * che non c'entra. Fallire subito, con il motivo, e' il comportamento giusto.
 *
 * Il test chiama la CLI **in un processo separato**, come farebbe l'operatore:
 * non interessa il codice che produce l'errore, interessa l'errore.
 */

/**Esegue la CLI e restituisce stdout+stderr con lo stato di uscita. */
function cli(args: string[]): { output: string; status: number } {
  try {
    const stdout = execFileSync(
      'node',
      [
        path.join(REPO_ROOT, 'node_modules/tsx/dist/cli.mjs'),
        path.join(REPO_ROOT, 'src/cli/main.ts'),
        ...args,
      ],
      {
        env: { ...process.env, ...testEnv() },
        encoding: 'utf8',
        cwd: REPO_ROOT,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    return { output: stdout, status: 0 };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { output: `${e.stdout ?? ''}${e.stderr ?? ''}`, status: e.status ?? 1 };
  }
}

describe('client add rifiuta un client che non puo\' autenticarsi', () => {
  it('rifiuta la lista di scope di servizio senza openid (il caso del contratto §9 prima della correzione)', () => {
    const result = cli([
      'client',
      'add',
      'test-senza-openid',
      '--type',
      'public',
      '--redirect-uri',
      'http://localhost:5173/auth/callback',
      // Solo scope di servizio: nessuno scope OIDC.
      '--scope',
      'streaming:catalog,streaming:playback,streaming:account',
      '--audience',
      'https://api.engine.local/streaming',
    ]);

    expect(result.status, `la CLI doveva fallire, output:\n${result.output}`).not.toBe(0);
    expect(result.output).toContain('openid');
    // Il messaggio deve dire *perche'*, non solo che manca.
    expect(result.output).toContain('invalid_scope');
    // E deve proporre la riga di comando che funziona.
    expect(result.output).toContain('--scope openid,profile,email,offline_access');
    // E non deve aver scritto niente.
    expect(result.output).not.toContain('client registrato');
  }, 60_000);

  it('accetta un client con openid, anche se gli scope sono minimi', () => {
    const result = cli([
      'client',
      'add',
      'test-solo-openid',
      '--type',
      'public',
      '--redirect-uri',
      'http://localhost:5173/auth/callback',
      '--scope',
      'openid',
      '--audience',
      'https://api.engine.local/streaming',
    ]);
    expect(result.status, `output:\n${result.output}`).toBe(0);
    expect(result.output).toContain('client registrato');
    expect(result.output).toContain('openid');
  }, 60_000);

  it('accetta la procedura documentata: openid + profilo + offline + servizio', () => {
    const result = cli([
      'client',
      'add',
      'test-procedura',
      '--type',
      'public',
      '--redirect-uri',
      'http://localhost:5173/auth/callback',
      '--post-logout-uri',
      'http://localhost:5173/',
      '--scope',
      'openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account',
      '--audience',
      'https://api.engine.local/streaming',
    ]);
    expect(result.status, `output:\n${result.output}`).toBe(0);
    expect(result.output).toContain('client registrato');
  }, 60_000);
});