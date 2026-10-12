import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Caricamento del `.env` di sviluppo.
 *
 * Node 24 espone `process.loadEnvFile()`: nessuna dipendenza, e le variabili
 * **gia' presenti** nell'ambiente hanno la precedenza (comportamento verificato),
 * quindi un export esplicito vince sempre sul file. Sotto compose non serve: il
 * compose passa `env_file` al container.
 *
 * Il file vive alla radice di EngineAccounts. Non cerca configurazioni nei
 * repository vicini: EngineAccounts deve poter funzionare da solo.
 */

let loaded = false;

/** src/ e dist/ sono immediatamente sotto la radice del repository. */
function repoRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '..');
}

/**
 * Solo la radice del repository. La cwd puo' appartenere a un altro progetto.
 */
function candidates(): string[] {
  return [
    path.join(repoRoot(), '.env'),
  ];
}

/**
 * Carica il `.env` se esiste. Idempotente e silenzioso se assente: in
 * produzione il file non c'e' e non deve esserci, la configurazione arriva
 * tutta dall'ambiente.
 *
 * @returns il percorso caricato, o `null` se nessun `.env` era presente.
 */
export function loadRepoEnv(): string | null {
  if (loaded) return null;
  for (const candidate of candidates()) {
    if (!fs.existsSync(candidate)) continue;
    try {
      process.loadEnvFile(candidate);
      loaded = true;
      return candidate;
    } catch {
      // File illeggibile o malformato: si prosegue con l'ambiente corrente,
      // che in sviluppo vuol dire "va bene cosi'", in produzione "manca roba"
      // e se ne accorgera' `loadConfig()` con un errore esplicito.
      continue;
    }
  }
  loaded = true;
  return null;
}
