/**
 * Copia in `dist/` gli asset che `tsc` non tocca.
 *
 * Le pagine sono servite da `/static/*` (CSS e JS esterni, perche' la CSP non
 * ammette `unsafe-inline`). Senza questo passo l'avvio da `dist` risponderebbe
 * 404 su ogni stylesheet.
 */
import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Coppie (sorgente, destinazione): tutto cio` che `tsc` non tocca. */
const ASSETS = [
  [path.join(root, 'src', 'ui', 'static'), path.join(root, 'dist', 'ui', 'static')],
  [path.join(root, 'src', 'security', 'data'), path.join(root, 'dist', 'security', 'data')],
];

for (const [from, to] of ASSETS) {
  await mkdir(path.dirname(to), { recursive: true });
  await cp(from, to, { recursive: true });
  process.stdout.write(`asset copiati in ${path.relative(root, to)}\n`);
}