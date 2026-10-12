import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // I test di integrazione condividono il database di sviluppo: le suite girano
    // in sequenza (un solo processo) per non litigare sulle tabelle.
    fileParallelism: false,
    isolate: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
    reporters: ['default'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/cli/main.ts', 'src/ui/static/**'],
    },
  },
});