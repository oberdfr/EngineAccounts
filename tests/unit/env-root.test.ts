import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

describe('standalone .env discovery', () => {
  it('does not read the caller repository when the own .env is absent', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'engineaccounts-env-'));
    try {
      const root = path.join(temp, 'EngineAccounts');
      mkdirSync(path.join(root, 'src'), { recursive: true });
      writeFileSync(path.join(temp, '.env'), 'EA_ENV_ROOT_TEST=wrong-parent\n');
      cpSync(fileURLToPath(new URL('../../src/env.ts', import.meta.url)), path.join(root, 'src', 'env.ts'));
      const code = `const {loadRepoEnv}=await import(${JSON.stringify(path.join(root, 'src', 'env.ts'))});loadRepoEnv();console.log(process.env.EA_ENV_ROOT_TEST??'not-loaded')`;
      expect(execFileSync(process.execPath, ['--input-type=module', '-e', code], {
        cwd: temp, env: { PATH: process.env.PATH }, encoding: 'utf8',
      }).trim()).toBe('not-loaded');
    } finally { rmSync(temp, { recursive: true, force: true }); }
  });
  it.each(['src', 'dist'])('loads only the checkout root from %s, not the parent repository', (dir) => {
    const temp = mkdtempSync(path.join(tmpdir(), 'engineaccounts-env-'));
    try {
      const root = path.join(temp, 'EngineAccounts');
      mkdirSync(path.join(root, dir), { recursive: true });
      writeFileSync(path.join(temp, '.env'), 'EA_ENV_ROOT_TEST=wrong-parent\n');
      writeFileSync(path.join(root, '.env'), 'EA_ENV_ROOT_TEST=standalone\n');
      const source = fileURLToPath(new URL('../../src/env.ts', import.meta.url));
      cpSync(source, path.join(root, dir, 'env.ts'));
      const code = `const {loadRepoEnv}=await import(${JSON.stringify(path.join(root, dir, 'env.ts'))});loadRepoEnv();console.log(process.env.EA_ENV_ROOT_TEST)`;
      const result = execFileSync(process.execPath, ['--input-type=module', '-e', code], {
        cwd: temp, env: { PATH: process.env.PATH }, encoding: 'utf8',
      });
      expect(result.trim()).toBe('standalone');
    } finally { rmSync(temp, { recursive: true, force: true }); }
  });
});
