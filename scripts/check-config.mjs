import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { loadConfig } from '../src/config.ts';

const env = parseEnv(readFileSync(new URL('../.env', import.meta.url), 'utf8'));
const config = loadConfig(env);
if (config.issuer !== config.baseUrl) throw new Error('PUBLIC_BASE_URL must match OIDC_ISSUER');
if (config.NODE_ENV === 'production' && new URL(config.issuer).protocol !== 'https:') {
  throw new Error('Production OIDC issuer must use HTTPS');
}
if (config.MAIL_ENABLED && (!config.SMTP_HOST || !config.SMTP_FROM)) throw new Error('Configure SMTP_HOST and SMTP_FROM');
console.log('EngineAccounts .env is valid (values/secrets not printed). External dependencies still require checks.');
