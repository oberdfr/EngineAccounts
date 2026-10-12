import crypto from 'node:crypto';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { isAllowedBackchannelUri, loadConfig, type Config } from '../config.js';
import { loadRepoEnv } from '../env.js';
import { createDb, type Db } from '../db/pool.js';
import { migrate } from '../db/migrate.js';
import { createAccountsStore, createOidcTokenStore } from '../db/repositories.js';
import { hashPassword } from '../security/password.js';
import { rotateKeys } from '../oidc/provider.js';
import { listScopesForAudience } from './scope-catalog.js';
import { AdministrationService } from '../services/administration.js';
import { SessionManager } from '../services/session-manager.js';

/**
 * CLI admin. Nessuna UI per-servizio (D2): tutto da riga di comando.
 *
 *   engine-accounts client add <client_id> --type public|confidential \
 *       --redirect-uri <uri> --post-logout-uri <uri> \
 *       --scope openid,profile,email,offline_access,streaming:catalog,streaming:playback,streaming:account \
 *       --audience https://api.engine.local/streaming \
 *       [--backchannel-events-uri <url>]
 *
 *   engine-accounts user block <sub>       engine-accounts user unblock <sub>
 *   engine-accounts sessions revoke <sub>  engine-accounts keys rotate
 *   engine-accounts client list            engine-accounts scopes list
 */

const USAGE = `engine-accounts — CLI admin

  client add <client_id> --type public|confidential --redirect-uri <uri>
      [--post-logout-uri <uri>] [--scope a,b,c] --audience <url>
      [--backchannel-events-uri <url>] [--name <nome>] [--rotate]
  client list
  client remove <client_id>

  user add <email> --password <pwd> [--name <nome>] [--verified]
  user password <sub_o_email> --password <pwd>
  user block <sub> [--reason <testo>]
  user unblock <sub>
  user list
  user promote|demote <sub> --global [--force]
  service-admin grant|revoke <sub> <service_id>
  service add <service_id> --audience <url> [--service-name <name>]
      [--service-description <text>] [--admin-url <url>] [--admin-api-url <url>]

  sessions revoke <sub> [--except-session <id>]

  keys rotate
  keys list

  scopes list
`;

interface Parsed {
  command: string;
  positionals: string[];
  values: Record<string, string | boolean | undefined>;
}

const OPTIONS = {
  type: { type: 'string' },
  'redirect-uri': { type: 'string', multiple: true },
  'post-logout-uri': { type: 'string', multiple: true },
  scope: { type: 'string' },
  audience: { type: 'string' },
  'backchannel-events-uri': { type: 'string' },
  name: { type: 'string' },
  password: { type: 'string' },
  verified: { type: 'boolean' },
  global: { type: 'boolean' },
  force: { type: 'boolean' },
  'service-id': { type: 'string' },
  'service-name': { type: 'string' },
  'service-description': { type: 'string' },
  'admin-url': { type: 'string' },
  'admin-api-url': { type: 'string' },
  reason: { type: 'string' },
  'except-session': { type: 'string' },
  rotate: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
} as const;

function parse(argv: string[]): Parsed {
  const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  const command = positionals.shift() ?? 'help';
  return { command, positionals, values: values as Parsed['values'] };
}

/** Il secret in chiaro esiste solo qui, nel comando che lo crea. */
function generateClientSecret(): string {
  return `ea_${crypto.randomBytes(32).toString('base64url')}`;
}

export async function runCli(argv: string[]): Promise<number> {
  const parsed = parse(argv);
  if (parsed.command === 'help' || parsed.values.help === true || argv.length === 0) {
    process.stdout.write(USAGE);
    return 0;
  }

  // La CLI parte anche senza `npm run migrate` (lei stessa migra), ma sempre
  // con la stessa configurazione del server: `.env` incluso.
  loadRepoEnv();
  const config = loadConfig();
  const db = createDb(config);
  try {
    await migrate(db);
    switch (parsed.command) {
      case 'client':
        return await clientCommand(parsed, config, db);
      case 'user':
        return await userCommand(parsed, config, db);
      case 'service-admin':
        return await serviceAdminCommand(parsed, config, db);
      case 'service':
        return await serviceCommand(parsed, config, db);
      case 'sessions':
        return await sessionsCommand(parsed, config, db);
      case 'keys':
        return await keysCommand(parsed, config);
      case 'scopes':
        return await scopesCommand(parsed, config, db);
      default:
        process.stderr.write(`comando sconosciuto: ${parsed.command}\n\n${USAGE}`);
        return 2;
    }
  } finally {
    await db.close();
  }
}

async function clientCommand(parsed: Parsed, config: Config, db: Db): Promise<number> {
  const store = createAccountsStore(db);
  const sub = parsed.positionals[0];
  switch (sub) {
    case 'add':
      return clientAdd(parsed, config, db, store);
    case 'list': {
      const clients = await store.listClients();
      if (!clients.length) return log('nessun client registrato');
      process.stdout.write('CLIENT_ID                              TIPO           AUDIENCE\n');
      for (const client of clients) {
        process.stdout.write(
          `${client.clientId.padEnd(38)} ${client.clientType.padEnd(14)} ${client.audience}` +
            `${client.backchannelEventsUri ? '  (backchannel)' : ''}\n`,
        );
      }
      return 0;
    }
    case 'remove': {
      const clientId = parsed.positionals[1];
      if (!clientId) return log('manca client_id', true);
      await db.query(`DELETE FROM "${db.schema}"."clients" WHERE client_id = $1`, [clientId]);
      return log(`client ${clientId} rimosso`);
    }
    default:
      return log('uso: client add|list|remove', true);
  }
}

async function clientAdd(
  parsed: Parsed,
  config: Config,
  db: Db,
  store: ReturnType<typeof createAccountsStore>,
): Promise<number> {
  const clientId = parsed.positionals[1];
  const type = parsed.values.type;
  if (!clientId || (type !== 'public' && type !== 'confidential')) {
    return log('uso: client add <client_id> --type public|confidential --redirect-uri <uri> ...', true);
  }

  const redirectUris = toArray(parsed.values['redirect-uri']);
  if (!redirectUris.length) return log('manca almeno --redirect-uri (match esatto obbligatorio)', true);
  const postLogout = toArray(parsed.values['post-logout-uri']);
  const audience = String(parsed.values.audience ?? config.OIDC_AUDIENCE);
  const scope = String(parsed.values.scope ?? 'openid profile email offline_access')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  // Gli scope richiesti devono esistere: niente scope inventati.
  const known = new Set(['openid', 'profile', 'email', 'offline_access', 'engine:admin', ...(await listScopesForAudience(store, audience))]);
  const unknown = scope.filter((s) => !known.has(s));
  if (unknown.length) {
    return log(`scope non supportati: ${unknown.join(', ')} (scope disponibili: ${[...known].sort().join(', ')})`, true);
  }

  /*
   * `openid` e' obbligatorio, e il motivo va detto adesso.
   *
   * Senza `openid` il provider rifiuta ogni richiesta di autorizzazione con
   * `error=invalid_scope` (OIDC Core §3.1.2.1): il client nasce e non potra'
   * mai autenticarsi. Fallire qui significa un messaggio che spiega il motivo,
   * invece di un errore che arriva tre richieste piu' avanti e sembra un altro
   * problema. Lo scope e' tra i `clientDefaults` del provider, quindi il
   * difetto sarebbe silenzioso e permanente.
   */
  if (!scope.includes('openid')) {
    return log(
      "manca lo scope 'openid': senza, il provider rifiuta ogni richiesta di " +
        "autorizzazione con error=invalid_scope e il client non puo' autenticarsi.\n" +
        `  --scope openid,profile,email,offline_access${scope.length ? `,${scope.join(',')}` : ''}`,
      true,
    );
  }

  const backchannel = parsed.values['backchannel-events-uri'];
  if (backchannel && !isAllowedBackchannelUri(String(backchannel), config.BACKCHANNEL_HTTP_ALLOWED_ORIGINS)) {
    return log('--backchannel-events-uri richiede HTTPS, loopback o origine HTTP interna autorizzata', true);
  }

  let secretHash: string | null = null;
  let plainSecret: string | null = null;
  if (type === 'confidential') {
    plainSecret = generateClientSecret();
    secretHash = await hashPassword(plainSecret, config);
  }

  if (parsed.values['service-id']) {
    await cliAdministration(db, config).upsertService('admin:cli', {
      serviceId: String(parsed.values['service-id']), audience,
      name: String(parsed.values['service-name'] ?? parsed.values['service-id']),
      description: parsed.values['service-description'] ? String(parsed.values['service-description']) : undefined,
      adminUrl: parsed.values['admin-url'] ? String(parsed.values['admin-url']) : null,
      adminApiUrl: parsed.values['admin-api-url'] ? String(parsed.values['admin-api-url']) : null,
    });
  } else if (!(await store.listServices()).some((service) => service.audience === audience)) {
    await cliAdministration(db, config).upsertService('admin:cli', {
      serviceId: `client:${clientId}`, audience, name: String(parsed.values.name ?? clientId),
    });
  }
  await store.upsertClient({
    clientId,
    clientName: String(parsed.values.name ?? clientId),
    clientType: type,
    clientSecretHash: secretHash,
    redirectUris,
    postLogoutRedirectUris: postLogout,
    // Solo Authorization Code + refresh: niente implicit, niente password grant.
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scope,
    audience,
    backchannelEventsUri: backchannel ? String(backchannel) : null,
    tokenEndpointAuthMethod: type === 'public' ? 'none' : 'client_secret_basic',
    enabled: true,
  });

  process.stdout.write(`client registrato: ${clientId}\n`);
  process.stdout.write(`  tipo            ${type}\n`);
  process.stdout.write(`  audience        ${audience}\n`);
  process.stdout.write(`  scope           ${scope.join(' ')}\n`);
  process.stdout.write(`  redirect_uri    ${redirectUris.join('\n                   ')}\n`);
  if (postLogout.length) process.stdout.write(`  post_logout_uri ${postLogout.join('\n                   ')}\n`);
  if (backchannel) process.stdout.write(`  backchannel     ${String(backchannel)}\n`);
  if (plainSecret) {
    // Unica volta in cui il segreto esiste in chiaro.-after: solo l'hash.
    process.stdout.write(`\n  CLIENT_SECRET (mostrato una volta sola):\n  ${plainSecret}\n\n`);
  }
  return 0;
}

async function userCommand(
  parsed: Parsed,
  config: Config,
  db: Db,
): Promise<number> {
  const store = createAccountsStore(db);
  const tokens = createOidcTokenStore(db);
  const administration = cliAdministration(db, config);
  const action = parsed.positionals[0];
  const sub = parsed.positionals[1];

  if (action === 'list') {
    const result = await administration.accounts({ pageSize: 100, role: parsed.values.global ? 'global' : undefined });
    for (const user of result.items) process.stdout.write(`${user.id} ${user.email} ${user.status}${user.isGlobalAdmin ? ' [global-admin]' : ''}\n`);
    return log(`totale: ${result.total} (primi 100)`);
  }

  if (action === 'promote' || action === 'demote') {
    if (!sub || parsed.values.global !== true) return log('uso: user promote|demote <sub> --global [--force]', true);
    await administration.setGlobalRole('admin:cli', sub, action === 'promote', { force: parsed.values.force === true });
    return log(`ruolo global ${action === 'promote' ? 'assegnato' : 'revocato'}: ${sub}`);
  }

  if (action === 'add') {
    const email = sub;
    if (!email) return log('uso: user add <email> --password <pwd> [--name <nome>] [--verified]', true);
    const password = parsed.values.password ? String(parsed.values.password) : null;
    if (!password) return log('manca --password', true);
    const existing = await store.findUserByEmail(email);
    if (existing) return log(`utente con email ${email} gia' esistente (id: ${existing.id})`, true);
    const passwordHash = await hashPassword(password, config);
    const displayName = parsed.values.name ? String(parsed.values.name) : null;
    const verified = parsed.values.verified === true;
    const user = await store.createUser({
      email,
      passwordHash,
      displayName,
      emailVerifiedAt: verified ? new Date() : null,
    });
    return log(`utente creato:\n  id:    ${user.id}\n  email: ${user.email}\n  stato: ${user.status} (verificato: ${verified})`);
  }

  if (action === 'password') {
    if (!sub) return log('uso: user password <sub_o_email> --password <pwd>', true);
    const password = parsed.values.password ? String(parsed.values.password) : null;
    if (!password) return log('manca --password', true);
    const user = sub.includes('@')
      ? await store.findUserByEmail(sub)
      : (await store.findUserById(sub)) ?? (await store.findUserByEmail(sub));
    if (!user) return log(`utente ${sub} non trovato`, true);
    const passwordHash = await hashPassword(password, config);
    await store.updateUser(user.id, { passwordHash, failedLogins: 0, lockedUntil: null });
    return log(`password aggiornata per utente ${user.email} (${user.id})`);
  }

  if (!sub) return log('uso: user block|unblock|list|add|password <sub>', true);
  if (action !== 'block' && action !== 'unblock') return log('uso: user block|unblock <sub>', true);

  const user = await store.findUserById(sub);
  if (!user) return log(`utente ${sub} non trovato`, true);

  const reason = action === 'block' ? (String(parsed.values.reason ?? 'amministrazione')) : null;
  await administration.mutateAccount('admin:cli', sub, action, { reason: reason ?? undefined, force: parsed.values.force === true });

  if (action === 'block') {
    // Bloccare deve chiudere le sessioni e revocare i token: altrimenti un
    // account bloccato continua a funzionare con i token gia' emessi.
    return log(`utente ${sub} bloccato (grant revocati, sessioni provider chiuse)`);
  }

  await store.updateUser(sub, { failedLogins: 0, lockedUntil: null });
  return log(`utente ${sub} sbloccato`);
}

function cliAdministration(db: Db, config: Config): AdministrationService {
  const store = createAccountsStore(db);
  const tokens = createOidcTokenStore(db);
  const sessions = new SessionManager({ config, store, tokens });
  return new AdministrationService({ db, config, store, tokens, sessions });
}
async function serviceAdminCommand(parsed: Parsed, config: Config, db: Db): Promise<number> {
  const [action, sub, serviceId] = parsed.positionals;
  if (!serviceId || !sub || !['grant', 'revoke'].includes(action ?? '')) return log('uso: service-admin grant|revoke <sub> <service_id>', true);
  const administration = cliAdministration(db, config);
  if (action === 'grant') await administration.grantAssignment('admin:cli', sub, serviceId);
  else await administration.revokeAssignment('admin:cli', sub, serviceId);
  return log(`service-admin ${action}: ${sub} / ${serviceId}`);
}
async function serviceCommand(parsed: Parsed, config: Config, db: Db): Promise<number> {
  const [action, serviceId] = parsed.positionals;
  if (action !== 'add' || !serviceId || !parsed.values.audience) return log('uso: service add <service_id> --audience <url>', true);
  await cliAdministration(db, config).upsertService('admin:cli', {
    serviceId, audience: String(parsed.values.audience), name: String(parsed.values['service-name'] ?? serviceId),
    description: parsed.values['service-description'] ? String(parsed.values['service-description']) : undefined,
    adminUrl: parsed.values['admin-url'] ? String(parsed.values['admin-url']) : null,
    adminApiUrl: parsed.values['admin-api-url'] ? String(parsed.values['admin-api-url']) : null,
  });
  return log(`servizio registrato: ${serviceId}`);
}

async function sessionsCommand(parsed: Parsed, _config: Config, db: Db): Promise<number> {
  const store = createAccountsStore(db);
  const tokens = createOidcTokenStore(db);
  if (parsed.positionals[0] !== 'revoke') return log('uso: sessions revoke <sub>', true);
  const sub = parsed.positionals[1];
  if (!sub) return log('manca <sub>', true);
  const except = parsed.values['except-session'];
  const revokedSessions = await store.revokeAllSessions(sub, 'admin_revoke', except ? String(except) : undefined);
  const revokedTokens = await tokens.revokeUserGrants(sub);
  await store.appendAudit({
    userId: sub,
    actor: 'admin:cli',
    event: 'sessions.revoked_by_admin',
    outcome: 'info',
    metadata: { sessions: revokedSessions.length, tokens: revokedTokens },
  });
  return log(`sessioni revocate: ${revokedSessions.length}, token revocate: ${revokedTokens}`);
}

async function keysCommand(parsed: Parsed, config: Config): Promise<number> {
  if (parsed.positionals[0] === 'rotate') {
    const result = await rotateKeys(config);
    process.stdout.write(`nuova chiave: ${result.kid}\n`);
    process.stdout.write(`chiavi nel JWKS: ${result.retained}\n`);
    process.stdout.write(
      'Le chiavi precedenti restano pubblicate finche\' i token che hanno firmato non scadono.\n' +
        'Riavvia il servizio perche\' la nuova chiave venga usata per firmare.\n',
    );
    return 0;
  }
  if (parsed.positionals[0] === 'list') {
    const { loadOrCreateJwks } = await import('../oidc/provider.js');
    const jwks = await loadOrCreateJwks(config);
    process.stdout.write('KID                ALG      KTY\n');
    for (const key of jwks.keys) {
      process.stdout.write(`${String(key.kid).padEnd(18)} ${String(key.alg ?? '-').padEnd(8)} ${String(key.kty)}\n`);
    }
    return 0;
  }
  return log('uso: keys rotate|list', true);
}

async function scopesCommand(parsed: Parsed, _config: Config, db: Db): Promise<number> {
  if (parsed.positionals[0] !== 'list') return log('uso: scopes list', true);
  const store = createAccountsStore(db);
  const services = await store.listServices();
  const scopes = await store.listServiceScopes();
  for (const service of services) {
    process.stdout.write(`\n${service.serviceId} (${service.audience})${service.enabled ? '' : ' [disabilitato]'}\n`);
    for (const scope of scopes.filter((s) => s.serviceId === service.serviceId)) {
      process.stdout.write(`  ${scope.scope.padEnd(22)} ${scope.description}\n`);
    }
  }
  process.stdout.write('\nopenid profile email offline_access   (scope base, nel core)\n');
  return 0;
}

function toArray(value: string | string[] | boolean | undefined): string[] {
  if (value === undefined || typeof value === 'boolean') return [];
  return (Array.isArray(value) ? value : [value]).filter((v) => typeof v === 'string' && v.length > 0);
}

function log(message: string, isError = false): number {
  (isError ? process.stderr : process.stdout).write(`${message}\n`);
  return isError ? 1 : 0;
}

/* Entry point: `npm run cli -- <comando>`. */
const isMain =
  process.argv[1] !== undefined &&
  (import.meta.url === pathToFileURL(process.argv[1]).href || process.argv[1].endsWith('main.ts'));

if (isMain) {
  runCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`cli: ${(err as Error).message}\n`);
      process.exit(1);
    });
}
