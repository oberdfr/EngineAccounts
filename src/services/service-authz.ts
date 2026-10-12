import type { FastifyInstance } from 'fastify';
import type { AccountsStore } from '../domain/ports.js';
import type { ArgonConfig } from '../security/argon.js';
import { decoyVerify, verifyPassword } from '../security/password.js';
import type { RateLimiter } from '../security/rate-limit.js';
import type { AdministrationService } from './administration.js';

/** AdministrationService can implement this port without exposing its DB. */
export interface ServiceAuthorization {
  rolesFor(sub: string, audience: string): Promise<string[]>;
}

export function serviceAuthorizationFromAdministration(admin: Pick<AdministrationService, 'listServices' | 'authorization'>): ServiceAuthorization {
  return {
    async rolesFor(sub, audience) {
      const service = (await admin.listServices()).find((s) => s.enabled && s.audience === audience);
      if (!service) return [];
      const role = await admin.authorization(sub, service.serviceId);
      return role.admin && role.status === 'active' ? role.global ? ['admin', 'global'] : ['admin'] : [];
    },
  };
}

export interface ServiceAuthzDeps {
  store: AccountsStore;
  argon: ArgonConfig;
  limiter: RateLimiter;
  authorization: ServiceAuthorization;
}

/** Machine-only CSRF exception: HTTP Basic, never cookies or browser Origin. */
export async function registerServiceAuthzRoute(app: FastifyInstance, deps: ServiceAuthzDeps): Promise<void> {
  app.post('/services/authz', { bodyLimit: 4096 }, async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    if (request.headers.origin !== undefined || request.headers.cookie !== undefined ||
        request.headers['sec-fetch-site'] !== undefined) {
      return reply.code(403).send({ error: 'machine_credentials_required' });
    }
    const rate = deps.limiter.checkIp(`service-authz:${request.ip}`, 30, 60_000);
    if (!rate.allowed) return reply.code(429).header('Retry-After', rate.retryAfterSeconds).send({ error: 'rate_limited' });
    const credentials = parseBasic(request.headers.authorization);
    const client = credentials ? await deps.store.findClient(credentials.clientId) : undefined;
    let valid = false;
    if (credentials && client?.enabled && client.clientType === 'confidential' &&
        client.tokenEndpointAuthMethod === 'client_secret_basic' && client.scope.includes('engine:admin') && client.clientSecretHash?.startsWith('$argon2')) {
      valid = await verifyPassword(client.clientSecretHash, credentials.secret, deps.argon);
    } else {
      await decoyVerify(credentials?.secret ?? '', deps.argon);
    }
    if (!valid || !client) return reply.code(401).header('WWW-Authenticate', 'Basic realm="services"').send({ error: 'invalid_client' });
    const body = request.body as Record<string, unknown> | undefined;
    if (!body || typeof body.sub !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.sub) ||
        typeof body.serviceId !== 'string' || Object.keys(body).some((k) => !['sub', 'serviceId'].includes(k))) {
      return reply.code(400).send({ error: 'invalid_request' });
    }
    const service = (await deps.store.listServices()).find((s) => s.enabled && s.serviceId === body.serviceId && s.audience === client.audience);
    if (!service) {
      return reply.code(404).send({ error: 'not_found' });
    }
    const user = await deps.store.findUserById(body.sub);
    const active = Boolean(user && user.status === 'active' && !user.mustChangePassword);
    const assigned = active && client.scope.includes('engine:admin')
      ? await deps.authorization.rolesFor(body.sub, service.audience) : [];
    const roles = assigned.includes('admin') ? assigned.includes('global') ? ['admin', 'global'] : ['admin'] : [];
    return reply.send({ admin: roles.includes('admin'), global: roles.includes('global'), status: user?.status ?? 'deleted' });
  });
}

function parseBasic(header: string | undefined): { clientId: string; secret: string } | undefined {
  if (!header || header.length > 4096 || !/^Basic [A-Za-z0-9+/]+={0,2}$/.test(header)) return undefined;
  const encoded = header.slice(6);
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.toString('base64') !== encoded) return undefined;
  const decoded = bytes.toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator < 1) return undefined;
  try {
    // RFC 6749: client id and secret are form-url-encoded before Basic.
    const clientId = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, ' '));
    const secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, ' '));
    if (!clientId || !secret || /[\x00-\x1f\x7f]/.test(clientId + secret)) return undefined;
    return { clientId, secret };
  } catch { return undefined; }
}
