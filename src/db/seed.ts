import type { Config } from '../config.js';
import type { Db } from './pool.js';

/** Client pubblici dichiarati in .env. Nessun consumer imposto dal provider. */
export async function ensureDefaultClients(db: Db, config: Config): Promise<void> {
  const registeredAudiences = new Set<string>();
  for (const client of config.OIDC_CLIENTS_JSON) {
    if (!registeredAudiences.has(client.audience)) {
      const group = config.OIDC_CLIENTS_JSON.filter((item) => item.audience === client.audience);
      const metadata = {
        serviceId: group.find((item) => item.serviceId)?.serviceId,
        serviceName: group.find((item) => item.serviceName)?.serviceName,
        description: group.find((item) => item.serviceDescription)?.serviceDescription,
        adminUrl: group.find((item) => item.adminUrl)?.adminUrl,
        adminApiUrl: group.find((item) => item.adminApiUrl)?.adminApiUrl,
      };
      await db.query(`
        INSERT INTO "${db.schema}"."services" (service_id, audience, name)
        VALUES ($1, $2, $3) ON CONFLICT (audience) DO NOTHING
      `, [metadata.serviceId ?? `client:${client.clientId}`, client.audience, metadata.serviceName ?? client.clientName ?? client.clientId]);
      // Declarative metadata is reapplied at startup; enabled remains a DB switch.
      await db.query(`UPDATE "${db.schema}"."services"
        SET name = $2, description = $3, admin_url = $4, admin_api_url = $5, origin = 'env'
        WHERE audience = $1`, [client.audience, metadata.serviceName ?? client.clientName ?? client.clientId,
        metadata.description ?? '', metadata.adminUrl ?? null, metadata.adminApiUrl ?? null]);
      registeredAudiences.add(client.audience);
    }
    for (const scope of client.scope.filter((s) => !['openid', 'profile', 'email', 'offline_access', 'engine:admin'].includes(s))) {
      await db.query(`
        INSERT INTO "${db.schema}"."streaming_scopes" (scope, service_id, description)
        SELECT $1, service_id, $1 FROM "${db.schema}"."services" WHERE audience = $2
        ON CONFLICT (scope) DO UPDATE SET service_id = EXCLUDED.service_id
      `, [scope, client.audience]);
    }
    await db.query(`
      INSERT INTO "${db.schema}"."clients" (
        client_id, client_name, client_type, token_endpoint_auth_method,
        redirect_uris, post_logout_redirect_uris, scope, audience, backchannel_events_uri,
        grant_types, response_types, application_type, cors_origins
      ) VALUES ($1, $2, 'public', 'none', $3, $4, $5, $6, $7,
        COALESCE($8::text[], '{authorization_code,refresh_token}'),
        CASE WHEN $8::text[] IS NOT NULL AND NOT ('authorization_code' = ANY($8::text[])) THEN '{}'::text[] ELSE '{code}'::text[] END,
        COALESCE($9::text, 'web'), COALESCE($10::text[], '{}'))
      ON CONFLICT (client_id) DO UPDATE SET
        client_name = EXCLUDED.client_name,
        redirect_uris = EXCLUDED.redirect_uris,
        post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
        scope = EXCLUDED.scope, audience = EXCLUDED.audience,
        backchannel_events_uri = EXCLUDED.backchannel_events_uri,
        -- Metadati opzionali: se il .env non li dichiara, la riga esistente resta com'e'.
        grant_types = CASE WHEN $8::text[] IS NULL THEN clients.grant_types ELSE EXCLUDED.grant_types END,
        response_types = CASE WHEN $8::text[] IS NULL THEN clients.response_types ELSE EXCLUDED.response_types END,
        application_type = COALESCE($9::text, clients.application_type),
        cors_origins = COALESCE($10::text[], clients.cors_origins),
        updated_at = now()
      WHERE clients.client_type = 'public'
    `, [client.clientId, client.clientName ?? client.clientId, client.redirectUris,
      client.postLogoutRedirectUris, client.scope, client.audience, client.backchannelEventsUri ?? null,
      client.grantTypes ?? null, client.applicationType ?? null, client.corsOrigins ?? null]);
  }
}
