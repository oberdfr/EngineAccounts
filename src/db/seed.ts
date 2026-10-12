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
        redirect_uris, post_logout_redirect_uris, scope, audience, backchannel_events_uri
      ) VALUES ($1, $2, 'public', 'none', $3, $4, $5, $6, $7)
      ON CONFLICT (client_id) DO UPDATE SET
        client_name = EXCLUDED.client_name,
        redirect_uris = EXCLUDED.redirect_uris,
        post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
        scope = EXCLUDED.scope, audience = EXCLUDED.audience,
        backchannel_events_uri = EXCLUDED.backchannel_events_uri,
        updated_at = now()
      WHERE clients.client_type = 'public'
    `, [client.clientId, client.clientName ?? client.clientId, client.redirectUris,
      client.postLogoutRedirectUris, client.scope, client.audience, client.backchannelEventsUri ?? null]);
  }
}
