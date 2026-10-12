import type { AccountsStore } from '../domain/ports.js';
import { CORE_SCOPES } from '../oidc/account-adapter.js';

/** Scope validi per un audience: base + quelli del servizio registrato. */
export async function listScopesForAudience(store: AccountsStore, audience: string): Promise<string[]> {
  const services = await store.listServices();
  const service = services.find((s) => s.audience === audience && s.enabled);
  const serviceScopes = (await store.listServiceScopes()).filter((s) => !service || s.serviceId === service.serviceId);
  return [...CORE_SCOPES, ...serviceScopes.map((s) => s.scope)];
}