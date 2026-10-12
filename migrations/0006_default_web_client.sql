-- 0006_default_web_client.sql -- registrazione automatica dei client web SPA di default
-- Ingresso pubblico https://streaming.oberdfr.top (build di produzione servito da
-- `vite preview`) piu' gli ingressi LAN di sviluppo su 5173/5174.
-- Questa migration e' gia' applicata sul database in esercizio: non va rinominata
-- e non va affiancata da una nuova. Le righe vive sono allineate a startup da
-- src/db/seed.ts (INSERT ... ON CONFLICT DO UPDATE), quindi il contenuto qui
-- documenta lo stato atteso per gli ambienti che la eseguono da zero.
-- URI esatte: niente wildcard, niente slash finale sul callback (OIDC confronta
-- stringhe), e https per l'ingresso pubblico terminate dal tunnel.
INSERT INTO clients (
  client_id,
  client_name,
  client_type,
  token_endpoint_auth_method,
  redirect_uris,
  post_logout_redirect_uris,
  scope,
  audience
) VALUES (
  'streamingengine-web',
  'StreamingEngine Web',
  'public',
  'none',
  ARRAY['https://streaming.oberdfr.top/auth/callback', 'http://localhost:5173/auth/callback', 'http://localhost:5174/auth/callback'],
  ARRAY['https://streaming.oberdfr.top/', 'http://localhost:5173/', 'http://localhost:5174/'],
  ARRAY['openid', 'profile', 'email', 'offline_access', 'streaming:catalog', 'streaming:playback', 'streaming:account'],
  'https://api.engine.local/streaming'
), (
  'streamingengine-polished-web',
  'StreamingEngine Web (rewrite)',
  'public',
  'none',
  ARRAY['https://streaming.oberdfr.top/auth/callback', 'http://localhost:5173/auth/callback', 'http://localhost:5174/auth/callback'],
  ARRAY['https://streaming.oberdfr.top/', 'http://localhost:5173/', 'http://localhost:5174/'],
  ARRAY['openid', 'profile', 'email', 'offline_access', 'streaming:catalog', 'streaming:playback', 'streaming:account'],
  'https://api.engine.local/streaming'
)
ON CONFLICT (client_id) DO UPDATE SET
  redirect_uris = EXCLUDED.redirect_uris,
  post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
  scope = EXCLUDED.scope,
  audience = EXCLUDED.audience;
