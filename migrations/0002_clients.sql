-- 0002_clients.sql -- registrati come dati, non come codice (D2).
--
-- `scope`/`audience`/`backchannel_events_uri` sono colonne: aggiungere un
-- servizio alla suite non richiede modifiche al core.

CREATE TABLE clients (
  client_id                 text PRIMARY KEY,
  client_name               text NOT NULL,
  client_type               text NOT NULL CHECK (client_type IN ('public', 'confidential')),
  -- mai in chiaro: solo hash argon2id del secret (contratto 7)
  client_secret_hash        text,
  redirect_uris             text[] NOT NULL,
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  grant_types               text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
  response_types            text[] NOT NULL DEFAULT '{code}',
  scope                     text[] NOT NULL DEFAULT '{}',
  audience                  text NOT NULL,
  backchannel_events_uri    text,
  token_endpoint_auth_method text NOT NULL
                             DEFAULT 'client_secret_basic',
  enabled                   boolean NOT NULL DEFAULT true,
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (client_type = 'public'
      AND client_secret_hash IS NULL
      AND token_endpoint_auth_method = 'none')
    OR (client_type = 'confidential' AND client_secret_hash IS NOT NULL)
  )
);

-- Consenso per utente: stato corrente. La storia vive in audit_log.
CREATE TABLE client_consents (
  id          uuid PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id   text NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
  scope       text[] NOT NULL,
  granted_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);

CREATE UNIQUE INDEX client_consents_user_client_key ON client_consents (user_id, client_id);
CREATE INDEX client_consents_active_idx ON client_consents (user_id) WHERE revoked_at IS NULL;

-- Servizi e scope "di servizio": righe, non codice (contratto 3).
CREATE TABLE services (
  service_id   text PRIMARY KEY,
  audience     text NOT NULL UNIQUE,
  name         text NOT NULL,
  enabled      boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE streaming_scopes (
  scope       text PRIMARY KEY,
  service_id  text NOT NULL REFERENCES services (service_id) ON DELETE CASCADE,
  description text NOT NULL
);

-- Scope di base vivono nel core (contratto 3): openid profile email offline_access
INSERT INTO services (service_id, audience, name)
VALUES ('streaming', 'https://api.engine.local/streaming', 'StreamingCommunityProxyApi')
ON CONFLICT (service_id) DO NOTHING;

INSERT INTO streaming_scopes (scope, service_id, description) VALUES
  ('streaming:catalog',   'streaming', 'Catalogo, ricerca, metadati di catalogo'),
  ('streaming:playback', 'streaming', 'Avvio riproduzione di un titolo'),
  ('streaming:account',   'streaming', 'Dati utente (/v1/me/**)')
ON CONFLICT (scope) DO NOTHING;