-- 0003_oidc.sql -- stato per oidc-provider (adapter di persistenza nostro).
--
-- `oidc-provider` non vede che cosa c'e' dentro: chiama find/upsert/consume/
-- destroy/revokeByGrantId con un payload JSON e un id. Queste tabelle sono
-- l'unico punto di contatto (ADR-0008: i tipi della libreria non escono).
--
-- `oidc_tokens` contiene i refresh token; la famiglia e' il gruppo di token che
-- condividono `grant_id`: il riuso di un refresh token revoca l'intero gruppo.

CREATE TABLE oidc_grants (
  grant_id    text PRIMARY KEY,
  account_id  uuid,
  client_id   text,
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz
);

CREATE INDEX oidc_grants_account_idx ON oidc_grants (account_id);
CREATE INDEX oidc_grants_client_idx ON oidc_grants (client_id);

-- Codici monouso: authorization code, device code, PAR, pre-authorized code.
CREATE TABLE oidc_codes (
  id          text PRIMARY KEY,
  kind        text NOT NULL,
  grant_id    text,
  account_id  uuid,
  client_id   text,
  user_code   text,
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  consumed_at timestamptz,
  revoked_at  timestamptz
);

CREATE INDEX oidc_codes_grant_idx ON oidc_codes (grant_id);
CREATE INDEX oidc_codes_user_code_idx ON oidc_codes (user_code) WHERE user_code IS NOT NULL;

-- Access token e refresh token (e i token client-credentials, se mai usati).
CREATE TABLE oidc_tokens (
  id          text PRIMARY KEY,
  kind        text NOT NULL,
  grant_id    text,
  account_id  uuid,
  client_id   text,
  -- sessione del provider che ha ottenuto il token: serve a revocare per device
  session_uid text,
  scope       text,
  audience    text,
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  consumed_at timestamptz,
  revoked_at  timestamptz,
  rotations   integer NOT NULL DEFAULT 0
);

CREATE INDEX oidc_tokens_grant_idx ON oidc_tokens (grant_id);
CREATE INDEX oidc_tokens_account_idx ON oidc_tokens (account_id);
CREATE INDEX oidc_tokens_session_idx ON oidc_tokens (session_uid);
CREATE INDEX oidc_tokens_client_idx ON oidc_tokens (client_id);
CREATE INDEX oidc_tokens_expires_idx ON oidc_tokens (expires_at);

-- Sessione del provider (cookie di login): `uid` e' l'indice secondario.
CREATE TABLE oidc_sessions (
  id           text PRIMARY KEY,
  uid          text NOT NULL,
  account_id   uuid,
  payload      jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  revoked_at   timestamptz
);

CREATE UNIQUE INDEX oidc_sessions_uid_key ON oidc_sessions (uid);
CREATE INDEX oidc_sessions_account_idx ON oidc_sessions (account_id);

-- Interazione in corso (login/consenso/MFA): stato dei form.
CREATE TABLE oidc_interactions (
  id          text PRIMARY KEY,
  kind        text NOT NULL DEFAULT 'Interaction',
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  consumed_at timestamptz
);

-- Replay protection: jti gia' visti (contratto 5 `jti`).
CREATE TABLE jti_replay (
  jti       text PRIMARY KEY,
  kind      text NOT NULL DEFAULT 'ReplayDetection',
  iss       text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);

CREATE INDEX jti_replay_expires_idx ON jti_replay (expires_at);