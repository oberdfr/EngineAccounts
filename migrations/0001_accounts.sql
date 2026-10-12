-- 0001_accounts.sql — account, sessioni utente, token monouso.
-- Le password non esistono in chiaro: solo hash argon2id (nella stringa PHC
-- ci sono anche i parametri usati, cosi' il costo puo' aumentare col tempo).

CREATE TABLE users (
  id              uuid PRIMARY KEY,
  email           text NOT NULL,
  password_hash   text NOT NULL,
  display_name    text,
  email_verified_at timestamptz,
  status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'blocked', 'deleted')),
  blocked_reason  text,
  totp_enabled    boolean NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  last_login_at   timestamptz,
  deleted_at      timestamptz,
  -- contatore di fallimenti per il lockout progressivo (vedi security/rate-limit.ts)
  failed_logins   integer NOT NULL DEFAULT 0,
  locked_until    timestamptz
);

CREATE UNIQUE INDEX users_email_key ON users (email);
CREATE INDEX users_status_idx ON users (status);

-- Sessioni di login (una riga per browser/dispositivo). Il legame con la
-- sessione di oidc-provider e' tramite `provider_session_id` (il jti del
-- modello Session = valore del cookie di sessione del provider).
CREATE TABLE sessions (
  id                    uuid PRIMARY KEY,
  user_id               uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- solo il digest HMAC del token di cookie: un dump del DB non ruba sessioni
  token_digest          text NOT NULL UNIQUE,
  provider_session_id   text,
  provider_session_uid  text,
  device_label          text NOT NULL,
  ip                    inet,
  user_agent            text,
  amr                   text[] NOT NULL DEFAULT '{}',
  created_at            timestamptz NOT NULL DEFAULT now(),
  last_seen_at          timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz NOT NULL,
  revoked_at            timestamptz,
  revoke_reason         text
);

CREATE UNIQUE INDEX sessions_provider_session_id_key
  ON sessions (provider_session_id) WHERE provider_session_id IS NOT NULL;
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- Token monouso (verifica email, reset password, cambio email, codice magico).
-- Non si memorizza il token: solo HMAC-SHA256 del valore, keyed con una chiave
-- derivata dalla radice dei segreti. Il confronto e' a tempo costante.
CREATE TABLE account_tokens (
  id           uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose      text NOT NULL
                 CHECK (purpose IN ('email_verification', 'password_reset', 'email_change', 'magic_code')),
  token_digest text NOT NULL,
  payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz,
  -- per il reset: a quale indirizzo e' stato spedito, per anti-enumerazione
  target_email text NOT NULL
);

CREATE UNIQUE INDEX account_tokens_digest_key ON account_tokens (token_digest);
CREATE INDEX account_tokens_user_purpose_idx ON account_tokens (user_id, purpose);