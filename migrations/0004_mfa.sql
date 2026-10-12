-- 0004_mfa.sql -- secondo fattore.

CREATE TABLE totp_secrets (
  user_id     uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  -- cifrato a riposo con AES-256-GCM (chiave derivata HKDF), mai in chiaro
  secret_ct   text NOT NULL,
  confirmed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE webauthn_credentials (
  id            uuid PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  credential_id text NOT NULL UNIQUE,   -- base64url, come arriva dall'autenticatore
  public_key    bytea NOT NULL,         -- COSE (CBOR), non decodificata: la verifica la fa la libreria
  counter       bigint NOT NULL DEFAULT 0,
  transports    text[] NOT NULL DEFAULT '{}',
  aaguid        text,
  device_type   text NOT NULL DEFAULT 'single_device',
  backed_up     boolean NOT NULL DEFAULT false,
  nickname      text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);

CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

-- Codici di recupero monouso: digest HMAC-SHA256, non l'hash argon2 (sono
-- casuali, altissima entropia, e l'uso deve essere veloce).
CREATE TABLE recovery_codes (
  id          uuid PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  digest      text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  used_at     timestamptz
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id);