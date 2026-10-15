ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS application_type text NOT NULL DEFAULT 'web'
    CHECK (application_type IN ('web', 'native')),
  ADD COLUMN IF NOT EXISTS cors_origins text[] NOT NULL DEFAULT '{}';
