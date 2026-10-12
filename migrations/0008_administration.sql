-- Additive: no bootstrap administrator and no changes to existing registrations.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_global_admin boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
ALTER TABLE services ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
ALTER TABLE services ADD COLUMN IF NOT EXISTS admin_url text;
ALTER TABLE services ADD COLUMN IF NOT EXISTS admin_api_url text;
ALTER TABLE services ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'cli';
CREATE TABLE IF NOT EXISTS service_admin_assignments (
  service_id text NOT NULL REFERENCES services(service_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_at timestamptz NOT NULL DEFAULT now(),
  granted_by text NOT NULL,
  PRIMARY KEY(service_id,user_id)
);
CREATE TABLE IF NOT EXISTS administration_settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL
);
-- All callers (including self-delete in AccountService) share this lock.
-- Explicit CLI --force sets a transaction-local override, never a session flag.
CREATE OR REPLACE FUNCTION protect_last_global_admin() RETURNS trigger AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(TG_TABLE_SCHEMA || ':global-admin', 0));
  IF OLD.is_global_admin AND OLD.status = 'active' AND
     (TG_OP = 'DELETE' OR NOT NEW.is_global_admin OR NEW.status <> 'active') AND
     current_setting('engine_accounts.force_admin', true) IS DISTINCT FROM 'on' AND
     NOT EXISTS (SELECT 1 FROM users WHERE is_global_admin AND status = 'active' AND id <> OLD.id) THEN
    RAISE EXCEPTION 'last_active_global_admin' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path FROM CURRENT;
DROP TRIGGER IF EXISTS users_protect_last_global_admin ON users;
CREATE TRIGGER users_protect_last_global_admin BEFORE UPDATE OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION protect_last_global_admin();
