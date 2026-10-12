-- 0005_audit_events.sql -- audit log append-only e outbox degli eventi back-channel.

-- Audit log di sicurezza. Append-only per applicazione: il trigger qui sotto
-- rifiuta UPDATE e DELETE. In piu' ogni riga e' concatenata con la precedente
-- tramite hash SHA-256 (catena): mancare una riga o alterarne una rompe la
-- catena ed e' rilevabile con la query di verifica in docs/.
CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  user_id    uuid,
  subject_id uuid,
  actor      text NOT NULL DEFAULT 'user',      -- user | admin:<sub> | system
  event      text NOT NULL,
  outcome    text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'info')),
  ip         inet,
  user_agent text,
  metadata   jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash  text,
  hash       text NOT NULL
);

CREATE INDEX audit_log_user_idx ON audit_log (user_id, at DESC);
CREATE INDEX audit_log_event_idx ON audit_log (event, at DESC);

CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log e'' append-only ( tentato % su id=%)', TG_OP, OLD.id
    USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Outbox per l'evento `account.deleted` (C11): la firma e' deterministica,
-- l'invio e' ritentabile e idempotente lato destinatario (stesso jti).
CREATE TABLE outbox_events (
  id          uuid PRIMARY KEY,
  event       text NOT NULL,
  sub         text NOT NULL,
  audience    text NOT NULL,
  jti         text NOT NULL UNIQUE,
  payload     jsonb NOT NULL,
  attempts    integer NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_error  text,
  delivered_at timestamptz
);

CREATE INDEX outbox_events_pending_idx ON outbox_events (created_at)
  WHERE delivered_at IS NULL;