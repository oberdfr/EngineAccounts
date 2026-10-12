-- Every already registered audience becomes discoverable without consumer code.
-- Preserve all existing IDs, metadata, roles, and enabled states.
INSERT INTO services(service_id,audience,name,origin)
SELECT 'client:' || min(client_id),audience,min(client_name),'cli'
FROM clients c
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.audience=c.audience)
GROUP BY audience
ON CONFLICT DO NOTHING;
CREATE INDEX IF NOT EXISTS service_admin_assignments_user_idx ON service_admin_assignments(user_id);
CREATE INDEX IF NOT EXISTS users_global_admin_active_idx ON users(id) WHERE is_global_admin AND status='active';
