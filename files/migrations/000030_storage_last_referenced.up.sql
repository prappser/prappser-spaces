ALTER TABLE storage ADD COLUMN last_referenced_at BIGINT;

-- Nothing existing may be purged before a full grace period has passed since deploy.
UPDATE storage SET last_referenced_at = EXTRACT(EPOCH FROM now())::BIGINT;
