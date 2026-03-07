DELETE FROM applications WHERE deleted_at IS NOT NULL;
ALTER TABLE applications DROP COLUMN deleted_at;
