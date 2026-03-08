ALTER TABLE users DROP COLUMN IF EXISTS avatar_storage_id;
DELETE FROM storage WHERE application_id IS NULL;
ALTER TABLE storage ALTER COLUMN application_id SET NOT NULL;
