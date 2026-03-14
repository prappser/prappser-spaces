ALTER TABLE members ADD CONSTRAINT members_avatar_storage_id_fkey
  FOREIGN KEY (avatar_storage_id) REFERENCES storage(id) ON DELETE SET NULL;
ALTER TABLE storage ADD CONSTRAINT storage_application_id_fkey
  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE;
