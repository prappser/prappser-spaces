ALTER TABLE server_keys RENAME TO space_keys;
ALTER TABLE applications RENAME COLUMN server_public_key TO space_public_key;
