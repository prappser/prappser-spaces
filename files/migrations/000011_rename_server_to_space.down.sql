ALTER TABLE space_keys RENAME TO server_keys;
ALTER TABLE applications RENAME COLUMN space_public_key TO server_public_key;
