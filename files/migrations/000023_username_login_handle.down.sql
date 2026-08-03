DROP INDEX users_password_username_idx;
ALTER TABLE users DROP COLUMN password_handle;
ALTER TABLE users ADD COLUMN identifier TEXT;
CREATE UNIQUE INDEX users_identifier_lower_idx ON users (lower(identifier));
