ALTER TABLE users ADD COLUMN identifier TEXT;
ALTER TABLE users ADD COLUMN password_verifier TEXT;
CREATE UNIQUE INDEX users_identifier_lower_idx ON users (lower(identifier));
