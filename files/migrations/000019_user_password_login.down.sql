DROP INDEX users_identifier_lower_idx;
ALTER TABLE users DROP COLUMN password_verifier;
ALTER TABLE users DROP COLUMN identifier;
