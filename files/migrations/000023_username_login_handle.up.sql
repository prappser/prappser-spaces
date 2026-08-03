ALTER TABLE users ADD COLUMN password_handle TEXT;
UPDATE users SET password_handle = lower(identifier) WHERE password_verifier IS NOT NULL AND identifier IS NOT NULL;
DROP INDEX users_identifier_lower_idx;
ALTER TABLE users DROP COLUMN identifier;
-- Two password-enabled accounts may already share lower(username) (identifier
-- and username were independent columns pre-migration), which would violate
-- the unique index below. Keep the oldest such account's password login and
-- disable it on the rest: they can re-set a password in settings, and their
-- escrow blobs are left in place (inert, not destroyed) since a cleared
-- password_verifier just makes them unreachable, not deleted.
UPDATE users SET password_verifier = NULL, password_handle = NULL WHERE public_key IN (
  SELECT public_key FROM (
    SELECT public_key, row_number() OVER (PARTITION BY lower(username) ORDER BY created_at) AS rn
    FROM users WHERE password_verifier IS NOT NULL
  ) d WHERE rn > 1
);
CREATE UNIQUE INDEX users_password_username_idx ON users (lower(username)) WHERE password_verifier IS NOT NULL;
