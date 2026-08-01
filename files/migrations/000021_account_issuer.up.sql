ALTER TABLE users ADD COLUMN issuer TEXT;
UPDATE users SET issuer = public_key WHERE issuer IS NULL;
ALTER TABLE users ALTER COLUMN issuer SET NOT NULL;
