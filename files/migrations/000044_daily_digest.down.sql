DROP TABLE IF EXISTS push_digest_pending;
ALTER TABLE users DROP COLUMN IF EXISTS digest_sent_at;
ALTER TABLE users DROP COLUMN IF EXISTS timezone;
