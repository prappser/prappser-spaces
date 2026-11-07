ALTER TABLE push_digest_pending ADD COLUMN IF NOT EXISTS component_key TEXT NOT NULL DEFAULT '';
ALTER TABLE push_digest_pending ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT '';
ALTER TABLE push_digest_pending ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';
ALTER TABLE push_digest_pending DROP CONSTRAINT IF EXISTS push_digest_pending_pkey;
ALTER TABLE push_digest_pending ADD PRIMARY KEY (subscription_id, application_id, component_key);
