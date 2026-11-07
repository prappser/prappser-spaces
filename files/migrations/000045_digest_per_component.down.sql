DELETE FROM push_digest_pending;
ALTER TABLE push_digest_pending DROP CONSTRAINT IF EXISTS push_digest_pending_pkey;
ALTER TABLE push_digest_pending DROP COLUMN IF EXISTS title;
ALTER TABLE push_digest_pending DROP COLUMN IF EXISTS kind;
ALTER TABLE push_digest_pending DROP COLUMN IF EXISTS component_key;
ALTER TABLE push_digest_pending ADD PRIMARY KEY (subscription_id, application_id);
