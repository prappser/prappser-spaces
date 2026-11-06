ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS categories JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users DROP COLUMN IF EXISTS notify_mode;
