ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS transport TEXT NOT NULL DEFAULT 'webpush';
ALTER TABLE push_subscriptions DROP CONSTRAINT IF EXISTS push_subscriptions_endpoint_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_push_subscriptions_webpush_endpoint ON push_subscriptions(endpoint) WHERE transport = 'webpush';
CREATE UNIQUE INDEX IF NOT EXISTS idx_push_subscriptions_ws_device ON push_subscriptions(device_public_key) WHERE transport = 'ws';
