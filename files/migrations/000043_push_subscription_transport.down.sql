DELETE FROM push_subscriptions WHERE transport = 'ws';
DROP INDEX IF EXISTS idx_push_subscriptions_ws_device;
DROP INDEX IF EXISTS idx_push_subscriptions_webpush_endpoint;
ALTER TABLE push_subscriptions DROP CONSTRAINT IF EXISTS push_subscriptions_endpoint_key;
ALTER TABLE push_subscriptions ADD CONSTRAINT push_subscriptions_endpoint_key UNIQUE (endpoint);
ALTER TABLE push_subscriptions DROP COLUMN IF EXISTS transport;
