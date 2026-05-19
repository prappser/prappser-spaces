CREATE TABLE push_vapid_keys (
    user_public_key TEXT PRIMARY KEY REFERENCES users(public_key) ON DELETE CASCADE,
    vapid_public_key TEXT NOT NULL,
    vapid_private_key TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE push_subscriptions (
    id TEXT PRIMARY KEY,
    user_public_key TEXT NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    device_label TEXT,
    categories JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at BIGINT NOT NULL,
    last_success_at BIGINT,
    failure_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_push_subscriptions_user ON push_subscriptions(user_public_key);
