CREATE TABLE user_devices (
    device_public_key TEXT PRIMARY KEY,
    user_public_key   TEXT NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    device_name       TEXT,
    created_at        BIGINT NOT NULL,
    last_seen_at      BIGINT,
    revoked_at        BIGINT
);
CREATE INDEX idx_user_devices_user ON user_devices(user_public_key);

-- Free migration: current account key IS device #1's key.
INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at)
SELECT public_key, public_key, NULL, created_at FROM users;

ALTER TABLE push_subscriptions RENAME COLUMN user_public_key TO device_public_key;
ALTER TABLE push_subscriptions DROP CONSTRAINT push_subscriptions_user_public_key_fkey;
ALTER TABLE push_subscriptions
    ADD CONSTRAINT push_subscriptions_device_fkey
    FOREIGN KEY (device_public_key) REFERENCES user_devices(device_public_key) ON DELETE CASCADE;
ALTER INDEX idx_push_subscriptions_user RENAME TO idx_push_subscriptions_device;
