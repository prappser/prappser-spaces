ALTER TABLE push_subscriptions DROP CONSTRAINT push_subscriptions_device_fkey;
ALTER INDEX idx_push_subscriptions_device RENAME TO idx_push_subscriptions_user;
ALTER TABLE push_subscriptions RENAME COLUMN device_public_key TO user_public_key;

-- Orphan cleanup: a subscription created for a device other than device #1
-- has no matching users row for that device's own key (device keys besides
-- device #1 never exist in users), so it can't satisfy the users FK re-added
-- below.
DELETE FROM push_subscriptions
WHERE user_public_key NOT IN (SELECT public_key FROM users);

ALTER TABLE push_subscriptions
    ADD CONSTRAINT push_subscriptions_user_public_key_fkey
    FOREIGN KEY (user_public_key) REFERENCES users(public_key) ON DELETE CASCADE;

DROP INDEX IF EXISTS idx_user_devices_user;
DROP TABLE IF EXISTS user_devices;
