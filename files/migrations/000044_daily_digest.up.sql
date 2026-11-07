ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS digest_sent_at BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS push_digest_pending (
    subscription_id TEXT NOT NULL REFERENCES push_subscriptions(id) ON DELETE CASCADE,
    application_id TEXT NOT NULL,
    count INT NOT NULL,
    last_at BIGINT NOT NULL,
    PRIMARY KEY (subscription_id, application_id)
);
