DROP TABLE IF EXISTS space_vapid;

CREATE TABLE push_vapid_keys (
    user_public_key TEXT PRIMARY KEY REFERENCES users(public_key) ON DELETE CASCADE,
    vapid_public_key TEXT NOT NULL,
    vapid_private_key TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
