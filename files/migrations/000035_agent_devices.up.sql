ALTER TABLE user_devices ADD COLUMN kind TEXT NOT NULL DEFAULT 'human' CHECK (kind IN ('human', 'agent'));

CREATE TABLE agent_refresh_tokens (
    device_public_key TEXT PRIMARY KEY REFERENCES user_devices(device_public_key) ON DELETE CASCADE,
    token_hash        TEXT NOT NULL UNIQUE,
    prev_token_hash   TEXT UNIQUE,
    expires_at        BIGINT NOT NULL
);
