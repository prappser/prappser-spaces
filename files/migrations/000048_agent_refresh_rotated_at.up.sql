ALTER TABLE agent_refresh_tokens ADD COLUMN IF NOT EXISTS rotated_at BIGINT;
