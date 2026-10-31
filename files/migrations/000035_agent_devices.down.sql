DROP TABLE IF EXISTS agent_refresh_tokens;
DELETE FROM user_devices WHERE kind = 'agent';
ALTER TABLE user_devices DROP COLUMN IF EXISTS kind;
