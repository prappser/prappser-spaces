ALTER TABLE applications ADD COLUMN IF NOT EXISTS moved_to_url TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS move_invite_token TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS moved_at BIGINT;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS member_public_keys TEXT[];
