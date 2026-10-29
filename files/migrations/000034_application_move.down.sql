ALTER TABLE applications DROP COLUMN IF EXISTS moved_to_url;
ALTER TABLE applications DROP COLUMN IF EXISTS move_invite_token;
ALTER TABLE applications DROP COLUMN IF EXISTS moved_at;
ALTER TABLE invitations DROP COLUMN IF EXISTS member_public_keys;
