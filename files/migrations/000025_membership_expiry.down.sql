DROP INDEX IF EXISTS idx_members_app_key;
ALTER TABLE members DROP COLUMN IF EXISTS membership_expires_at;
ALTER TABLE invitations DROP COLUMN IF EXISTS membership_duration_hours;
