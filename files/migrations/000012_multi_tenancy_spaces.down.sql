-- Revert users.role CHECK constraint
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('owner', 'admin', 'member', 'viewer'));

-- Remove space_id from existing tables
ALTER TABLE storage DROP COLUMN IF EXISTS space_id;
ALTER TABLE invitation_uses DROP COLUMN IF EXISTS space_id;
ALTER TABLE invitations DROP COLUMN IF EXISTS space_id;
ALTER TABLE events DROP COLUMN IF EXISTS space_id;
ALTER TABLE applications DROP COLUMN IF EXISTS space_id;

-- Drop spaces table
DROP TABLE IF EXISTS spaces;
