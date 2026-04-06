-- Spaces table
CREATE TABLE spaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    user_public_key TEXT REFERENCES users(public_key),
    created_at BIGINT,
    updated_at BIGINT
);
CREATE INDEX idx_spaces_user_public_key ON spaces(user_public_key);

-- Add space_id to existing tables
ALTER TABLE applications ADD COLUMN space_id TEXT REFERENCES spaces(id);
ALTER TABLE events ADD COLUMN space_id TEXT REFERENCES spaces(id);
ALTER TABLE invitations ADD COLUMN space_id TEXT REFERENCES spaces(id);
ALTER TABLE invitation_uses ADD COLUMN space_id TEXT REFERENCES spaces(id);
ALTER TABLE storage ADD COLUMN space_id TEXT REFERENCES spaces(id);

-- Update users.role CHECK constraint to instance-level roles
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('owner', 'user', 'guest'));
