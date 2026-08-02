ALTER TABLE invitations ADD COLUMN grants_membership BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE invitations ADD COLUMN grants_identity BOOLEAN NOT NULL DEFAULT true;
