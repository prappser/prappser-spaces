-- #117: invitation-driven membership expiry. An invitation can carry a
-- membership_duration_hours; when it does, a joiner gets an absolute
-- membership_expires_at (now + duration) recorded on their member row at
-- join time. Enforcement is lazy - read-time queries filter on this column
-- (see activeMemberPredicate in internal/application/repository.go) - there
-- is no cron job and no expiry event. The member row itself is never
-- deleted, so re-joining after expiry is a normal upsert, not a re-create.
ALTER TABLE invitations ADD COLUMN membership_duration_hours INTEGER;
ALTER TABLE members ADD COLUMN membership_expires_at BIGINT;

-- Dev data only: this repo has no production deployments yet, so a
-- duplicate (application_id, public_key) row from before this constraint
-- existed can simply be collapsed rather than reconciled. Keeps whichever
-- physical row ctid sorts second; which one that is carries no meaning.
DELETE FROM members a USING members b
  WHERE a.ctid < b.ctid AND a.application_id = b.application_id AND a.public_key = b.public_key;

-- Backs CreateMember's ON CONFLICT (application_id, public_key) upsert,
-- which is what makes re-joining after expiry update the same row instead
-- of erroring or duplicating.
CREATE UNIQUE INDEX idx_members_app_key ON members(application_id, public_key);
