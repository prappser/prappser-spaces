-- The one-shot guard for POST /users/owners/claim (#114) is "this space has
-- been claimed once", NOT "the users table contains at most one owner
-- forever" - those are different invariants, and only the first one matches
-- the domain. A prior attempt enforced the latter with a partial unique index
-- on users.role, but real deployed spaces predate #114's one-owner rule (the
-- old POST /users/owners/register happily created or upgraded any number of
-- owners) and very likely already hold multiple role='owner' rows. A unique
-- index would make this migration fail outright on those spaces (NewDB's
-- log.Fatal on migration error means a crash-loop on deploy), and the only
-- way to satisfy it afterwards would be demoting real, currently-working
-- owner accounts and costing them owner-only functionality.
--
-- This single-row claim table is the guard instead: its primary key is what
-- ClaimOwner's transaction collides against to detect a second claim (see
-- user_repository.go). It follows the id-literal singleton convention used by
-- setup_config/server_keys in 000001_init.up.sql, keyed by the fixed row id
-- 'main' rather than by owner_public_key, so a second INSERT under any
-- public key trips the same primary-key violation.
--
-- No foreign key to users(public_key): owner_public_key is a historical
-- record of who claimed the space, not a live reference to be kept in sync.
-- A CASCADE FK would let deleting that user's row silently delete the claim
-- too, re-opening the space to a fresh claim - exactly the hole this table
-- exists to close. A RESTRICT/NO ACTION FK would only add a foreign-key
-- lookup with no behavioral upside over no FK at all, since nothing here
-- ever updates or deletes through it.
--
-- The backfill below deliberately does NOT touch the users table (no UPDATE,
-- no DELETE): a space that already has one or more owners has, by
-- definition, already been claimed, so it earns a claim row recording that
-- fact - but legacy multi-owner spaces are left exactly as they are. Nothing
-- is demoted. When several owners already exist, the oldest (by created_at,
-- then public_key to break ties) is recorded as the historical claimant;
-- that choice is arbitrary among equals and only affects which key this
-- table's audit row credits, not any user's role or permissions.
CREATE TABLE IF NOT EXISTS space_owner_claim (
    id               TEXT PRIMARY KEY DEFAULT 'main',
    owner_public_key TEXT NOT NULL,
    claimed_at       BIGINT NOT NULL
);

INSERT INTO space_owner_claim (id, owner_public_key, claimed_at)
SELECT 'main', public_key, created_at FROM users WHERE role = 'owner'
ORDER BY created_at ASC, public_key ASC LIMIT 1
ON CONFLICT (id) DO NOTHING;
