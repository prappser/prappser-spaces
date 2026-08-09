-- #115: hosting-move identity export/import. last_seen_at lets GET /status
-- report a liveness signal for this space's identity (see KeyService's
-- throttled TouchLastSeen) - the useful read is whether it stays continuous
-- across a restart/hosting cutover, not its value at any single healthy
-- instant (see docs/hosting/selfhost.md).
ALTER TABLE space_keys ADD COLUMN last_seen_at BIGINT;
