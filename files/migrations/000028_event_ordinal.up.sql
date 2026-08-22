-- #47: created_at is whole seconds and event ids are client-minted (UUIDv7,
-- plus UUIDv4 at event_service.go:607), so no (created_at, id) pair can order
-- the log without skipping rows written in the cursor's own second. ordinal
-- is a server-assigned total order that GetSince can use as the sole cursor
-- key, replacing the two disagreeing predicates that caused the loss.
ALTER TABLE events ADD COLUMN ordinal BIGSERIAL;

-- ADD COLUMN numbers existing rows in physical (heap) order, which carries no
-- meaning. Restate the backfill in an order that does: oldest event first,
-- id as a tie-break within the same second.
UPDATE events SET ordinal = sub.rn
FROM (
    SELECT id, row_number() OVER (ORDER BY created_at ASC, id ASC) AS rn
    FROM events
) AS sub
WHERE events.id = sub.id;

-- Point the sequence at the next free value so future inserts continue past
-- the backfilled max instead of colliding with it.
SELECT setval(
    pg_get_serial_sequence('events', 'ordinal'),
    COALESCE((SELECT MAX(ordinal) FROM events), 0) + 1,
    false
);

CREATE UNIQUE INDEX idx_events_ordinal ON events(ordinal);
