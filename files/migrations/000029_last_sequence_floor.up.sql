-- #52: last_sequence was written with a plain SET, so a client whose event
-- execution ever failed (updateAppVersion only runs on executeEvent success)
-- can already be sitting below its app's true max sequence_number. Floor it
-- up so GetNextSequence's own GREATEST has an accurate value to compare
-- against, not a stale one from before this fix.
UPDATE applications a
SET last_sequence = GREATEST(COALESCE(a.last_sequence, 0), sub.max_seq)
FROM (
    SELECT application_id, MAX(sequence_number) AS max_seq
    FROM events
    WHERE application_id IS NOT NULL
    GROUP BY application_id
) sub
WHERE a.id = sub.application_id;
