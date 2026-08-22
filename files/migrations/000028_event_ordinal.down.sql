DROP INDEX IF EXISTS idx_events_ordinal;
ALTER TABLE events DROP COLUMN IF EXISTS ordinal;
