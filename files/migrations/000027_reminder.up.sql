-- #42: generic timer queue. One row per (rule_id, offset_index), holding
-- only the NEXT fire time for that offset - the server knows nothing about
-- checklists or any other component; target_key is opaque to it. The
-- component_id FK cascades on component AND application deletion (deleting
-- an application cascades to its components via the existing FK in
-- 000001_init), so a reminder row never outlives what it points at.
--
-- anchor_at is the rule's original occurrence (dueAt at the time the rule
-- was last created/edited) and never changes as the row advances - it's
-- what makes COUNT/UNTIL exact: the recurrence is always expanded from the
-- true start, not re-anchored at whatever occurrence just fired.
CREATE TABLE reminder (
    rule_id TEXT NOT NULL,
    offset_index INT NOT NULL,
    application_id TEXT NOT NULL,
    component_id TEXT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    target_key TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    tz TEXT NOT NULL,
    rrule TEXT,
    offset_spec TEXT NOT NULL,
    anchor_at BIGINT NOT NULL,
    due_at BIGINT NOT NULL,
    fire_at BIGINT NOT NULL,
    recipients JSONB,
    state TEXT NOT NULL DEFAULT 'pending',
    rev BIGINT NOT NULL,
    PRIMARY KEY (rule_id, offset_index)
);
CREATE INDEX idx_reminder_due ON reminder(state, fire_at);
