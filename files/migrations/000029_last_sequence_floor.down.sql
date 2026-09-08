-- A high-water mark cannot be un-raised: the true max sequence_number this
-- migration floored against is still true after a rollback, so undoing it
-- would only reintroduce the bug it fixed.
SELECT 1;
