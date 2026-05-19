ALTER TABLE push_subscriptions
  ADD COLUMN muted_application_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
