-- Client-submitted user-scoped events stored with an app id (sequence 0) were served to that app's members; server fan-out rows are sequenced and stay.
UPDATE events SET application_id = NULL
WHERE application_id IS NOT NULL
  AND COALESCE(sequence_number, 0) = 0
  AND type IN ('user_settings_changed', 'application_created', 'template_changed');
