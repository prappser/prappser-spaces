package push

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// pushRepository handles all database operations for space_vapid and push_subscriptions.
// It implements the PushRepository interface defined in push.go.
type pushRepository struct {
	db *sql.DB
}

// NewPushRepository creates a new PushRepository backed by the given database connection.
func NewPushRepository(db *sql.DB) PushRepository {
	return &pushRepository{db: db}
}

// UpsertSpaceVapid inserts or updates the singleton space VAPID keypair (id = 1).
func (r *pushRepository) UpsertSpaceVapid(v *SpaceVapid) error {
	query := `
		INSERT INTO space_vapid (id, vapid_public_key, vapid_private_key, created_at, updated_at)
		VALUES (1, $1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE
		  SET vapid_public_key  = EXCLUDED.vapid_public_key,
		      vapid_private_key = EXCLUDED.vapid_private_key,
		      updated_at        = EXCLUDED.updated_at`

	_, err := r.db.Exec(query, v.VapidPublicKey, v.VapidPrivateKey, v.CreatedAt, v.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to upsert space vapid: %w", err)
	}
	return nil
}

// GetSpaceVapid returns the singleton space VAPID keypair.
// Returns nil, nil when no row has been persisted yet.
func (r *pushRepository) GetSpaceVapid() (*SpaceVapid, error) {
	query := `
		SELECT vapid_public_key, vapid_private_key, created_at, updated_at
		FROM space_vapid
		WHERE id = 1`

	v := &SpaceVapid{}
	err := r.db.QueryRow(query).Scan(
		&v.VapidPublicKey,
		&v.VapidPrivateKey,
		&v.CreatedAt,
		&v.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get space vapid: %w", err)
	}
	return v, nil
}

// CreateSubscription: a repeat endpoint takes over the row, keeping its id and created_at and
// resetting failure_count. s.ID only applies to fresh inserts; callers must use the returned id.
// A changed owner's pending digest rows are dropped so they never reach the new device.
func (r *pushRepository) CreateSubscription(s *Subscription) (string, error) {
	mutedJSON, err := json.Marshal(s.MutedApplicationIDs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal muted_application_ids: %w", err)
	}

	tx, err := r.db.Begin()
	if err != nil {
		return "", fmt.Errorf("failed to begin create subscription: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		DELETE FROM push_digest_pending
		WHERE subscription_id IN (
		  SELECT id FROM push_subscriptions
		  WHERE endpoint = $1 AND transport = 'webpush' AND device_public_key <> $2
		)`, s.Endpoint, s.DevicePublicKey); err != nil {
		return "", fmt.Errorf("failed to clear previous owner's digest: %w", err)
	}

	query := `
		INSERT INTO push_subscriptions
		  (id, device_public_key, transport, endpoint, p256dh, auth, device_label, muted_application_ids, created_at, last_success_at, failure_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (endpoint) WHERE transport = 'webpush' DO UPDATE
		  SET device_public_key     = EXCLUDED.device_public_key,
		      p256dh                = EXCLUDED.p256dh,
		      auth                  = EXCLUDED.auth,
		      device_label          = EXCLUDED.device_label,
		      muted_application_ids = EXCLUDED.muted_application_ids,
		      failure_count         = 0
		RETURNING id`

	var id string
	err = tx.QueryRow(query,
		s.ID,
		s.DevicePublicKey,
		transportOrDefault(s.Transport),
		s.Endpoint,
		s.P256dh,
		s.Auth,
		s.DeviceLabel,
		string(mutedJSON),
		s.CreatedAt,
		s.LastSuccessAt,
		s.FailureCount,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to create subscription: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit create subscription: %w", err)
	}
	return id, nil
}

func transportOrDefault(t string) string {
	if t == "" {
		return TransportWebpush
	}
	return t
}

// UpsertWSSubscription inserts the device's ws subscription or, when one exists, updates its
// muted apps and label. endpoint, p256dh and auth are empty for ws.
func (r *pushRepository) UpsertWSSubscription(s *Subscription) (string, error) {
	mutedJSON, err := json.Marshal(s.MutedApplicationIDs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal muted_application_ids: %w", err)
	}

	query := `
		INSERT INTO push_subscriptions
		  (id, device_public_key, transport, endpoint, p256dh, auth, device_label, muted_application_ids, created_at, failure_count)
		VALUES ($1, $2, 'ws', '', '', '', $3, $4, $5, 0)
		ON CONFLICT (device_public_key) WHERE transport = 'ws' DO UPDATE
		  SET muted_application_ids = EXCLUDED.muted_application_ids,
		      device_label          = EXCLUDED.device_label
		RETURNING id`

	var id string
	if err := r.db.QueryRow(query, s.ID, s.DevicePublicKey, s.DeviceLabel, string(mutedJSON), s.CreatedAt).Scan(&id); err != nil {
		return "", fmt.Errorf("failed to upsert ws subscription: %w", err)
	}
	return id, nil
}

// UpdateSubscription updates mutable fields of a subscription.
// The WHERE clause includes device_public_key as an ownership guard.
func (r *pushRepository) UpdateSubscription(s *Subscription) error {
	mutedJSON, err := json.Marshal(s.MutedApplicationIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal muted_application_ids: %w", err)
	}

	query := `
		UPDATE push_subscriptions
		SET endpoint              = $1,
		    p256dh                = $2,
		    auth                  = $3,
		    muted_application_ids = $4
		WHERE id = $5 AND device_public_key = $6`

	result, err := r.db.Exec(query,
		s.Endpoint,
		s.P256dh,
		s.Auth,
		string(mutedJSON),
		s.ID,
		s.DevicePublicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("subscription not found")
	}
	return nil
}

// DeleteSubscription removes a subscription by id, scoped to the owning device.
// Returns an error if no row was deleted (not owned or not found).
func (r *pushRepository) DeleteSubscription(id, devicePublicKey string) error {
	result, err := r.db.Exec(
		`DELETE FROM push_subscriptions WHERE id = $1 AND device_public_key = $2`,
		id, devicePublicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to delete subscription: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("subscription not found")
	}
	return nil
}

// GetSubscriptionsForUsers returns all push subscriptions owned by any
// non-revoked device belonging to any of the given ACCOUNT public keys.
// Returns an empty slice when userPublicKeys is empty.
func (r *pushRepository) GetSubscriptionsForUsers(userPublicKeys []string) ([]*Subscription, error) {
	if len(userPublicKeys) == 0 {
		return nil, nil
	}

	// Build $1,$2,... placeholder list.
	placeholders := make([]string, len(userPublicKeys))
	args := make([]interface{}, len(userPublicKeys))
	for i, pk := range userPublicKeys {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = pk
	}

	query := fmt.Sprintf(`
		SELECT ps.id, ps.device_public_key, ps.transport, ps.endpoint, ps.p256dh, ps.auth, ps.device_label,
		       ps.muted_application_ids, ps.created_at, ps.last_success_at, ps.failure_count, u.locale, u.notify_mode, u.notifications_seen_at, ud.user_public_key
		FROM push_subscriptions ps
		JOIN user_devices ud ON ud.device_public_key = ps.device_public_key
		JOIN users u ON u.public_key = ud.user_public_key
		WHERE ud.user_public_key IN (%s) AND ud.revoked_at IS NULL`, strings.Join(placeholders, ","))

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []*Subscription
	for rows.Next() {
		s := &Subscription{}
		var mutedJSON string
		var deviceLabel sql.NullString
		var lastSuccessAt sql.NullInt64

		err := rows.Scan(
			&s.ID,
			&s.DevicePublicKey,
			&s.Transport,
			&s.Endpoint,
			&s.P256dh,
			&s.Auth,
			&deviceLabel,
			&mutedJSON,
			&s.CreatedAt,
			&lastSuccessAt,
			&s.FailureCount,
			&s.Locale,
			&s.NotifyMode,
			&s.NotificationsSeenAt,
			&s.UserPublicKey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan subscription: %w", err)
		}

		if deviceLabel.Valid {
			s.DeviceLabel = &deviceLabel.String
		}
		if lastSuccessAt.Valid {
			s.LastSuccessAt = &lastSuccessAt.Int64
		}

		if err := json.Unmarshal([]byte(mutedJSON), &s.MutedApplicationIDs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal muted_application_ids: %w", err)
		}
		if s.MutedApplicationIDs == nil {
			s.MutedApplicationIDs = []string{}
		}

		subs = append(subs, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subscriptions: %w", err)
	}

	return subs, nil
}

// GetSubscriptionByID returns a single subscription by id, scoped to the owning device.
// Returns nil, nil when not found or not owned by devicePublicKey.
func (r *pushRepository) GetSubscriptionByID(id, devicePublicKey string) (*Subscription, error) {
	query := `
		SELECT id, device_public_key, transport, endpoint, p256dh, auth, device_label,
		       muted_application_ids, created_at, last_success_at, failure_count
		FROM push_subscriptions
		WHERE id = $1 AND device_public_key = $2`

	s := &Subscription{}
	var mutedJSON string
	var deviceLabel sql.NullString
	var lastSuccessAt sql.NullInt64

	err := r.db.QueryRow(query, id, devicePublicKey).Scan(
		&s.ID,
		&s.DevicePublicKey,
		&s.Transport,
		&s.Endpoint,
		&s.P256dh,
		&s.Auth,
		&deviceLabel,
		&mutedJSON,
		&s.CreatedAt,
		&lastSuccessAt,
		&s.FailureCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}

	if deviceLabel.Valid {
		s.DeviceLabel = &deviceLabel.String
	}
	if lastSuccessAt.Valid {
		s.LastSuccessAt = &lastSuccessAt.Int64
	}

	if err := json.Unmarshal([]byte(mutedJSON), &s.MutedApplicationIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal muted_application_ids: %w", err)
	}
	if s.MutedApplicationIDs == nil {
		s.MutedApplicationIDs = []string{}
	}

	return s, nil
}

// MarkSuccess sets last_success_at to ts and resets failure_count to 0 for the given subscription.
func (r *pushRepository) MarkSuccess(id string, ts int64) error {
	_, err := r.db.Exec(
		`UPDATE push_subscriptions SET last_success_at = $1, failure_count = 0 WHERE id = $2`,
		ts, id,
	)
	if err != nil {
		return fmt.Errorf("failed to mark success: %w", err)
	}
	return nil
}

// IncrementFailure increments failure_count by 1 for the given subscription.
func (r *pushRepository) IncrementFailure(id string) error {
	_, err := r.db.Exec(
		`UPDATE push_subscriptions SET failure_count = failure_count + 1 WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to increment failure: %w", err)
	}
	return nil
}

func (r *pushRepository) CountDigest(subscriptionID, applicationID string, bucket DigestBucket, at, seenAt int64) error {
	_, err := r.db.Exec(`
		INSERT INTO push_digest_pending (subscription_id, application_id, component_key, kind, title, count, last_at)
		VALUES ($1, $2, $5, $6, $7, 1, $3)
		ON CONFLICT (subscription_id, application_id, component_key) DO UPDATE
		  SET count   = CASE WHEN push_digest_pending.last_at <= $4 THEN 1 ELSE push_digest_pending.count + 1 END,
		      kind    = $6,
		      title   = $7,
		      last_at = $3`,
		subscriptionID, applicationID, at, seenAt, bucket.Key, string(bucket.Kind), bucket.Title)
	if err != nil {
		return fmt.Errorf("failed to count digest: %w", err)
	}
	return nil
}

func (r *pushRepository) UncountDigest(subscriptionID, applicationID, componentKey string, countedAt, seenAt int64) (bool, error) {
	res, err := r.db.Exec(`
		UPDATE push_digest_pending p SET count = p.count - 1
		FROM push_subscriptions ps, user_devices ud, users u
		WHERE p.subscription_id = $1 AND p.application_id = $2 AND p.component_key = $3
		  AND p.count > 0 AND p.last_at > $5
		  AND ps.id = p.subscription_id AND ud.device_public_key = ps.device_public_key AND ud.revoked_at IS NULL
		  AND u.public_key = ud.user_public_key AND $4 > u.digest_sent_at AND $4 > $5`,
		subscriptionID, applicationID, componentKey, countedAt, seenAt)
	if err != nil {
		return false, fmt.Errorf("failed to uncount digest: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read uncounted digest rows: %w", err)
	}
	return n > 0, nil
}

func (r *pushRepository) PreviousChange(applicationID, componentID, key string, sequence, since int64) (*PriorChange, error) {
	var creator, data string
	var createdAt int64
	err := r.db.QueryRow(`
		SELECT COALESCE(creator_public_key, ''), created_at, data FROM events
		WHERE application_id = $1 AND type = 'component_data_changed' AND sequence_number < $4 AND created_at > $5
		  AND data::jsonb->>'componentId' = $2 AND data::jsonb->'changedFields' ? $3
		ORDER BY sequence_number DESC LIMIT 1`,
		applicationID, componentID, key, sequence, since).Scan(&creator, &createdAt, &data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query previous change: %w", err)
	}
	var d struct {
		ChangedFields map[string]struct {
			OldValue any `json:"oldValue"`
			NewValue any `json:"newValue"`
		} `json:"changedFields"`
	}
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return nil, fmt.Errorf("failed to decode previous change: %w", err)
	}
	c := d.ChangedFields[key]
	return &PriorChange{CreatorPublicKey: creator, CreatedAt: createdAt, OldValue: c.OldValue, NewValue: c.NewValue, Keys: len(d.ChangedFields)}, nil
}

// ponytail: full scan each tick, move the due check into SQL if daily users grow.
func (r *pushRepository) GetDailyUsers() ([]DigestUser, error) {
	rows, err := r.db.Query(`SELECT public_key, timezone, digest_sent_at FROM users WHERE notify_mode = 'daily'`)
	if err != nil {
		return nil, fmt.Errorf("failed to query daily users: %w", err)
	}
	defer rows.Close()

	var users []DigestUser
	for rows.Next() {
		var u DigestUser
		if err := rows.Scan(&u.PublicKey, &u.Timezone, &u.SentAt); err != nil {
			return nil, fmt.Errorf("failed to scan daily user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating daily users: %w", err)
	}
	return users, nil
}

// ClaimDigest stamps and deletes before any send: a crash or failed send loses one digest instead of repeating it.
func (r *pushRepository) ClaimDigest(userPublicKey string, due, now int64) ([]DigestRow, bool, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return nil, false, fmt.Errorf("failed to begin digest claim: %w", err)
	}
	defer tx.Rollback()

	var seenAt int64
	err = tx.QueryRow(`
		UPDATE users SET digest_sent_at = $2
		WHERE public_key = $1 AND notify_mode = 'daily' AND digest_sent_at < $3
		RETURNING notifications_seen_at`, userPublicKey, now, due).Scan(&seenAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to stamp digest: %w", err)
	}

	rows, err := tx.Query(`
		WITH gone AS (
		  DELETE FROM push_digest_pending p
		  USING push_subscriptions ps, user_devices ud
		  WHERE p.subscription_id = ps.id AND ud.device_public_key = ps.device_public_key AND ud.user_public_key = $1
		  RETURNING p.subscription_id, p.application_id, p.kind, p.title, p.count, p.last_at)
		SELECT g.subscription_id, g.application_id, a.name, g.kind, g.title, g.count
		FROM gone g
		JOIN applications a ON a.id = g.application_id AND a.deleted_at IS NULL
		WHERE g.last_at > $2 AND g.count > 0
		  AND EXISTS (SELECT 1 FROM members m WHERE m.application_id = g.application_id AND m.public_key = $1)
		ORDER BY g.count DESC`, userPublicKey, seenAt)
	if err != nil {
		return nil, false, fmt.Errorf("failed to take pending digest rows: %w", err)
	}
	defer rows.Close()

	var out []DigestRow
	for rows.Next() {
		var d DigestRow
		if err := rows.Scan(&d.SubscriptionID, &d.ApplicationID, &d.AppName, &d.Kind, &d.Title, &d.Count); err != nil {
			return nil, false, fmt.Errorf("failed to scan digest row: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("error iterating digest rows: %w", err)
	}
	rows.Close()

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("failed to commit digest claim: %w", err)
	}
	return out, true, nil
}
