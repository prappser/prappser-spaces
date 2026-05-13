package push

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// pushRepository handles all database operations for push_vapid_keys and push_subscriptions.
// It implements the PushRepository interface defined in push.go.
type pushRepository struct {
	db *sql.DB
}

// NewPushRepository creates a new PushRepository backed by the given database connection.
func NewPushRepository(db *sql.DB) PushRepository {
	return &pushRepository{db: db}
}

// UpsertVapidKey inserts or updates a user's VAPID keypair.
func (r *pushRepository) UpsertVapidKey(key *VapidKey) error {
	query := `
		INSERT INTO push_vapid_keys (user_public_key, vapid_public_key, vapid_private_key, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_public_key) DO UPDATE
		  SET vapid_public_key  = EXCLUDED.vapid_public_key,
		      vapid_private_key = EXCLUDED.vapid_private_key,
		      updated_at        = EXCLUDED.updated_at`

	_, err := r.db.Exec(query, key.UserPublicKey, key.VapidPublicKey, key.VapidPrivateKey, key.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to upsert vapid key: %w", err)
	}
	return nil
}

// GetVapidKey returns the VAPID keypair for the given user public key.
// Returns nil, nil when no keypair has been registered.
func (r *pushRepository) GetVapidKey(userPublicKey string) (*VapidKey, error) {
	query := `
		SELECT user_public_key, vapid_public_key, vapid_private_key, updated_at
		FROM push_vapid_keys
		WHERE user_public_key = $1`

	key := &VapidKey{}
	err := r.db.QueryRow(query, userPublicKey).Scan(
		&key.UserPublicKey,
		&key.VapidPublicKey,
		&key.VapidPrivateKey,
		&key.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get vapid key: %w", err)
	}
	return key, nil
}

// CreateSubscription persists a new push subscription.
// The caller is responsible for setting s.ID before calling (use google/uuid).
func (r *pushRepository) CreateSubscription(s *Subscription) error {
	categoriesJSON, err := json.Marshal(s.Categories)
	if err != nil {
		return fmt.Errorf("failed to marshal categories: %w", err)
	}

	query := `
		INSERT INTO push_subscriptions
		  (id, user_public_key, endpoint, p256dh, auth, device_label, categories, created_at, last_success_at, failure_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err = r.db.Exec(query,
		s.ID,
		s.UserPublicKey,
		s.Endpoint,
		s.P256dh,
		s.Auth,
		s.DeviceLabel,
		string(categoriesJSON),
		s.CreatedAt,
		s.LastSuccessAt,
		s.FailureCount,
	)
	if err != nil {
		return fmt.Errorf("failed to create subscription: %w", err)
	}
	return nil
}

// UpdateSubscription updates mutable fields of a subscription.
// The WHERE clause includes user_public_key as an ownership guard.
func (r *pushRepository) UpdateSubscription(s *Subscription) error {
	categoriesJSON, err := json.Marshal(s.Categories)
	if err != nil {
		return fmt.Errorf("failed to marshal categories: %w", err)
	}

	query := `
		UPDATE push_subscriptions
		SET endpoint      = $1,
		    p256dh        = $2,
		    auth          = $3,
		    categories    = $4
		WHERE id = $5 AND user_public_key = $6`

	result, err := r.db.Exec(query,
		s.Endpoint,
		s.P256dh,
		s.Auth,
		string(categoriesJSON),
		s.ID,
		s.UserPublicKey,
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

// DeleteSubscription removes a subscription by id, scoped to the owning user.
// Returns an error if no row was deleted (not owned or not found).
func (r *pushRepository) DeleteSubscription(id, userPublicKey string) error {
	result, err := r.db.Exec(
		`DELETE FROM push_subscriptions WHERE id = $1 AND user_public_key = $2`,
		id, userPublicKey,
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

// GetSubscriptionsForUsers returns all push subscriptions owned by any of the given user public keys.
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
		SELECT id, user_public_key, endpoint, p256dh, auth, device_label,
		       categories, created_at, last_success_at, failure_count
		FROM push_subscriptions
		WHERE user_public_key IN (%s)`, strings.Join(placeholders, ","))

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []*Subscription
	for rows.Next() {
		s := &Subscription{}
		var categoriesJSON string
		var deviceLabel sql.NullString
		var lastSuccessAt sql.NullInt64

		err := rows.Scan(
			&s.ID,
			&s.UserPublicKey,
			&s.Endpoint,
			&s.P256dh,
			&s.Auth,
			&deviceLabel,
			&categoriesJSON,
			&s.CreatedAt,
			&lastSuccessAt,
			&s.FailureCount,
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

		if err := json.Unmarshal([]byte(categoriesJSON), &s.Categories); err != nil {
			return nil, fmt.Errorf("failed to unmarshal categories: %w", err)
		}

		subs = append(subs, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subscriptions: %w", err)
	}

	return subs, nil
}

// GetSubscriptionByID returns a single subscription by id, scoped to the owning user.
// Returns nil, nil when not found or not owned by userPublicKey.
func (r *pushRepository) GetSubscriptionByID(id, userPublicKey string) (*Subscription, error) {
	query := `
		SELECT id, user_public_key, endpoint, p256dh, auth, device_label,
		       categories, created_at, last_success_at, failure_count
		FROM push_subscriptions
		WHERE id = $1 AND user_public_key = $2`

	s := &Subscription{}
	var categoriesJSON string
	var deviceLabel sql.NullString
	var lastSuccessAt sql.NullInt64

	err := r.db.QueryRow(query, id, userPublicKey).Scan(
		&s.ID,
		&s.UserPublicKey,
		&s.Endpoint,
		&s.P256dh,
		&s.Auth,
		&deviceLabel,
		&categoriesJSON,
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

	if err := json.Unmarshal([]byte(categoriesJSON), &s.Categories); err != nil {
		return nil, fmt.Errorf("failed to unmarshal categories: %w", err)
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
