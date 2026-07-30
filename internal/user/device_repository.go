package user

import (
	"database/sql"
	"fmt"
)

// EnsureDevice registers a device for an account if it doesn't already exist.
// Uses ON CONFLICT DO NOTHING so repeated calls for an already-known device
// (e.g. every invitation Join, or a retried device registration) are cheap no-ops.
func (r *userRepository) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	_, err := r.db.Exec(
		`INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (device_public_key) DO NOTHING`,
		devicePublicKey, userPublicKey, deviceName, createdAt,
	)
	if err != nil {
		return fmt.Errorf("failed to ensure device: %w", err)
	}
	return nil
}

// GetDevice returns nil, nil when no device with that key exists.
func (r *userRepository) GetDevice(devicePublicKey string) (*Device, error) {
	var d Device
	var deviceName sql.NullString
	var lastSeenAt sql.NullInt64
	var revokedAt sql.NullInt64

	err := r.db.QueryRow(
		`SELECT device_public_key, user_public_key, device_name, created_at, last_seen_at, revoked_at
		 FROM user_devices WHERE device_public_key = $1`,
		devicePublicKey,
	).Scan(&d.DevicePublicKey, &d.UserPublicKey, &deviceName, &d.CreatedAt, &lastSeenAt, &revokedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if deviceName.Valid {
		d.DeviceName = &deviceName.String
	}
	if lastSeenAt.Valid {
		d.LastSeenAt = &lastSeenAt.Int64
	}
	if revokedAt.Valid {
		d.RevokedAt = &revokedAt.Int64
	}
	return &d, nil
}

// ListDevices returns the non-revoked devices for an account.
func (r *userRepository) ListDevices(userPublicKey string) ([]*Device, error) {
	rows, err := r.db.Query(
		`SELECT device_public_key, user_public_key, device_name, created_at, last_seen_at, revoked_at
		 FROM user_devices WHERE user_public_key = $1 AND revoked_at IS NULL`,
		userPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		d := &Device{}
		var deviceName sql.NullString
		var lastSeenAt sql.NullInt64
		var revokedAt sql.NullInt64

		if err := rows.Scan(&d.DevicePublicKey, &d.UserPublicKey, &deviceName, &d.CreatedAt, &lastSeenAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}
		if deviceName.Valid {
			d.DeviceName = &deviceName.String
		}
		if lastSeenAt.Valid {
			d.LastSeenAt = &lastSeenAt.Int64
		}
		if revokedAt.Valid {
			d.RevokedAt = &revokedAt.Int64
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating devices: %w", err)
	}
	return devices, nil
}

// RevokeDevice soft-revokes a device and deletes its push subscriptions in a
// single transaction. The soft revoke (UPDATE revoked_at) never fires
// push_subscriptions' ON DELETE CASCADE - that only fires on a hard DELETE
// FROM user_devices, which this intentionally doesn't do (revocation keeps
// history). The user package can't import push (push already imports user,
// so the reverse would cycle), so this raw DELETE against push_subscriptions
// is how that coupling gets named instead of silently assumed.
func (r *userRepository) RevokeDevice(devicePublicKey string, ts int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`UPDATE user_devices SET revoked_at = $2 WHERE device_public_key = $1`,
		devicePublicKey, ts,
	); err != nil {
		return fmt.Errorf("failed to revoke device: %w", err)
	}

	if _, err := tx.Exec(
		`DELETE FROM push_subscriptions WHERE device_public_key = $1`,
		devicePublicKey,
	); err != nil {
		return fmt.Errorf("failed to delete device push subscriptions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit device revocation: %w", err)
	}
	return nil
}

// TouchDeviceLastSeen updates a device's last_seen_at timestamp.
func (r *userRepository) TouchDeviceLastSeen(devicePublicKey string, ts int64) error {
	_, err := r.db.Exec(
		`UPDATE user_devices SET last_seen_at = $1 WHERE device_public_key = $2`,
		ts, devicePublicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to touch device last seen: %w", err)
	}
	return nil
}
