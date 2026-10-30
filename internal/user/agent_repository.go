package user

import (
	"database/sql"
	"fmt"
)

type agentRepository struct {
	db *sql.DB
}

func newAgentRepository(db *sql.DB) *agentRepository {
	return &agentRepository{db: db}
}

func (r *agentRepository) countLiveAgents(userPublicKey string) (int, error) {
	var n int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM user_devices WHERE user_public_key = $1 AND kind = 'agent' AND revoked_at IS NULL`,
		userPublicKey,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count agents: %w", err)
	}
	return n, nil
}

func (r *agentRepository) createAgent(devicePublicKey, userPublicKey string, name *string, tokenHash string, createdAt, expiresAt int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at, kind)
		 VALUES ($1, $2, $3, $4, 'agent')`,
		devicePublicKey, userPublicKey, name, createdAt,
	); err != nil {
		return fmt.Errorf("failed to insert agent device: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO agent_refresh_tokens (device_public_key, token_hash, expires_at) VALUES ($1, $2, $3)`,
		devicePublicKey, tokenHash, expiresAt,
	); err != nil {
		return fmt.Errorf("failed to insert refresh token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit agent: %w", err)
	}
	return nil
}

func (r *agentRepository) rotateRefreshToken(oldHash, newHash string, now, newExpiresAt int64) (string, error) {
	var device string
	err := r.db.QueryRow(
		`UPDATE agent_refresh_tokens t
		 SET prev_token_hash = t.token_hash, token_hash = $2, expires_at = $4
		 FROM user_devices d
		 WHERE t.token_hash = $1 AND t.expires_at > $3
		   AND d.device_public_key = t.device_public_key AND d.revoked_at IS NULL
		 RETURNING t.device_public_key`,
		oldHash, newHash, now, newExpiresAt,
	).Scan(&device)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to rotate refresh token: %w", err)
	}
	return device, nil
}

func (r *agentRepository) deviceForPrevHash(hash string) (string, error) {
	var device string
	err := r.db.QueryRow(
		`SELECT device_public_key FROM agent_refresh_tokens WHERE prev_token_hash = $1`, hash,
	).Scan(&device)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to look up previous refresh token: %w", err)
	}
	return device, nil
}
