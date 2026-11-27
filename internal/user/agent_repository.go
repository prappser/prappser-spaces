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

func (r *agentRepository) countLiveAgents(userPublicKey string, now int64) (int, error) {
	var n int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM user_devices d
		 JOIN agent_refresh_tokens t ON t.device_public_key = d.device_public_key
		 WHERE d.user_public_key = $1 AND d.kind = 'agent' AND d.revoked_at IS NULL AND t.expires_at > $2`,
		userPublicKey, now,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count agents: %w", err)
	}
	return n, nil
}

func (r *agentRepository) countLiveAgentsExcludingClient(userPublicKey, clientID string, now int64) (int, error) {
	var n int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM user_devices d
		 JOIN agent_refresh_tokens t ON t.device_public_key = d.device_public_key
		 WHERE d.user_public_key = $1 AND d.kind = 'agent' AND d.revoked_at IS NULL AND t.expires_at > $2
		   AND d.client_id IS DISTINCT FROM $3`,
		userPublicKey, now, clientID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count agents: %w", err)
	}
	return n, nil
}

func (r *agentRepository) liveAgentsForClient(userPublicKey, clientID string, now int64) ([]string, error) {
	rows, err := r.db.Query(
		`SELECT d.device_public_key FROM user_devices d
		 JOIN agent_refresh_tokens t ON t.device_public_key = d.device_public_key
		 WHERE d.user_public_key = $1 AND d.kind = 'agent' AND d.revoked_at IS NULL AND d.client_id = $2 AND t.expires_at > $3`,
		userPublicKey, clientID, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents for client: %w", err)
	}
	defer rows.Close()
	var devices []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("failed to scan agent: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating agents: %w", err)
	}
	return devices, nil
}

func (r *agentRepository) createAgent(devicePublicKey, userPublicKey string, name, clientID, clientHost *string, tokenHash string, createdAt, expiresAt int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at, kind, client_id, client_host)
		 VALUES ($1, $2, $3, $4, 'agent', $5, $6)`,
		devicePublicKey, userPublicKey, name, createdAt, clientID, clientHost,
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
		 SET prev_token_hash = t.token_hash, token_hash = $2, expires_at = $4, rotated_at = $3
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

type prevTokenMatch struct {
	device, account, currentHash string
	rotatedAt                    sql.NullInt64
}

func (r *agentRepository) deviceForPrevHash(hash string) (*prevTokenMatch, error) {
	var m prevTokenMatch
	err := r.db.QueryRow(
		`SELECT t.device_public_key, d.user_public_key, t.token_hash, t.rotated_at FROM agent_refresh_tokens t
		 JOIN user_devices d ON d.device_public_key = t.device_public_key
		 WHERE t.prev_token_hash = $1 AND d.revoked_at IS NULL`, hash,
	).Scan(&m.device, &m.account, &m.currentHash, &m.rotatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up previous refresh token: %w", err)
	}
	return &m, nil
}
