package keys

import (
	"context"
	"crypto/ed25519"
	"database/sql"
)

type KeyRepository struct {
	db *sql.DB
}

func NewKeyRepository(db *sql.DB) *KeyRepository {
	return &KeyRepository{db: db}
}

func (r *KeyRepository) GetSpaceKey(ctx context.Context) (*EncryptedKey, error) {
	var pubKey, privKey, salt, nonce []byte
	var lastSeenAt sql.NullInt64

	err := r.db.QueryRowContext(ctx,
		`SELECT public_key, encrypted_private_key, salt, nonce, last_seen_at
		 FROM space_keys WHERE id = 'main'`,
	).Scan(&pubKey, &privKey, &salt, &nonce, &lastSeenAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	enc := &EncryptedKey{
		PublicKey:           ed25519.PublicKey(pubKey),
		EncryptedPrivateKey: privKey,
		Salt:                salt,
		Nonce:               nonce,
	}
	if lastSeenAt.Valid {
		enc.LastSeenAt = &lastSeenAt.Int64
	}
	return enc, nil
}

func (r *KeyRepository) HasUsers(ctx context.Context) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&exists)
	return exists, err
}

// TouchLastSeen persists the space identity's last-seen timestamp; see
// KeyService.TouchLastSeen for the throttling that guards how often this is
// called.
func (r *KeyRepository) TouchLastSeen(ctx context.Context, ts int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE space_keys SET last_seen_at = $1 WHERE id = 'main'`, ts)
	return err
}
