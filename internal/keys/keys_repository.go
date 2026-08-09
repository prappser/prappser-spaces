package keys

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"time"
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

// SaveSpaceKey upserts the singleton space_keys row. An existing row is
// re-encrypted in place (identity import re-wrap under a new
// MASTER_PASSWORD, see KeyService.Initialize) without touching created_at,
// algorithm, or last_seen_at - only the crypto fields change on conflict.
func (r *KeyRepository) SaveSpaceKey(ctx context.Context, enc *EncryptedKey) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO space_keys (id, public_key, encrypted_private_key, salt, nonce, created_at, algorithm)
		 VALUES ('main', $1, $2, $3, $4, $5, 'ed25519')
		 ON CONFLICT (id) DO UPDATE SET
			public_key = EXCLUDED.public_key,
			encrypted_private_key = EXCLUDED.encrypted_private_key,
			salt = EXCLUDED.salt,
			nonce = EXCLUDED.nonce`,
		[]byte(enc.PublicKey), enc.EncryptedPrivateKey, enc.Salt, enc.Nonce, time.Now().Unix(),
	)
	return err
}

// TouchLastSeen persists the space identity's last-seen timestamp; see
// KeyService.TouchLastSeen for the throttling that guards how often this is
// called.
func (r *KeyRepository) TouchLastSeen(ctx context.Context, ts int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE space_keys SET last_seen_at = $1 WHERE id = 'main'`, ts)
	return err
}
