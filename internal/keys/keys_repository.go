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

	err := r.db.QueryRowContext(ctx,
		`SELECT public_key, encrypted_private_key, salt, nonce
		 FROM space_keys WHERE id = 'main'`,
	).Scan(&pubKey, &privKey, &salt, &nonce)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &EncryptedKey{
		PublicKey:           ed25519.PublicKey(pubKey),
		EncryptedPrivateKey: privKey,
		Salt:                salt,
		Nonce:               nonce,
	}, nil
}

func (r *KeyRepository) SaveSpaceKey(ctx context.Context, enc *EncryptedKey) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO space_keys (id, public_key, encrypted_private_key, salt, nonce, created_at, algorithm)
		 VALUES ('main', $1, $2, $3, $4, $5, 'ed25519')`,
		[]byte(enc.PublicKey), enc.EncryptedPrivateKey, enc.Salt, enc.Nonce, time.Now().Unix(),
	)
	return err
}
