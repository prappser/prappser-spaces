package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize  = 32
	NonceSize = 12
	KeySize   = 32

	// Argon2id parameters (OWASP recommended for 2024+)
	Argon2Time    = 3         // iterations
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4         // parallelism
)

type EncryptedKey struct {
	PublicKey           ed25519.PublicKey
	EncryptedPrivateKey []byte
	Salt                []byte
	Nonce               []byte
	// LastSeenAt mirrors space_keys.last_seen_at (see migration 000026) -
	// nil when the row has never been touched. Only GetSpaceKey populates
	// this; EncodeIdentityBlob deliberately never reads it, so it can't
	// leak into an identity export.
	LastSeenAt *int64
}

func GenerateEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

// DeriveKey derives an AES key from a master password and salt using Argon2id
// with the package's standard parameters.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		KeySize,
	)
}

func EncryptPrivateKey(privateKey ed25519.PrivateKey, masterPassword string) (*EncryptedKey, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aesKey := DeriveKey(masterPassword, salt)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	encrypted := gcm.Seal(nil, nonce, privateKey.Seed(), nil)

	return &EncryptedKey{
		PublicKey:           privateKey.Public().(ed25519.PublicKey),
		EncryptedPrivateKey: encrypted,
		Salt:                salt,
		Nonce:               nonce,
	}, nil
}

func DecryptPrivateKey(enc *EncryptedKey, masterPassword string) (ed25519.PrivateKey, error) {
	aesKey := DeriveKey(masterPassword, enc.Salt)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	seed, err := gcm.Open(nil, enc.Nonce, enc.EncryptedPrivateKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: wrong password or corrupted key")
	}

	return ed25519.NewKeyFromSeed(seed), nil
}
