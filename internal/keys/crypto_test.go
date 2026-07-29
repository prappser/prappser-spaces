package keys

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestDeriveKey_IsDeterministicForSameSaltAndDiffersForDifferentSalt(t *testing.T) {
	salt1 := make([]byte, SaltSize)
	salt2 := make([]byte, SaltSize)
	salt2[0] = 1 // guaranteed different from the all-zero salt1

	key1a := DeriveKey("password", salt1)
	key1b := DeriveKey("password", salt1)
	key2 := DeriveKey("password", salt2)

	if len(key1a) != KeySize {
		t.Errorf("key size: got %d, want %d", len(key1a), KeySize)
	}
	if !bytes.Equal(key1a, key1b) {
		t.Error("DeriveKey should be deterministic for the same password and salt")
	}
	if bytes.Equal(key1a, key2) {
		t.Error("DeriveKey should produce different keys for different salts")
	}
}

func TestGenerateEd25519KeyPair(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("Private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Verify key works for signing
	message := []byte("test message")
	sig := ed25519.Sign(priv, message)
	if !ed25519.Verify(pub, message, sig) {
		t.Error("Generated key cannot sign/verify")
	}
}

func TestEncryptDecryptPrivateKey(t *testing.T) {
	password := "TestMasterPassword123!"

	// Generate a keypair
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Encrypt the private key
	enc, err := EncryptPrivateKey(priv, password)
	if err != nil {
		t.Fatalf("Failed to encrypt private key: %v", err)
	}

	// Verify encrypted structure
	if len(enc.Salt) != SaltSize {
		t.Errorf("Salt size: got %d, want %d", len(enc.Salt), SaltSize)
	}
	if len(enc.Nonce) != NonceSize {
		t.Errorf("Nonce size: got %d, want %d", len(enc.Nonce), NonceSize)
	}
	if !bytes.Equal(enc.PublicKey, pub) {
		t.Error("Public key mismatch after encryption")
	}

	// Decrypt the private key
	decrypted, err := DecryptPrivateKey(enc, password)
	if err != nil {
		t.Fatalf("Failed to decrypt private key: %v", err)
	}

	// Verify decrypted key matches original
	if !bytes.Equal(decrypted.Seed(), priv.Seed()) {
		t.Error("Decrypted private key doesn't match original")
	}

	// Verify decrypted key works for signing
	message := []byte("test message after decryption")
	sig := ed25519.Sign(decrypted, message)
	if !ed25519.Verify(pub, message, sig) {
		t.Error("Decrypted key cannot sign/verify")
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	correctPassword := "CorrectPassword123!"
	wrongPassword := "WrongPassword456!"

	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	enc, err := EncryptPrivateKey(priv, correctPassword)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Try to decrypt with wrong password
	_, err = DecryptPrivateKey(enc, wrongPassword)
	if err == nil {
		t.Error("Expected error when decrypting with wrong password")
	}
}

func TestUniqueSaltAndNonce(t *testing.T) {
	password := "TestPassword"
	priv, _, _ := GenerateEd25519KeyPair()

	// Encrypt same key multiple times
	enc1, _ := EncryptPrivateKey(priv, password)
	enc2, _ := EncryptPrivateKey(priv, password)
	enc3, _ := EncryptPrivateKey(priv, password)

	// Salt should be unique each time
	if bytes.Equal(enc1.Salt, enc2.Salt) {
		t.Error("Salt should be unique - enc1 and enc2 have same salt")
	}
	if bytes.Equal(enc2.Salt, enc3.Salt) {
		t.Error("Salt should be unique - enc2 and enc3 have same salt")
	}

	// Nonce should be unique each time
	if bytes.Equal(enc1.Nonce, enc2.Nonce) {
		t.Error("Nonce should be unique - enc1 and enc2 have same nonce")
	}

	// Encrypted data should be different (due to different salt/nonce)
	if bytes.Equal(enc1.EncryptedPrivateKey, enc2.EncryptedPrivateKey) {
		t.Error("Encrypted data should differ due to unique salt/nonce")
	}

	// But all should decrypt to the same key
	dec1, _ := DecryptPrivateKey(enc1, password)
	dec2, _ := DecryptPrivateKey(enc2, password)
	dec3, _ := DecryptPrivateKey(enc3, password)

	if !bytes.Equal(dec1.Seed(), dec2.Seed()) || !bytes.Equal(dec2.Seed(), dec3.Seed()) {
		t.Error("All encryptions should decrypt to the same original key")
	}
}
