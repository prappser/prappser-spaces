package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

const pemTypePrivateKey = "PRIVATE KEY"

var errKeyFileExists = errors.New("key file already exists")

// loadKeyFile returns (nil, nil) only for fs.ErrNotExist; every other failure
// is an error so a bad file is never treated as missing.
func loadKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read space key file %s: %w", path, err)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("space key file %s is not valid PEM", path)
	}
	if block.Type != pemTypePrivateKey {
		return nil, fmt.Errorf("space key file %s has PEM type %q, want %q", path, block.Type, pemTypePrivateKey)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("space key file %s has trailing data after the key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse space key file %s: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("space key file %s does not hold an Ed25519 key", path)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("[KEYS] space key file has group/other permissions and could not be restricted to 0600")
		} else {
			log.Warn().Str("path", path).Msg("[KEYS] space key file had group/other permissions, restricted to 0600")
		}
	}
	return priv, nil
}

// writeKeyFile publishes the key with no-clobber Link and returns
// errKeyFileExists on EEXIST; the caller must then load and cross-check.
func writeKeyFile(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to encode space key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der})

	dir := filepath.Dir(path)
	_, statErr := os.Stat(dir)
	dirCreated := errors.Is(statErr, fs.ErrNotExist)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create key directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("failed to restrict key directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("failed to create temp key file in %s: %w", dir, err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(pemBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp key file %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp key file %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp key file %s: %w", tmp.Name(), err)
	}

	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errKeyFileExists
		}
		return fmt.Errorf("cannot publish space key file %s: the storage volume must support hard links: %w", path, err)
	}

	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("failed to open key directory %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("failed to sync key directory %s: %w", dir, err)
	}
	if dirCreated {
		pd, err := os.Open(filepath.Dir(dir))
		if err != nil {
			return fmt.Errorf("failed to open parent of key directory %s: %w", dir, err)
		}
		defer pd.Close()
		if err := pd.Sync(); err != nil {
			return fmt.Errorf("failed to sync parent of key directory %s: %w", dir, err)
		}
	}
	return nil
}
