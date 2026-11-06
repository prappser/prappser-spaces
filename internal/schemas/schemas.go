// Package schemas keeps the current signed schema bundle container and refreshes it from a URL.
package schemas

// Current is the verified bundle served to clients; Container is the exact signed bytes.
type Current struct {
	Bundle    int
	Container []byte
}

// Stored is the persisted bundle row.
type Stored struct {
	Bundle    int
	Container []byte
}

type Store interface {
	// Get returns nil, nil when no row exists.
	Get() (*Stored, error)
	Save(bundle int, container []byte) error
}
