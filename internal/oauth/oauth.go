package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	scopeMCP           = "mcp"
	scopeOfflineAccess = "offline_access"

	pendingTTL = 10 * time.Minute
	codeTTL    = 60 * time.Second
	maxPending = 1000
)

const (
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidGrant         = "invalid_grant"
	CodeInvalidScope         = "invalid_scope"
	CodeInvalidTarget        = "invalid_target"
	CodeUnsupportedGrantType = "unsupported_grant_type"
	CodeServerError          = "server_error"
)

var (
	ErrRequestNotFound = errors.New("request not found or expired")
	ErrWrongUser       = errors.New("request belongs to another account")
	ErrStoreFull       = errors.New("too many pending requests")
)

type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Description
}

func newError(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

var nowFunc = time.Now

type pendingRequest struct {
	clientID         string
	clientName       string
	clientHost       string
	clientURI        string
	logoURI          string
	redirectURI      string
	redirectHost     string
	redirectLoopback bool
	codeChallenge    string
	state            string
	scope            string
	userPublicKey    string
	expiresAt        time.Time
}

type authCode struct {
	clientID      string
	clientName    string
	redirectURI   string
	codeChallenge string
	userPublicKey string
	deviceKey     string
	used          bool
	expiresAt     time.Time
}

// ponytail: single instance, lost on restart; move to the DB if the space runs multi-instance.
type store struct {
	mu      sync.Mutex
	pending map[string]*pendingRequest
	codes   map[string]*authCode
}

func newStore() *store {
	return &store{pending: map[string]*pendingRequest{}, codes: map[string]*authCode{}}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func (s *store) sweep(now time.Time) {
	for id, p := range s.pending {
		if now.After(p.expiresAt) {
			delete(s.pending, id)
		}
	}
	for h, c := range s.codes {
		if now.After(c.expiresAt) {
			delete(s.codes, h)
		}
	}
}

func (s *store) addPending(p *pendingRequest) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	now := nowFunc()
	p.expiresAt = now.Add(pendingTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if len(s.pending) >= maxPending {
		return "", ErrStoreFull
	}
	s.pending[id] = p
	return id, nil
}

func (s *store) lookupPending(id, userPublicKey string) (*pendingRequest, error) {
	p, ok := s.pending[id]
	if !ok || nowFunc().After(p.expiresAt) {
		delete(s.pending, id)
		return nil, ErrRequestNotFound
	}
	if p.userPublicKey == "" {
		p.userPublicKey = userPublicKey
	} else if p.userPublicKey != userPublicKey {
		return nil, ErrWrongUser
	}
	return p, nil
}

func (s *store) getPending(id, userPublicKey string) (pendingRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookupPending(id, userPublicKey)
	if err != nil {
		return pendingRequest{}, err
	}
	return *p, nil
}

func (s *store) takePending(id, userPublicKey string) (pendingRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookupPending(id, userPublicKey)
	if err != nil {
		return pendingRequest{}, err
	}
	delete(s.pending, id)
	return *p, nil
}

func (s *store) addCode(c *authCode) (string, error) {
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	now := nowFunc()
	c.expiresAt = now.Add(codeTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	s.codes[hashCode(code)] = c
	return code, nil
}

func (s *store) consumeCode(code string) (c authCode, reused, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[hashCode(code)]
	if !ok || nowFunc().After(entry.expiresAt) {
		return authCode{}, false, false
	}
	reused = entry.used
	entry.used = true
	return *entry, reused, true
}

func (s *store) setCodeDevice(code, deviceKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.codes[hashCode(code)]; ok {
		entry.deviceKey = deviceKey
	}
}
