package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
)

type Service struct {
	agents   *user.AgentService
	users    user.UserRepository
	fetcher  *metadataFetcher
	store    *store
	issuer   string
	resource string
	appURL   string
}

func NewService(agents *user.AgentService, users user.UserRepository, externalURL, appURL string) *Service {
	issuer := strings.TrimRight(externalURL, "/")
	return &Service{
		agents:   agents,
		users:    users,
		fetcher:  newMetadataFetcher(),
		store:    newStore(),
		issuer:   issuer,
		resource: issuer + "/mcp",
		appURL:   strings.TrimRight(appURL, "/"),
	}
}

type authorizeParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Scope               string
	Resource            string
	HasResource         bool
}

type RequestInfo struct {
	ClientID         string `json:"clientId"`
	ClientHost       string `json:"clientHost"`
	ClientName       string `json:"clientName"`
	ClientURI        string `json:"clientUri,omitempty"`
	LogoURI          string `json:"logoUri,omitempty"`
	RedirectHost     string `json:"redirectHost"`
	RedirectLoopback bool   `json:"redirectLoopback"`
	Scope            string `json:"scope"`
	ExpiresAt        int64  `json:"expiresAt"`
}

type tokenParams struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
	Scope        string
	HasScope     bool
	Resource     string
	HasResource  bool
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (s *Service) Authorize(ctx context.Context, p authorizeParams) (string, error) {
	if _, err := parseClientID(p.ClientID); err != nil {
		return "", newError(CodeInvalidRequest, err.Error())
	}
	doc, err := s.fetcher.fetch(ctx, p.ClientID)
	if err != nil {
		log.Error().Err(err).Msg("[OAUTH] Client metadata fetch failed")
		return "", newError(CodeInvalidRequest, "client metadata document could not be fetched")
	}
	client, err := parseClientDoc(p.ClientID, doc)
	if err != nil {
		return "", newError(CodeInvalidRequest, err.Error())
	}

	redirect, err := parseRedirectURI(p.RedirectURI)
	if err != nil {
		return "", newError(CodeInvalidRequest, err.Error())
	}
	if !redirectMatches(redirect, p.RedirectURI, client.redirectURIs) {
		return "", newError(CodeInvalidRequest, "redirect_uri is not registered for this client")
	}

	if p.ResponseType != "code" {
		return "", newError(CodeInvalidRequest, "response_type must be code")
	}
	if p.CodeChallengeMethod != "S256" {
		return "", newError(CodeInvalidRequest, "code_challenge_method must be S256")
	}
	if !validChallenge(p.CodeChallenge) {
		return "", newError(CodeInvalidRequest, "code_challenge is invalid")
	}
	if err := s.checkResource(p.Resource, p.HasResource); err != nil {
		return "", err
	}
	if err := checkScope(p.Scope); err != nil {
		return "", err
	}

	id, err := s.store.addPending(&pendingRequest{
		clientID:         client.id,
		clientName:       client.name,
		clientHost:       client.host,
		clientURI:        client.uri,
		logoURI:          client.logoURI,
		redirectURI:      p.RedirectURI,
		redirectHost:     redirect.Host,
		redirectLoopback: redirect.Scheme == "http",
		codeChallenge:    p.CodeChallenge,
		state:            p.State,
		scope:            scopeMCP,
	})
	if err != nil {
		return "", err
	}
	log.Debug().Msg("[OAUTH] Authorization request parked for consent")
	return s.appURL + "/#/oauth/consent?space=" + url.QueryEscape(s.issuer) + "&request=" + url.QueryEscape(id), nil
}

func (s *Service) checkResource(resource string, present bool) error {
	if present && resource != s.resource {
		return newError(CodeInvalidTarget, "resource must be "+s.resource)
	}
	return nil
}

func checkScope(scope string) error {
	for _, tok := range strings.Fields(scope) {
		if tok != scopeMCP && tok != scopeOfflineAccess {
			return newError(CodeInvalidScope, "unsupported scope")
		}
	}
	return nil
}

func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for _, r := range c {
		if !isBase64URL(r) {
			return false
		}
	}
	return true
}

func isBase64URL(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !isBase64URL(r) && r != '.' && r != '~' {
			return false
		}
	}
	return true
}

func pkceMatches(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func (s *Service) GetRequest(id, userPublicKey string) (*RequestInfo, error) {
	p, err := s.store.getPending(id, userPublicKey)
	if err != nil {
		return nil, err
	}
	return &RequestInfo{
		ClientID:         p.clientID,
		ClientHost:       p.clientHost,
		ClientName:       p.clientName,
		ClientURI:        p.clientURI,
		LogoURI:          p.logoURI,
		RedirectHost:     p.redirectHost,
		RedirectLoopback: p.redirectLoopback,
		Scope:            p.scope,
		ExpiresAt:        p.expiresAt.Unix(),
	}, nil
}

func (s *Service) Approve(id, userPublicKey string) (string, error) {
	if _, err := s.store.getPending(id, userPublicKey); err != nil {
		return "", err
	}
	ok, err := s.agents.CanAddAgent(userPublicKey)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", user.ErrAgentLimit
	}
	p, err := s.store.takePending(id, userPublicKey)
	if err != nil {
		return "", err
	}
	code, err := s.store.addCode(&authCode{
		clientID:      p.clientID,
		clientName:    p.clientName,
		redirectURI:   p.redirectURI,
		codeChallenge: p.codeChallenge,
		userPublicKey: userPublicKey,
	})
	if err != nil {
		return "", err
	}
	log.Info().Msg("[OAUTH] Authorization approved")
	return s.redirectURL(p, url.Values{"code": {code}}), nil
}

func (s *Service) Deny(id, userPublicKey string) (string, error) {
	p, err := s.store.takePending(id, userPublicKey)
	if err != nil {
		return "", err
	}
	log.Info().Msg("[OAUTH] Authorization denied")
	return s.redirectURL(p, url.Values{"error": {"access_denied"}}), nil
}

func (s *Service) redirectURL(p pendingRequest, v url.Values) string {
	if p.state != "" {
		v.Set("state", p.state)
	}
	v.Set("iss", s.issuer)
	sep := "?"
	if strings.Contains(p.redirectURI, "?") {
		sep = "&"
	}
	return p.redirectURI + sep + v.Encode()
}

func (s *Service) Token(p tokenParams) (*TokenResponse, error) {
	switch p.GrantType {
	case "authorization_code":
		return s.exchangeCode(p)
	case "refresh_token":
		return s.refresh(p)
	case "":
		return nil, newError(CodeInvalidRequest, "grant_type is required")
	default:
		return nil, newError(CodeUnsupportedGrantType, "grant_type must be authorization_code or refresh_token")
	}
}

func (s *Service) exchangeCode(p tokenParams) (*TokenResponse, error) {
	if p.Code == "" || p.RedirectURI == "" || p.ClientID == "" || p.CodeVerifier == "" {
		return nil, newError(CodeInvalidRequest, "code, redirect_uri, client_id and code_verifier are required")
	}
	entry, reused, found := s.store.consumeCode(p.Code)
	if !found {
		return nil, newError(CodeInvalidGrant, "authorization code is invalid or expired")
	}
	if reused {
		if entry.deviceKey != "" {
			if err := s.users.RevokeDevice(entry.deviceKey, nowFunc().Unix()); err != nil {
				log.Error().Err(err).Msg("[OAUTH] Failed to revoke device after code reuse")
			}
		}
		log.Warn().Msg("[OAUTH] Authorization code reuse, device revoked")
		return nil, newError(CodeInvalidGrant, "authorization code is invalid or expired")
	}
	if p.ClientID != entry.clientID || p.RedirectURI != entry.redirectURI {
		return nil, newError(CodeInvalidGrant, "client_id or redirect_uri does not match the authorization request")
	}
	if !validVerifier(p.CodeVerifier) || !pkceMatches(p.CodeVerifier, entry.codeChallenge) {
		return nil, newError(CodeInvalidGrant, "code_verifier does not match")
	}
	if err := s.checkResource(p.Resource, p.HasResource); err != nil {
		return nil, err
	}

	tokens, err := s.agents.IssueTokens(entry.userPublicKey, entry.clientName)
	if errors.Is(err, user.ErrAgentLimit) {
		return nil, newError(CodeInvalidGrant, "agent limit reached, revoke an agent in Prappser settings")
	}
	if err != nil {
		s.store.unmarkCode(p.Code)
		log.Error().Err(err).Msg("[OAUTH] Failed to issue tokens")
		return nil, newError(CodeServerError, "failed to issue tokens")
	}
	s.store.setCodeDevice(p.Code, tokens.DevicePublicKey)
	return tokenResponse(tokens), nil
}

func (s *Service) refresh(p tokenParams) (*TokenResponse, error) {
	if p.RefreshToken == "" {
		return nil, newError(CodeInvalidRequest, "refresh_token is required")
	}
	if err := s.checkResource(p.Resource, p.HasResource); err != nil {
		return nil, err
	}
	if p.HasScope {
		if err := checkScope(p.Scope); err != nil {
			return nil, err
		}
	}
	tokens, err := s.agents.Refresh(p.RefreshToken)
	if errors.Is(err, user.ErrInvalidRefreshToken) {
		return nil, newError(CodeInvalidGrant, "refresh token is invalid or expired")
	}
	if err != nil {
		log.Error().Err(err).Msg("[OAUTH] Failed to refresh tokens")
		return nil, newError(CodeServerError, "failed to refresh tokens")
	}
	return tokenResponse(tokens), nil
}

func tokenResponse(t *user.AgentTokens) *TokenResponse {
	return &TokenResponse{
		AccessToken:  t.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    max(t.AccessTokenExpiresAt-time.Now().Unix(), 0),
		RefreshToken: t.RefreshToken,
		Scope:        scopeMCP,
	}
}
