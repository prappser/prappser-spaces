package oauth

import (
	"context"
	"errors"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

const maxTokenBodyLen = 8 * 1024

type Endpoints struct {
	service *Service
}

func NewEndpoints(service *Service) *Endpoints {
	return &Endpoints{service: service}
}

type serverMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameter bool     `json:"authorization_response_iss_parameter_supported"`
}

func (oe *Endpoints) Metadata(ctx *fasthttp.RequestCtx) {
	iss := oe.service.issuer
	writeJSON(ctx, fasthttp.StatusOK, serverMetadata{
		Issuer:                            iss,
		AuthorizationEndpoint:             iss + "/oauth/authorize",
		TokenEndpoint:                     iss + "/oauth/token",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                   []string{scopeMCP},
		ClientIDMetadataDocumentSupported: true,
		AuthorizationResponseIssParameter: true,
	})
}

func (oe *Endpoints) Authorize(ctx *fasthttp.RequestCtx) {
	q := ctx.QueryArgs()
	params := authorizeParams{
		ClientID:            string(q.Peek("client_id")),
		RedirectURI:         string(q.Peek("redirect_uri")),
		ResponseType:        string(q.Peek("response_type")),
		CodeChallenge:       string(q.Peek("code_challenge")),
		CodeChallengeMethod: string(q.Peek("code_challenge_method")),
		State:               string(q.Peek("state")),
		Scope:               string(q.Peek("scope")),
		Resource:            string(q.Peek("resource")),
		HasResource:         q.Has("resource"),
	}

	consentURL, err := oe.service.Authorize(context.Background(), params)
	if err != nil {
		var oauthErr *Error
		switch {
		case errors.As(err, &oauthErr):
			log.Error().Str("code", oauthErr.Code).Msg("[OAUTH] Authorization request rejected")
			ctx.Error(oauthErr.Error(), fasthttp.StatusBadRequest)
		case errors.Is(err, ErrStoreFull):
			log.Error().Msg("[OAUTH] Too many pending authorization requests")
			ctx.Error("Too many pending authorization requests, try again later", fasthttp.StatusServiceUnavailable)
		default:
			log.Error().Err(err).Msg("[OAUTH] Failed to start authorization")
			ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		}
		return
	}
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Redirect(consentURL, fasthttp.StatusFound)
}

func (oe *Endpoints) Token(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("Pragma", "no-cache")

	if len(ctx.PostBody()) > maxTokenBodyLen {
		writeTokenError(ctx, newError(CodeInvalidRequest, "request body too large"))
		return
	}
	f := ctx.PostArgs()
	resp, err := oe.service.Token(tokenParams{
		GrantType:    string(f.Peek("grant_type")),
		Code:         string(f.Peek("code")),
		RedirectURI:  string(f.Peek("redirect_uri")),
		ClientID:     string(f.Peek("client_id")),
		CodeVerifier: string(f.Peek("code_verifier")),
		RefreshToken: string(f.Peek("refresh_token")),
		Scope:        string(f.Peek("scope")),
		HasScope:     f.Has("scope"),
		Resource:     string(f.Peek("resource")),
		HasResource:  f.Has("resource"),
	})
	if err != nil {
		var oauthErr *Error
		if !errors.As(err, &oauthErr) {
			oauthErr = newError(CodeServerError, "internal error")
		}
		writeTokenError(ctx, oauthErr)
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, resp)
}

func writeTokenError(ctx *fasthttp.RequestCtx, e *Error) {
	status := fasthttp.StatusBadRequest
	if e.Code == CodeServerError {
		status = fasthttp.StatusInternalServerError
	}
	log.Error().Str("code", e.Code).Msg("[OAUTH] Token request rejected")
	writeJSON(ctx, status, map[string]string{"error": e.Code, "error_description": e.Description})
}

func (oe *Endpoints) GetRequest(ctx *fasthttp.RequestCtx) {
	id, authenticatedUser, ok := consentCaller(ctx)
	if !ok {
		return
	}
	info, err := oe.service.GetRequest(id, authenticatedUser.PublicKey)
	if err != nil {
		writeConsentError(ctx, err)
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, info)
}

func (oe *Endpoints) Approve(ctx *fasthttp.RequestCtx) {
	id, authenticatedUser, ok := consentCaller(ctx)
	if !ok {
		return
	}
	redirectURI, err := oe.service.Approve(id, authenticatedUser.PublicKey)
	if err != nil {
		writeConsentError(ctx, err)
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"redirectUri": redirectURI})
}

func (oe *Endpoints) Deny(ctx *fasthttp.RequestCtx) {
	id, authenticatedUser, ok := consentCaller(ctx)
	if !ok {
		return
	}
	redirectURI, err := oe.service.Deny(id, authenticatedUser.PublicKey)
	if err != nil {
		writeConsentError(ctx, err)
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"redirectUri": redirectURI})
}

func consentCaller(ctx *fasthttp.RequestCtx) (string, *user.User, bool) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok {
		log.Error().Msg("[OAUTH] Missing authenticated user")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return "", nil, false
	}
	id, _ := ctx.UserValue("requestID").(string)
	return id, authenticatedUser, true
}

func writeConsentError(ctx *fasthttp.RequestCtx, err error) {
	switch {
	case errors.Is(err, ErrRequestNotFound):
		log.Error().Msg("[OAUTH] Consent request expired or unknown")
		writeJSON(ctx, fasthttp.StatusGone, map[string]string{"error": "request_expired"})
	case errors.Is(err, ErrWrongUser):
		log.Error().Msg("[OAUTH] Consent request belongs to another account")
		writeJSON(ctx, fasthttp.StatusForbidden, map[string]string{"error": "wrong_user"})
	case errors.Is(err, user.ErrAgentLimit):
		log.Error().Msg("[OAUTH] Agent limit reached at approval")
		writeJSON(ctx, fasthttp.StatusConflict, map[string]string{"error": "agent_limit"})
	default:
		log.Error().Err(err).Msg("[OAUTH] Consent request failed")
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": "internal_error"})
	}
}

func writeJSON(ctx *fasthttp.RequestCtx, status int, body any) {
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(body); err != nil {
		log.Error().Err(err).Msg("[OAUTH] Failed to encode response")
	}
}
