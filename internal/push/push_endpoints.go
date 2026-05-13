package push

import (
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// PushEndpoints exposes HTTP handlers for VAPID key management and subscription CRUD.
type PushEndpoints struct {
	service *PushService
	repo    PushRepository
}

// NewPushEndpoints creates a new PushEndpoints.
func NewPushEndpoints(service *PushService, repo PushRepository) *PushEndpoints {
	return &PushEndpoints{service: service, repo: repo}
}

// setVapidKeysRequest is the request body for PUT /push/vapid.
type setVapidKeysRequest struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// SetVapidKeys handles PUT /push/vapid.
// Upserts the authenticated user's VAPID keypair.
func (pe *PushEndpoints) SetVapidKeys(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PUSH] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req setVapidKeysRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[PUSH] Failed to parse vapid key request body")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.PublicKey == "" || req.PrivateKey == "" {
		log.Error().Msg("[PUSH] Missing publicKey or privateKey in vapid request")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{"error": "publicKey and privateKey are required"})
		return
	}

	key := &VapidKey{
		UserPublicKey:   authenticatedUser.PublicKey,
		VapidPublicKey:  req.PublicKey,
		VapidPrivateKey: req.PrivateKey,
		UpdatedAt:       time.Now().Unix(),
	}

	if err := pe.repo.UpsertVapidKey(key); err != nil {
		log.Error().Err(err).Msg("[PUSH] Failed to upsert vapid key")
		ctx.Error("Failed to save VAPID keys", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("userPublicKey", authenticatedUser.PublicKey).Msg("[PUSH] VAPID keys upserted")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{"status": "ok"})
}

// createSubscriptionRequest is the request body for POST /push/subscriptions.
type createSubscriptionRequest struct {
	Endpoint    string     `json:"endpoint"`
	P256dh      string     `json:"p256dh"`
	Auth        string     `json:"auth"`
	DeviceLabel *string    `json:"deviceLabel,omitempty"`
	Categories  Categories `json:"categories"`
}

// CreateSubscription handles POST /push/subscriptions.
// Creates a new push subscription for the authenticated user.
func (pe *PushEndpoints) CreateSubscription(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PUSH] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req createSubscriptionRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[PUSH] Failed to parse create subscription request body")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.Endpoint == "" || req.P256dh == "" || req.Auth == "" {
		log.Error().Msg("[PUSH] Missing required fields in create subscription request")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{"error": "endpoint, p256dh, and auth are required"})
		return
	}

	sub := &Subscription{
		ID:            uuid.NewString(),
		UserPublicKey: authenticatedUser.PublicKey,
		Endpoint:      req.Endpoint,
		P256dh:        req.P256dh,
		Auth:          req.Auth,
		DeviceLabel:   req.DeviceLabel,
		Categories:    req.Categories,
		CreatedAt:     time.Now().Unix(),
	}

	if err := pe.repo.CreateSubscription(sub); err != nil {
		log.Error().Err(err).Msg("[PUSH] Failed to create subscription")
		ctx.Error("Failed to create subscription", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("subscriptionId", sub.ID).Str("userPublicKey", authenticatedUser.PublicKey).Msg("[PUSH] Subscription created")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{"id": sub.ID})
}

// updateSubscriptionRequest is the request body for PATCH /push/subscriptions/:id.
type updateSubscriptionRequest struct {
	Endpoint   string     `json:"endpoint"`
	P256dh     string     `json:"p256dh"`
	Auth       string     `json:"auth"`
	Categories Categories `json:"categories"`
}

// UpdateSubscription handles PATCH /push/subscriptions/:id.
// Updates mutable fields of a subscription owned by the authenticated user.
func (pe *PushEndpoints) UpdateSubscription(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PUSH] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	subscriptionID, _ := ctx.UserValue("subscriptionId").(string)
	if subscriptionID == "" {
		log.Error().Msg("[PUSH] Missing subscriptionId in path")
		ctx.Error("Subscription ID is required", fasthttp.StatusBadRequest)
		return
	}

	existing, err := pe.repo.GetSubscriptionByID(subscriptionID, authenticatedUser.PublicKey)
	if err != nil {
		log.Error().Err(err).Str("subscriptionId", subscriptionID).Msg("[PUSH] Failed to fetch subscription for update")
		ctx.Error("Failed to fetch subscription", fasthttp.StatusInternalServerError)
		return
	}
	if existing == nil {
		ctx.Error("Subscription not found", fasthttp.StatusNotFound)
		return
	}

	var req updateSubscriptionRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[PUSH] Failed to parse update subscription request body")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	// Apply partial updates: only overwrite fields that are present in the request.
	if req.Endpoint != "" {
		existing.Endpoint = req.Endpoint
	}
	if req.P256dh != "" {
		existing.P256dh = req.P256dh
	}
	if req.Auth != "" {
		existing.Auth = req.Auth
	}
	existing.Categories = req.Categories

	if err := pe.repo.UpdateSubscription(existing); err != nil {
		log.Error().Err(err).Str("subscriptionId", subscriptionID).Msg("[PUSH] Failed to update subscription")
		ctx.Error("Failed to update subscription", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("subscriptionId", subscriptionID).Msg("[PUSH] Subscription updated")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{"status": "ok"})
}

// DeleteSubscription handles DELETE /push/subscriptions/:id.
// Removes a subscription owned by the authenticated user.
func (pe *PushEndpoints) DeleteSubscription(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PUSH] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	subscriptionID, _ := ctx.UserValue("subscriptionId").(string)
	if subscriptionID == "" {
		log.Error().Msg("[PUSH] Missing subscriptionId in path")
		ctx.Error("Subscription ID is required", fasthttp.StatusBadRequest)
		return
	}

	if err := pe.repo.DeleteSubscription(subscriptionID, authenticatedUser.PublicKey); err != nil {
		if err.Error() == "subscription not found" {
			ctx.Error("Subscription not found", fasthttp.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("subscriptionId", subscriptionID).Msg("[PUSH] Failed to delete subscription")
		ctx.Error("Failed to delete subscription", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("subscriptionId", subscriptionID).Msg("[PUSH] Subscription deleted")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}
