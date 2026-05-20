package push

import (
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// PushEndpoints exposes HTTP handlers for VAPID public key retrieval and subscription CRUD.
type PushEndpoints struct {
	service      *PushService
	repo         PushRepository
	vapidService *SpaceVapidService
}

// NewPushEndpoints creates a new PushEndpoints.
func NewPushEndpoints(service *PushService, repo PushRepository, vapidService *SpaceVapidService) *PushEndpoints {
	return &PushEndpoints{service: service, repo: repo, vapidService: vapidService}
}

// GetVapidPublicKey handles GET /push/vapid-public-key.
// Returns the space VAPID public key. No authentication required.
func (pe *PushEndpoints) GetVapidPublicKey(ctx *fasthttp.RequestCtx) {
	log.Debug().Msg("[PUSH] GetVapidPublicKey called")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{"publicKey": pe.vapidService.PublicKey()})
}

// createSubscriptionRequest is the request body for POST /push/subscriptions.
type createSubscriptionRequest struct {
	Endpoint            string     `json:"endpoint"`
	P256dh              string     `json:"p256dh"`
	Auth                string     `json:"auth"`
	DeviceLabel         *string    `json:"deviceLabel,omitempty"`
	Categories          Categories `json:"categories"`
	MutedApplicationIDs []string   `json:"mutedApplicationIds"`
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

	if req.MutedApplicationIDs == nil {
		req.MutedApplicationIDs = []string{}
	}

	sub := &Subscription{
		ID:                  uuid.NewString(),
		UserPublicKey:       authenticatedUser.PublicKey,
		Endpoint:            req.Endpoint,
		P256dh:              req.P256dh,
		Auth:                req.Auth,
		DeviceLabel:         req.DeviceLabel,
		Categories:          req.Categories,
		MutedApplicationIDs: req.MutedApplicationIDs,
		CreatedAt:           time.Now().Unix(),
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
	Endpoint            string     `json:"endpoint"`
	P256dh              string     `json:"p256dh"`
	Auth                string     `json:"auth"`
	Categories          Categories `json:"categories"`
	MutedApplicationIDs []string   `json:"mutedApplicationIds"`
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

	if req.MutedApplicationIDs == nil {
		req.MutedApplicationIDs = []string{}
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
	existing.MutedApplicationIDs = req.MutedApplicationIDs

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
