package event

import (
	"strconv"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type EventEndpoints struct {
	eventService *EventService
}

func NewEventEndpoints(eventService *EventService) *EventEndpoints {
	return &EventEndpoints{
		eventService: eventService,
	}
}

// GetEvents handles GET /events
// Query parameters:
//   - since (optional): Last event ID client received (UUID v7)
//   - limit (optional, default: 100, max: 500): Maximum events to return
func (ee *EventEndpoints) GetEvents(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Parse query parameters
	sinceEventID := string(ctx.QueryArgs().Peek("since"))

	limitStr := string(ctx.QueryArgs().Peek("limit"))
	limit := 100 // Default
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil {
			if parsedLimit > 0 && parsedLimit <= 500 {
				limit = parsedLimit
			} else if parsedLimit > 500 {
				limit = 500 // Max limit
			}
		}
	}

	// Get events for the authenticated user's applications
	response, err := ee.eventService.GetEventsSince(authenticatedUser.PublicKey, sinceEventID, limit)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get events")
		ctx.Error("Failed to get events", fasthttp.StatusInternalServerError)
		return
	}

	// Return response
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode events response")
		ctx.Error("Failed to encode response", fasthttp.StatusInternalServerError)
		return
	}
}

// SubmitEvent handles POST /events
func (ee *EventEndpoints) SubmitEvent(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req struct {
		Event *Event `json:"event"`
	}

	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]interface{}{
			"accepted": false,
			"error":    "invalid request body",
		})
		return
	}

	if req.Event == nil {
		log.Error().Msg("Event is missing in request")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]interface{}{
			"accepted": false,
			"error":    "event is required",
		})
		return
	}

	acceptedEvent, err := ee.eventService.AcceptEvent(ctx, req.Event, authenticatedUser)
	if err != nil {
		log.Error().Err(err).Msg("Failed to accept event")

		var statusCode int
		var reason string

		switch {
		case err == ErrUnauthorized || err.Error() == "unauthorized":
			statusCode = fasthttp.StatusForbidden
			reason = "unauthorized"
		case err == ErrValidation || err.Error() == "validation error":
			statusCode = fasthttp.StatusBadRequest
			reason = "validation_failed"
		default:
			statusCode = fasthttp.StatusInternalServerError
			reason = "internal_error"
		}

		ctx.SetStatusCode(statusCode)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]interface{}{
			"accepted": false,
			"error":    err.Error(),
			"reason":   reason,
		})
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]interface{}{
		"accepted":  true,
		"event":     acceptedEvent,
		"sequence":  acceptedEvent.SequenceNumber,
		"timestamp": acceptedEvent.CreatedAt,
	})
}
