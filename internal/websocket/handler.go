package websocket

import (
	"strings"

	"github.com/fasthttp/websocket"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

var upgrader = websocket.FastHTTPUpgrader{
	CheckOrigin: func(ctx *fasthttp.RequestCtx) bool {
		// TODO: Configure for production - check allowed origins
		return true
	},
}

type Handler struct {
	hub         *Hub
	userService *user.UserService
}

func NewHandler(hub *Hub, userService *user.UserService) *Handler {
	return &Handler{
		hub:         hub,
		userService: userService,
	}
}

// HandleFastHTTP handles WebSocket upgrade requests for FastHTTP
func (h *Handler) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
	// Extract JWT token from query param or Authorization header
	token := string(ctx.QueryArgs().Peek("token"))
	if token == "" {
		authHeader := string(ctx.Request.Header.Peek("Authorization"))
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		log.Debug().Msg("[WS] Connection rejected: missing token")
		ctx.Error("Unauthorized: missing token", fasthttp.StatusUnauthorized)
		return
	}

	authenticatedUser, err := h.userService.ValidateJWT(token)
	if err != nil {
		log.Debug().Err(err).Msg("[WS] Connection rejected: invalid token")
		ctx.Error("Unauthorized: invalid token", fasthttp.StatusUnauthorized)
		return
	}

	err = upgrader.Upgrade(ctx, func(conn *websocket.Conn) {
		client := NewClient(h.hub, conn, authenticatedUser)
		h.hub.Register(client)

		// Send connected message
		client.send <- &OutgoingMessage{
			Type:   MessageTypeConnected,
			UserID: authenticatedUser.PublicKey,
		}

		log.Info().
			Str("userPublicKey", authenticatedUser.PublicKey[:20]+"...").
			Str("username", authenticatedUser.Username).
			Msg("[WS] Client connected")

		// Start read and write pumps
		go client.WritePump()
		client.ReadPump() // Blocks until disconnect
	})

	if err != nil {
		log.Error().Err(err).Msg("[WS] Failed to upgrade connection")
		return
	}
}
