package websocket

import (
	"strings"
	"time"

	"github.com/fasthttp/websocket"
	"github.com/golang-jwt/jwt/v5"
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
	agents      *user.AgentService
	// beforeRegister is a test seam between token validation and hub registration.
	beforeRegister func()
}

func NewHandler(hub *Hub, userService *user.UserService, agents *user.AgentService) *Handler {
	return &Handler{
		hub:         hub,
		userService: userService,
		agents:      agents,
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

	var authenticatedUser *user.User
	var err error
	if hdr, _, perr := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{}); perr == nil && h.agents != nil && hdr.Header["typ"] == "at+jwt" {
		authenticatedUser, err = h.agents.ValidateAccessToken(token)
	} else {
		authenticatedUser, err = h.userService.ValidateJWT(token)
	}
	if err != nil {
		log.Debug().Err(err).Msg("[WS] Connection rejected: invalid token")
		ctx.Error("Unauthorized: invalid token", fasthttp.StatusUnauthorized)
		return
	}

	err = upgrader.Upgrade(ctx, func(conn *websocket.Conn) {
		// with KeepHijackedConns nothing else closes the conn if Unregister never closes send
		defer conn.Close()

		if authenticatedUser.Agent {
			t := time.AfterFunc(time.Until(time.Unix(authenticatedUser.TokenExpiresAt, 0)), func() { conn.Close() })
			defer t.Stop()
		}

		client := NewClient(h.hub, conn, authenticatedUser)
		if h.beforeRegister != nil {
			h.beforeRegister()
		}
		h.hub.Register(client)

		// A revoke between validation and registration found no client to disconnect.
		// Closing the conn here makes ReadPump below fail and unregister the client.
		if authenticatedUser.Agent {
			if active, err := h.agents.DeviceActive(authenticatedUser.DevicePublicKey); err != nil || !active {
				conn.Close()
			}
		}

		// Send connected message
		client.send <- &OutgoingMessage{
			Type:   MessageTypeConnected,
			UserID: authenticatedUser.PublicKey,
		}

		log.Debug().
			Str("userPublicKey", authenticatedUser.PublicKey[:20]+"...").
			Str("devicePublicKey", authenticatedUser.DevicePublicKey[:min(20, len(authenticatedUser.DevicePublicKey))]).
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
