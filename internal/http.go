package internal

import (
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/health"
	"github.com/prappser/prappser-spaces/internal/invitation"
	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/profile"
	"github.com/prappser/prappser-spaces/internal/push"
	"github.com/prappser/prappser-spaces/internal/setup"
	"github.com/prappser/prappser-spaces/internal/space"
	"github.com/prappser/prappser-spaces/internal/status"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/prappser/prappser-spaces/internal/websocket"
	"github.com/valyala/fasthttp"
)

const (
	ipRateLimitPerMinute         = 30
	identifierRateLimitPerMinute = 10

	// passwordEnrollLimit/Window rate-limit the password credential path of
	// POST /users/devices per normalized identifier - tighter than the
	// per-IP budget above because a password guesser can rotate IPs but not
	// the identifier they're targeting.
	passwordEnrollLimit  = 5
	passwordEnrollWindow = 15 * time.Minute
)

// challengePublicKeyKey extracts the publicKey query param used by
// GET /users/challenge, for per-identifier rate limiting.
func challengePublicKeyKey(ctx *fasthttp.RequestCtx) string {
	return string(ctx.QueryArgs().Peek("publicKey"))
}

// authPublicKeyKey extracts the publicKey claim from the (unverified) JWS
// bearer token used by POST /users/auth, for per-identifier rate limiting.
// This mirrors the claim extraction in user.verifyUserAuthJWS - cheap since
// no signature verification happens here.
func authPublicKeyKey(ctx *fasthttp.RequestCtx) string {
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	token, _, err := jwt.NewParser().ParseUnverified(parts[1], jwt.MapClaims{})
	if err != nil {
		return ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	publicKey, _ := claims["publicKey"].(string)
	return publicKey
}

// enrollIdentifierKey extracts the normalized password-login identifier from
// POST /users/devices' body, for per-identifier rate limiting on the
// password credential path. Returns "" for the delegation path (no
// identifier field) or a shape-invalid identifier - LimitByKey skips
// rate-limiting on an empty key, but the per-IP limiter composed around it
// (see the /users/devices route below) still applies either way.
func enrollIdentifierKey(ctx *fasthttp.RequestCtx) string {
	var req struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		return ""
	}
	identifier, err := user.NormalizeIdentifier(req.Identifier)
	if err != nil {
		return ""
	}
	return identifier
}

func NewRequestHandler(config *Config, userEndpoints *user.UserEndpoints, statusEndpoints *status.StatusEndpoints, healthEndpoints *health.HealthEndpoints, userService *user.UserService, appEndpoints *application.ApplicationEndpoints, invitationEndpoints *invitation.InvitationEndpoints, eventEndpoints *event.EventEndpoints, setupEndpoints *setup.SetupEndpoints, storageEndpoints *storage.Endpoints, wsHandler *websocket.Handler, spaceEndpoints *space.SpaceEndpoints, pushEndpoints *push.PushEndpoints, profileEndpoints *profile.ProfileEndpoints, deviceEndpoints *user.DeviceEndpoints, passwordEndpoints *user.PasswordEndpoints, assertionEndpoints *user.AssertionEndpoints) fasthttp.RequestHandler {
	authMiddleware := middleware.NewAuthMiddleware(userService)
	corsMiddleware := middleware.NewCORSMiddleware(config.AllowedOrigins)
	ipRateLimiter := middleware.NewRateLimiter(ipRateLimitPerMinute, time.Minute, config.TrustProxyHeaders)
	identifierRateLimiter := middleware.NewRateLimiter(identifierRateLimitPerMinute, time.Minute, config.TrustProxyHeaders)
	passwordRateLimiter := middleware.NewRateLimiter(passwordEnrollLimit, passwordEnrollWindow, config.TrustProxyHeaders)

	handler := func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())

		switch {
		case path == "/setup/railway":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireRole(setupEndpoints.SetRailwayToken, user.RoleOwner)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		case path == "/users/owners/register":
			ipRateLimiter.LimitByIP(userEndpoints.OwnerRegister)(ctx)
		case path == "/users/challenge":
			ipRateLimiter.LimitByIP(identifierRateLimiter.LimitByKey(userEndpoints.GetChallenge, challengePublicKeyKey))(ctx)
		case path == "/users/auth":
			ipRateLimiter.LimitByIP(identifierRateLimiter.LimitByKey(userEndpoints.UserAuth, authPublicKeyKey))(ctx)
		case path == "/users/devices":
			method := string(ctx.Method())
			switch method {
			case "POST":
				// Composed limiters, never skipping the per-IP one: the IP
				// limiter is wrapped INSIDE the identifier limiter, so even
				// when enrollIdentifierKey returns "" (delegation path) and
				// LimitByKey skips its own check, it still calls through to
				// the IP-limited handler - the per-IP budget always applies,
				// on top of the tighter per-identifier budget on the
				// password path (a guesser can rotate IPs but not the
				// identifier they're targeting).
				passwordRateLimiter.LimitByKey(ipRateLimiter.LimitByIP(deviceEndpoints.RegisterDevice), enrollIdentifierKey)(ctx)
			case "GET":
				authMiddleware.RequireAuth(deviceEndpoints.ListDevices)(ctx)
			case "DELETE":
				authMiddleware.RequireAuth(deviceEndpoints.RevokeDevice)(ctx)
			case "PATCH":
				authMiddleware.RequireAuth(deviceEndpoints.RenameDevice)(ctx)
			default:
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/users/salt":
			method := string(ctx.Method())
			if method == "GET" {
				ipRateLimiter.LimitByIP(passwordEndpoints.GetSalt)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/users/password":
			method := string(ctx.Method())
			if method == "POST" {
				ipRateLimiter.LimitByIP(authMiddleware.RequireAuth(passwordEndpoints.SetPassword))(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/users/me":
			method := string(ctx.Method())
			switch method {
			case "GET":
				authMiddleware.RequireAuth(userEndpoints.GetProfile)(ctx)
			case "PATCH":
				authMiddleware.RequireAuth(profileEndpoints.UpdateProfile)(ctx)
			default:
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/users/me/avatar":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireAuth(storageEndpoints.UploadUserAvatar)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		// #111: /space/publickey lets a client learn this space's key to use
		// as the audience when requesting an assertion (D2); /identity/assertion
		// mints one for the authenticated account.
		case path == "/space/publickey":
			method := string(ctx.Method())
			if method == "GET" {
				ipRateLimiter.LimitByIP(userEndpoints.GetSpacePublicKey)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/identity/assertion":
			method := string(ctx.Method())
			if method == "POST" {
				ipRateLimiter.LimitByIP(authMiddleware.RequireAuth(assertionEndpoints.IssueAssertion))(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		case path == "/health":
			healthEndpoints.Health(ctx)
		case path == "/status":
			authMiddleware.RequireAuth(statusEndpoints.Status)(ctx)
		case path == "/debug/env":
			statusEndpoints.DebugEnv(ctx)

		case path == "/applications/register":
			authMiddleware.RequireRole(appEndpoints.RegisterApplication, user.RoleOwner, user.RoleUser)(ctx)
		case path == "/applications":
			authMiddleware.RequireRole(appEndpoints.ListApplications, user.RoleOwner, user.RoleUser)(ctx)
		case strings.HasPrefix(path, "/applications/") && strings.HasSuffix(path, "/state"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "state" {
				ctx.SetUserValue("appID", parts[2])
				authMiddleware.RequireRole(appEndpoints.GetApplicationState, user.RoleOwner, user.RoleUser)(ctx)
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/applications/") && strings.Contains(path, "/invites"):
			parts := strings.Split(path, "/")
			if len(parts) >= 4 && parts[3] == "invites" {
				ctx.SetUserValue("appID", parts[2])

				if len(parts) == 4 {
					method := string(ctx.Method())
					switch method {
					case "POST":
						authMiddleware.RequireRole(invitationEndpoints.CreateInvite, user.RoleOwner, user.RoleUser)(ctx)
					case "GET":
						authMiddleware.RequireRole(invitationEndpoints.ListInvites, user.RoleOwner, user.RoleUser)(ctx)
					default:
						ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
					}
				} else if len(parts) == 5 {
					ctx.SetUserValue("inviteID", parts[4])
					method := string(ctx.Method())
					if method == "DELETE" {
						authMiddleware.RequireRole(invitationEndpoints.RevokeInvite, user.RoleOwner, user.RoleUser)(ctx)
					} else {
						ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
					}
				} else {
					ctx.Error("Not Found", fasthttp.StatusNotFound)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/applications/") && strings.HasSuffix(path, "/members/me"):
			parts := strings.Split(path, "/")
			if len(parts) == 5 && parts[3] == "members" && parts[4] == "me" {
				ctx.SetUserValue("appID", parts[2])
				method := string(ctx.Method())
				if method == "DELETE" {
					authMiddleware.RequireAuth(appEndpoints.LeaveApplication)(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/applications/"):
			parts := strings.Split(path, "/")
			if len(parts) == 3 {
				ctx.SetUserValue("appID", parts[2])
				method := string(ctx.Method())
				switch method {
				case "GET":
					authMiddleware.RequireAuth(appEndpoints.GetApplication)(ctx)
				case "DELETE":
					authMiddleware.RequireRole(appEndpoints.DeleteApplication, user.RoleOwner, user.RoleUser)(ctx)
				default:
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}

		case path == "/invites/check":
			method := string(ctx.Method())
			if method == "POST" {
				invitationEndpoints.CheckInvitation(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case strings.HasPrefix(path, "/invites/") && strings.HasSuffix(path, "/icon"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "icon" {
				ctx.SetUserValue("token", parts[2])
				method := string(ctx.Method())
				if method == "GET" {
					invitationEndpoints.GetInviteIcon(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/invites/") && strings.HasSuffix(path, "/join"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "join" {
				ctx.SetUserValue("token", parts[2])
				method := string(ctx.Method())
				if method == "POST" {
					invitationEndpoints.JoinApplication(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/invites/"):
			parts := strings.Split(path, "/")
			if len(parts) == 3 && parts[2] != "" {
				ctx.SetUserValue("token", parts[2])
				method := string(ctx.Method())
				if method == "GET" {
					invitationEndpoints.GetInviteInfo(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}

		case path == "/events":
			method := string(ctx.Method())
			if method == "GET" {
				authMiddleware.RequireAuth(eventEndpoints.GetEvents)(ctx)
			} else if method == "POST" {
				authMiddleware.RequireAuth(eventEndpoints.SubmitEvent)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		case path == "/storage/upload":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireAuth(storageEndpoints.Upload)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/storage/chunks/init":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireAuth(storageEndpoints.InitChunkedUpload)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case strings.HasPrefix(path, "/storage/chunks/") && strings.Contains(path, "/"):
			parts := strings.Split(path, "/")
			if len(parts) == 5 {
				ctx.SetUserValue("storageID", parts[3])
				ctx.SetUserValue("chunkIndex", parts[4])
				method := string(ctx.Method())
				if method == "POST" {
					authMiddleware.RequireAuth(storageEndpoints.UploadChunk)(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/storage/") && strings.HasSuffix(path, "/complete"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "complete" {
				ctx.SetUserValue("storageID", parts[2])
				method := string(ctx.Method())
				if method == "POST" {
					authMiddleware.RequireAuth(storageEndpoints.CompleteChunkedUpload)(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/storage/") && strings.HasSuffix(path, "/thumb"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "thumb" {
				ctx.SetUserValue("storageID", parts[2])
				authMiddleware.RequireAuth(storageEndpoints.GetThumbnail)(ctx)
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/storage/"):
			parts := strings.Split(path, "/")
			if len(parts) == 3 {
				ctx.SetUserValue("storageID", parts[2])
				method := string(ctx.Method())
				switch method {
				case "GET":
					authMiddleware.RequireAuth(storageEndpoints.GetFile)(ctx)
				case "DELETE":
					authMiddleware.RequireAuth(storageEndpoints.DeleteFile)(ctx)
				default:
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}

		case path == "/ws":
			wsHandler.HandleFastHTTP(ctx)

		case path == "/spaces/mine":
			method := string(ctx.Method())
			if method == "GET" {
				authMiddleware.RequireAuth(spaceEndpoints.GetMySpace)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/spaces/claim":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireAuth(spaceEndpoints.ClaimSpace)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/spaces":
			method := string(ctx.Method())
			switch method {
			case "GET":
				authMiddleware.RequireRole(spaceEndpoints.ListSpaces, user.RoleOwner)(ctx)
			case "POST":
				authMiddleware.RequireRole(spaceEndpoints.CreateSpace, user.RoleOwner)(ctx)
			default:
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case strings.HasPrefix(path, "/spaces/") && strings.HasSuffix(path, "/claim-invite"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "claim-invite" {
				ctx.SetUserValue("spaceID", parts[2])
				method := string(ctx.Method())
				if method == "POST" {
					authMiddleware.RequireRole(spaceEndpoints.CreateClaimInvite, user.RoleOwner)(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}
		case strings.HasPrefix(path, "/spaces/"):
			parts := strings.Split(path, "/")
			if len(parts) == 3 {
				ctx.SetUserValue("spaceID", parts[2])
				method := string(ctx.Method())
				if method == "DELETE" {
					authMiddleware.RequireRole(spaceEndpoints.DeleteSpace, user.RoleOwner)(ctx)
				} else {
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}

		case path == "/push/vapid-public-key":
			method := string(ctx.Method())
			if method == "GET" {
				pushEndpoints.GetVapidPublicKey(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		case path == "/push/subscriptions":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireAuth(pushEndpoints.CreateSubscription)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		case strings.HasPrefix(path, "/push/subscriptions/"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 {
				ctx.SetUserValue("subscriptionId", parts[3])
				method := string(ctx.Method())
				switch method {
				case "PATCH":
					authMiddleware.RequireAuth(pushEndpoints.UpdateSubscription)(ctx)
				case "DELETE":
					authMiddleware.RequireAuth(pushEndpoints.DeleteSubscription)(ctx)
				default:
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}

		default:
			ctx.Error("Not Found", fasthttp.StatusNotFound)
		}
	}

	return corsMiddleware.Handle(handler)
}
