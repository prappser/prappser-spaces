package internal

import (
	"strings"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/health"
	"github.com/prappser/prappser-spaces/internal/invitation"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/setup"
	"github.com/prappser/prappser-spaces/internal/status"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/prappser/prappser-spaces/internal/websocket"
	"github.com/valyala/fasthttp"
)

func NewRequestHandler(config *Config, userEndpoints *user.UserEndpoints, statusEndpoints *status.StatusEndpoints, healthEndpoints *health.HealthEndpoints, userService *user.UserService, appEndpoints *application.ApplicationEndpoints, invitationEndpoints *invitation.InvitationEndpoints, eventEndpoints *event.EventEndpoints, setupEndpoints *setup.SetupEndpoints, storageEndpoints *storage.Endpoints, wsHandler *websocket.Handler) fasthttp.RequestHandler {
	authMiddleware := middleware.NewAuthMiddleware(userService)
	corsMiddleware := middleware.NewCORSMiddleware(config.AllowedOrigins)

	handler := func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())

		switch {
		case path == "/setup/railway":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireRole(user.RoleOwner, setupEndpoints.SetRailwayToken)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}

		case path == "/users/owners/register":
			userEndpoints.OwnerRegister(ctx)
		case path == "/users/challenge":
			userEndpoints.GetChallenge(ctx)
		case path == "/users/auth":
			userEndpoints.UserAuth(ctx)
		case path == "/users/me":
			method := string(ctx.Method())
			if method == "GET" {
				authMiddleware.RequireAuth(userEndpoints.GetProfile)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/users/me/avatar":
			method := string(ctx.Method())
			if method == "POST" {
				authMiddleware.RequireAuth(storageEndpoints.UploadUserAvatar)(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			}
		case path == "/health":
			healthEndpoints.Health(ctx)
		case path == "/status":
			authMiddleware.RequireAuth(statusEndpoints.Status)(ctx)

		case path == "/applications/register":
			authMiddleware.RequireRole(user.RoleOwner, appEndpoints.RegisterApplication)(ctx)
		case path == "/applications":
			authMiddleware.RequireRole(user.RoleOwner, appEndpoints.ListApplications)(ctx)
		case strings.HasPrefix(path, "/applications/") && strings.HasSuffix(path, "/state"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "state" {
				ctx.SetUserValue("appID", parts[2])
				authMiddleware.RequireRole(user.RoleOwner, appEndpoints.GetApplicationState)(ctx)
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
						authMiddleware.RequireRole(user.RoleOwner, invitationEndpoints.CreateInvite)(ctx)
					case "GET":
						authMiddleware.RequireRole(user.RoleOwner, invitationEndpoints.ListInvites)(ctx)
					default:
						ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
					}
				} else if len(parts) == 5 {
					ctx.SetUserValue("inviteID", parts[4])
					method := string(ctx.Method())
					if method == "DELETE" {
						authMiddleware.RequireRole(user.RoleOwner, invitationEndpoints.RevokeInvite)(ctx)
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
					authMiddleware.RequireRole(user.RoleOwner, appEndpoints.DeleteApplication)(ctx)
				default:
					ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
				}
			} else {
				ctx.Error("Not Found", fasthttp.StatusNotFound)
			}

		case strings.HasPrefix(path, "/invites/") && strings.HasSuffix(path, "/info"):
			parts := strings.Split(path, "/")
			if len(parts) == 4 && parts[3] == "info" {
				ctx.SetUserValue("token", parts[2])
				invitationEndpoints.GetInviteInfo(ctx)
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
		case path == "/invites/check":
			method := string(ctx.Method())
			if method == "POST" {
				invitationEndpoints.CheckInvitation(ctx)
			} else {
				ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
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

		default:
			ctx.Error("Not Found", fasthttp.StatusNotFound)
		}
	}

	return corsMiddleware.Handle(handler)
}
