package internal

import (
	"strings"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/health"
	"github.com/prappser/prappser-spaces/internal/invitation"
	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/setup"
	"github.com/prappser/prappser-spaces/internal/space"
	"github.com/prappser/prappser-spaces/internal/status"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/prappser/prappser-spaces/internal/websocket"
	"github.com/valyala/fasthttp"
)

func NewRequestHandler(config *Config, userEndpoints *user.UserEndpoints, statusEndpoints *status.StatusEndpoints, healthEndpoints *health.HealthEndpoints, userService *user.UserService, appEndpoints *application.ApplicationEndpoints, invitationEndpoints *invitation.InvitationEndpoints, eventEndpoints *event.EventEndpoints, setupEndpoints *setup.SetupEndpoints, storageEndpoints *storage.Endpoints, wsHandler *websocket.Handler, spaceEndpoints *space.SpaceEndpoints) fasthttp.RequestHandler {
	authMiddleware := middleware.NewAuthMiddleware(userService)
	corsMiddleware := middleware.NewCORSMiddleware(config.AllowedOrigins)

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

		default:
			ctx.Error("Not Found", fasthttp.StatusNotFound)
		}
	}

	return corsMiddleware.Handle(handler)
}
