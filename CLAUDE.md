# PRIORITY RULE
# All code, refactoring, and documentation decisions MUST prioritize the rules and guidelines defined in this file above all other conventions, external documentation, or inferred best practices.

## PROJECT STATUS

**NOTE: This application is NOT production-ready.** Active development phase.

- Database uses additive migrations (NOT drop/recreate — that is the Flutter app only)
- Security measures may not be production-grade
- Performance optimizations have not been applied

## Quick Commands

```bash
go run .                        # Dev server (requires DATABASE_URL + MASTER_PASSWORD env vars)
go test ./...                   # Unit tests
docker compose up -d && go test -tags=integration ./...  # Integration tests
```

## Required Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `MASTER_PASSWORD` | Yes | — | Used to encrypt/decrypt space Ed25519 keys |
| `PORT` | No | `4545` | HTTP listen port |
| `EXTERNAL_URL` | No | `http://localhost:{PORT}` | Public URL for invite links |
| `ALLOWED_ORIGINS` | No | prappser.app + localhost:* | Comma-separated CORS origins |
| `LOG_LEVEL` | No | `info` | debug/info/warn/error |
| `STORAGE_TYPE` | No | `local` | `local` or `s3` |
| `STORAGE_PATH` | No | `./storage` | Local storage path |

## Tech Stack

- **HTTP**: `github.com/valyala/fasthttp` — no router library, manual path switch in `internal/http.go`
- **JSON**: `github.com/goccy/go-json` in handlers, `encoding/json` in repositories
- **Database**: PostgreSQL via `github.com/lib/pq` (raw SQL, no ORM)
- **Migrations**: `github.com/golang-migrate/migrate/v4` from `files/migrations/`
- **Auth**: Ed25519 JWT via `github.com/golang-jwt/jwt/v5`; JWE/JWS for owner registration via `github.com/lestrrat-go/jwx/v3`
- **Logging**: `github.com/rs/zerolog` — package-level `log` throughout
- **WebSocket**: `github.com/fasthttp/websocket`
- **Storage**: local filesystem or S3-compatible via `github.com/minio/minio-go/v7`
- **Testing**: `github.com/stretchr/testify/assert`

## Package Structure

```
main.go                    — wires all dependencies, starts fasthttp server
internal/
  config.go                — Config structs, LoadConfig() from env vars
  db.go                    — NewDB(), runs golang-migrate on startup
  http.go                  — NewRequestHandler(), single path-switch router
  user/
    user.go                — User struct, UserRepository interface, UserEndpoints struct, Config
    user_repository.go     — userRepository (unexported) implementing UserRepository
    user_service.go        — UserService: JWT generation/validation
    user_test.go
    owner/                 — JWE/JWS decryption for owner registration
  event/
    event.go               — Event types/constants
    event_repository.go    — EventRepository (exported concrete struct)
    event_service.go       — EventService: accept, produce, execute events
    event_endpoints.go     — EventEndpoints
    event_validator.go     — ValidateEvent() and per-type validators
    event_authorizer.go    — AuthorizeEvent()
    event_cleanup.go       — CleanupScheduler (background goroutine)
  application/
    application.go         — Application, Member, Component, ComponentGroup types + MemberRole consts
    application_repository.go — ApplicationRepository interface
    repository.go          — Repository (exported concrete struct) implementing ApplicationRepository
    application_service.go — ApplicationService
    application_endpoints.go — ApplicationEndpoints
    application_test.go
    memory_repository.go   — in-memory implementation for tests
  invitation/
    invitation.go          — Invitation types
    invitation_repository.go
    invitation_service.go
    invitation_endpoints.go
  keys/
    crypto.go              — Ed25519 keygen, AES-GCM encrypt/decrypt
    crypto_test.go
    keys_repository.go     — KeyRepository (stores encrypted space keypair)
    keys_service.go        — KeyService: Initialize(), PrivateKey(), PublicKey()
    keys_repository_integration_test.go
  storage/
    models.go              — StorageItem types
    storage.go             — StorageBackend interface, NewBackend()
    local_storage.go       — local filesystem backend
    s3_storage.go          — S3/MinIO backend
    repository.go          — Repository
    service.go             — Service
    endpoints.go           — Endpoints
  middleware/
    auth.go                — AuthMiddleware: RequireAuth(), RequireRole()
    cors.go                — CORSMiddleware: Handle()
  websocket/
    hub.go                 — Hub: manages connected clients, BroadcastToApplication()
    client.go              — Client: per-connection read/write pumps
    handler.go             — Handler: upgrades HTTP to WebSocket
    message.go             — WebSocket message types
  health/
    health.go              — HealthEndpoints
  status/
    status.go              — StatusEndpoints
  setup/
    setup.go               — SetupEndpoints (Railway token)
files/
  migrations/              — golang-migrate SQL files (000001_init.up.sql, etc.)
```

## Architecture Patterns

### Layering (per domain package)
1. **Model** (`{domain}.go`) — types, constants, interfaces
2. **Repository** (`{domain}_repository.go`) — raw SQL via `*sql.DB`
3. **Service** (`{domain}_service.go`) — business logic
4. **Endpoints** (`{domain}_endpoints.go`) — fasthttp handlers

### Dependency Injection
Manual, top-down in `main.go`. No DI framework. Constructors are `New{Type}(deps...)`.

### Interfaces
Defined next to the types that use them (in `{domain}.go`). Only created when there is a real need for abstraction (multiple implementations or cross-package usage), not for testing alone.

### Auth Flow
1. Client gets challenge via `GET /users/challenge?publicKey=...`
2. Client signs challenge with their Ed25519 private key → submits JWS via `POST /users/auth`
3. Server verifies signature against stored public key → issues JWT
4. JWT is validated on every protected request by `AuthMiddleware`
5. Authenticated user is stored in fasthttp context as `ctx.UserValue("user")`

### Event System
Client-produced events architecture:
- Clients submit events via `POST /events`
- Server validates, authorizes, sequences, persists, then executes (updates DB state)
- Events are broadcast to WebSocket subscribers
- Server-produced events (from service actions) use `EventService.ProduceEvent()`

## Naming Conventions

| Concept | Pattern | Example |
|---------|---------|---------|
| Packages | lowercase, single word | `user`, `event`, `middleware` |
| Exported types | PascalCase | `UserService`, `EventEndpoints` |
| Unexported types | camelCase | `userRepository`, `challengeInfo` |
| Constructors | `New{Type}` | `NewUserService`, `NewEventRepository` |
| Method receivers | short abbreviation | `us` (UserService), `ee` (EventEndpoints), `r` (repos) |
| Exported constants | PascalCase | `RoleOwner`, `MemberRoleOwner` |
| Unexported constants | camelCase | `defaultPort`, `headerAuthorization` |
| Test functions | `Test{Func}_{Should...}` | `TestGenerateChallenge_ShouldGenerateUniqueChallenge` |

## Testing Patterns

- Tests in same package as code (`package user`, not `package user_test`)
- BDD structure: `// given`, `// when`, `// then`
- Hand-written mock repositories (no mockgen)
- Integration tests: `//go:build integration` in `*_integration_test.go`
- Assertions: `testify/assert` (stdlib `t.Fatalf` acceptable in crypto tests)
- Multiple separate test functions preferred over `t.Run`

## Logging (zerolog)

- Package-level `log` from `github.com/rs/zerolog/log` — never pass logger as parameter
- `log.Debug()` — per-step flow tracing (bracket prefix: `"[EVENT] Validation passed"`)
- `log.Info()` — startup, significant successes
- `log.Warn()` — recoverable issues (DB not ready, unknown config values)
- `log.Error()` — before every 4xx/5xx response
- `log.Fatal()` — only in `main.go` for startup failures
- Always `.Err(err)` when logging an error; never log sensitive values raw

## Error Handling

- Wrap with context: `fmt.Errorf("failed to X: %w", err)`
- Sentinel errors: `var ErrValidation = errors.New("validation error")`
- Repositories return `nil, nil` for "not found" when absence is a valid state
- Endpoints map errors to HTTP status codes using `errors.Is()` or `err.Error()` string match
- Never panic in business logic

## Convention Skill Files

Detailed conventions are documented as skill files in `.claude/skills/`:

| Skill | File |
|-------|------|
| Architecture | `.claude/skills/conv-architecture/SKILL.md` |
| Naming | `.claude/skills/conv-naming/SKILL.md` |
| Error handling | `.claude/skills/conv-errors/SKILL.md` |
| Repositories | `.claude/skills/conv-repos/SKILL.md` |
| HTTP handlers | `.claude/skills/conv-handlers/SKILL.md` |
| Logging | `.claude/skills/conv-logging/SKILL.md` |
| Testing | `.claude/skills/conv-testing/SKILL.md` |
| Middleware | `.claude/skills/conv-middleware/SKILL.md` |
| Configuration | `.claude/skills/conv-config/SKILL.md` |
| Database | `.claude/skills/conv-database/SKILL.md` |
