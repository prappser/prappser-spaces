# Hosting on Railway

Railway deploys are driven from the Prappser app itself, with a companion
Chrome extension handling the handoff back to the app.

## Deploy flow

1. The user clicks "Deploy on Railway" inside the Prappser app. The app opens
   Railway's deploy flow with a unique session id attached (as a URL
   fragment, `#prappser-session=<id>`).
2. Railway provisions the project and starts the service on a
   `*.railway.app` domain.
3. The user visits their new Railway URL. The
   [Prappser Server Manager extension](../../../prappser-extension/) (a
   Chrome MV3 extension, matches on `https://*.railway.app/*`) detects the
   running Prappser server on that page.
4. The extension reports the detected server URL back to its background
   script, keyed by the session id.
5. The Prappser app polls the extension for that session id and auto-fills
   the server URL once available.

The extension does not provision the Railway project itself; it automates
detecting the deployed server and handing its URL back to the app so the
user doesn't have to copy it manually. See
[`prappser-extension/README.md`](../../../prappser-extension/README.md) for
the full detection flow.

## Self-management: the Railway token endpoint

Once a space is running on Railway, its owner can let the server manage
itself (for example, for future automated redeploys) by storing a Railway API
token:

```
POST /setup/railway
```

This endpoint is owner-only (`RequireRole(..., user.RoleOwner)` in
[`internal/http.go`](../../internal/http.go)) and stores the token via
`SetupEndpoints.SetRailwayToken` in
[`internal/setup/setup.go`](../../internal/setup/setup.go). The body is:

```json
{ "token": "your-railway-api-token" }
```

## Railway environment visibility

The server surfaces the Railway-provided environment at `GET /debug/env`
(`StatusEndpoints.DebugEnv` in
[`internal/status/status.go`](../../internal/status/status.go)), including
`RAILWAY_PUBLIC_DOMAIN`, `RAILWAY_STATIC_URL`, `RAILWAY_PROJECT_ID`,
`RAILWAY_SERVICE_ID`, and `RAILWAY_ENVIRONMENT_NAME`, alongside the resolved
`EXTERNAL_URL`. This is useful for confirming Railway wired up the expected
domain.

## Required environment variables and volume

Set the same variables listed in the main
[Configuration table](../../README.md#configuration):
`DATABASE_URL`, `MASTER_PASSWORD`, `PORT`, `EXTERNAL_URL`, `ALLOWED_ORIGINS`,
`LOG_LEVEL`, `STORAGE_TYPE`, `STORAGE_PATH`. Attach a persistent volume at the
path set by `STORAGE_PATH` (`/app/storage` if left at its default), otherwise
uploaded files are lost on every redeploy.

## Updates

Railway auto-deploys on every push to the connected branch, the same as the
Zeabur template. There is no manual redeploy step for routine updates.
