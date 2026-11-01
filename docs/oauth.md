# OAuth for MCP agents

The space is an OAuth 2.1 authorization server. Claude Code, claude.ai and ChatGPT use it to get agent tokens. Everything here returns 404 unless `MCP_ENABLED=true`.

Clients identify themselves with a client ID metadata document: `client_id` is an https URL, and the space fetches the JSON there. There is no dynamic registration. PKCE with S256 is required. Codes live 60 seconds and work once. A code is burned on first use even when the exchange fails. The one exception is a server error while issuing tokens, which leaves the code usable for a retry within its 60 seconds. If a retry lands while the first exchange is still issuing tokens, it counts as reuse and kills the code, and the user restarts authorization. Tokens are the agent tokens from `AgentService`: access tokens last 1 hour, refresh tokens rotate.

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| GET | `/oauth/authorize` | Validates the request, then redirects the browser to the consent screen. Errors are a plain-text 400, never a redirect to the client |
| POST | `/oauth/token` | Form encoded. `authorization_code` and `refresh_token` grants. Errors are `{error, error_description}` with status 400 |
| GET | `/oauth/requests/{id}` | Consent info. Needs a human JWT |
| POST | `/oauth/requests/{id}/approve` | Needs a human JWT |
| POST | `/oauth/requests/{id}/deny` | Needs a human JWT |

`resource` is optional. When sent it must equal `{EXTERNAL_URL}/mcp`. The granted scope is always `mcp`.

## Consent handoff

`/oauth/authorize` redirects to:

    {APP_URL}/#/oauth/consent?space={url-encoded space URL}&request={id}

The app then calls the consent API on that space with the user's JWT. Agent tokens are rejected.

`GET /oauth/requests/{id}` returns:

    {clientId, clientHost, clientName, clientUri?, logoUri?, redirectHost, redirectLoopback, scope, expiresAt}

`expiresAt` is unix seconds. `/oauth/authorize` is anonymous, so a request is not tied to whoever started it. The first authenticated account that reads it with this call is bound to it. The app's account picker runs before that call.

`approve` and `deny` return `{"redirectUri": "..."}`. The app navigates the browser to it. It carries `code` (or `error=access_denied`), `state` when the client sent one, and `iss`.

Errors: 401 missing or invalid JWT, or an agent token. 403 `wrong_user` when another account owns the request. 410 `request_expired` for unknown, expired or already decided requests. 409 `agent_limit` on approve when the account already has 5 agents.

## Consent screen requirement

The screen must show `clientHost` and `redirectHost` prominently. `clientName` is chosen by the client and can lie. When `redirectLoopback` is true, the agent runs on this computer, and the screen should say so. Consent phishing is the main risk of this flow.

## Notes

Pending requests and codes are in memory. This works for one instance. A restart drops in-flight flows and the user retries.

Self-hosting: set `APP_URL` to your web app and add it to `ALLOWED_ORIGINS`.
