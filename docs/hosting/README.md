# Hosting Prappser Spaces

Prappser Spaces can be hosted three ways. Pick whichever fits how much
infrastructure you want to manage yourself.

| | [Zeabur](zeabur.md) | [Railway](railway.md) | [Self-host](selfhost.md) |
|---|---|---|---|
| Setup | One-click template | Chrome extension + deploy button | Manual, `docker compose up` |
| Updates | Rebuild on push to `main` | Railway auto-deploy on push | watchtower polls GHCR |
| TLS | Managed by Zeabur | Managed by Railway | Caddy + Let's Encrypt, self-managed |
| Storage persistence | Volume provisioned by template | Volume provisioned by Railway | Named Docker volume on your host |
| Where it runs | Zeabur's infrastructure | Railway's infrastructure | Your own server |

## Common requirements

Regardless of hosting method, the server needs:

- **`DATABASE_URL`**: PostgreSQL 16 connection string
- **`MASTER_PASSWORD`**: used to encrypt the space's Ed25519 keypair, required with no default
- **`EXTERNAL_URL`**: the public URL clients use to reach the server
- **`ALLOWED_ORIGINS`**: comma-separated list of CORS origins allowed to call the API
- A persistent volume mounted at the path set by `STORAGE_PATH` (default `/app/storage`), so uploaded files survive container restarts
- A PostgreSQL 16 instance (bundled in the Zeabur/Railway templates and in the self-host compose stack)

The server exposes plain HTTP endpoints under the root path (for example
`/users/*`, `/applications/*`, `/events`, `/storage/*`, `/spaces/*`, `/push/*`,
`/health`, `/status`) plus a WebSocket at `wss://{domain}/ws`. There is no
`/api` path prefix on the current server.

See the full variable table in the [main README](../../README.md#configuration).

## Choosing a method

- **Zeabur**: fastest way to get a managed instance running, good default for most users. See [zeabur.md](zeabur.md).
- **Railway**: deploy from the Prappser app itself via the companion Chrome extension. See [railway.md](railway.md).
- **Self-host**: full control over the server, own domain, own updates. See [selfhost.md](selfhost.md). If your domain is on Cloudflare, selfhost.md also covers running behind Cloudflare Tunnel with no open inbound ports.
