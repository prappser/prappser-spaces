# Prappser Spaces

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Backend service for the Prappser platform. A space is a self-hosted server that Prappser apps connect to for sync and authentication.

## What is a Space?

A space manages everything needed to run one or more Prappser applications:

- **Auth** - Ed25519 challenge-response authentication, JWT sessions, invite-based membership
- **Applications** - multi-tenant app hosting with owner/member roles
- **Event sync** - client-produced events validated, sequenced, persisted, and executed server-side
- **Real-time** - WebSocket hub that pushes state changes to all connected clients instantly
- **File storage** - chunked upload/download with local or S3-compatible backends

## Requirements

- Go 1.24+
- Docker (for local PostgreSQL)

## Quick Start

```bash
# Start PostgreSQL
docker compose up -d

# Set required environment variables
export DATABASE_URL="postgres://test:test@localhost:5433/prappser_test?sslmode=disable"
export MASTER_PASSWORD="your-secure-password"

# Run the server
go run .
```

The server starts on port `4545` by default and runs database migrations automatically on startup.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `MASTER_PASSWORD` | Yes | - | Used to encrypt the space's Ed25519 keypair |
| `PORT` | No | `4545` | HTTP listen port |
| `EXTERNAL_URL` | No | `http://localhost:4545` | Public URL (used in invite links); overrides PORT |
| `HOSTING_PROVIDER` | No | - | Set to `zeabur` for automatic URL resolution |
| `ALLOWED_ORIGINS` | No | `https://prappser.app,http://localhost:*,https://localhost:*` | CORS origins (comma-separated) |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, or `error` |
| `JWT_EXPIRATION_HOURS` | No | `24` | JWT token lifetime in hours |
| `STORAGE_TYPE` | No | `local` | `local` or `s3` |
| `STORAGE_PATH` | No | `./storage` | Local storage path (when `STORAGE_TYPE=local`) |
| `STORAGE_MAX_FILE_SIZE_MB` | No | `50` | Maximum file size in MB |
| `STORAGE_CHUNK_SIZE_MB` | No | `5` | Chunk size for chunked uploads |

For S3 storage variables (`STORAGE_S3_*`), see [`.env.example`](.env.example).

## Development

```bash
# Unit tests
go test ./...

# Integration tests
docker compose up -d
go test -tags=integration ./...
docker compose down
```

## Deployment

### Docker

```bash
docker build -t prappser-spaces .
docker run \
  -e DATABASE_URL="postgres://user:pass@host:5432/prappser?sslmode=disable" \
  -e MASTER_PASSWORD="your-secure-password" \
  -p 4545:4545 \
  prappser-spaces
```

### Zeabur

Set `HOSTING_PROVIDER=zeabur` and `EXTERNAL_URL` to your subdomain name. For example, `myserver` resolves to `https://myserver.zeabur.app`.

## License

Prappser Spaces is licensed under the [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0).
