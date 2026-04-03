# Prappser Space

Backend space for the Prappser platform - provides authentication, application state sync, and event processing.

## Requirements

- Go 1.21+
- PostgreSQL 14+

## Quick Start

```bash
# Set required environment variables
export DATABASE_URL="postgres://user:pass@localhost:5432/prappser?sslmode=disable"
export MASTER_PASSWORD="your-secure-password"

# Run the server
go run .
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `MASTER_PASSWORD` | Yes | - | Master password for owner registration |
| `PORT` | No | `4545` | Server port |
| `EXTERNAL_URL` | No | `http://localhost:{PORT}` | Public URL for the server |
| `ALLOWED_ORIGINS` | No | `https://prappser.app,http://localhost:*` | CORS allowed origins (comma-separated) |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |
| `JWT_EXPIRATION_HOURS` | No | `24` | JWT token expiration time |
| `HOSTING_PROVIDER` | No | - | Set to `zeabur` for automatic URL resolution |

## Development

```bash
# Run unit tests
go test ./...

# Run integration tests (requires Docker)
docker compose up -d
go test -tags=integration ./...
docker compose down

# Run with live reload (using air)
air
```

## Database

The server uses PostgreSQL and automatically runs migrations on startup. Tables are created in `files/migrations/`.

## Deployment

### Docker

```bash
docker build -t prappser-space .
docker run -e DATABASE_URL="..." -e MASTER_PASSWORD="..." -p 4545:4545 prappser-space
```

### Zeabur

Set `HOSTING_PROVIDER=zeabur` and `EXTERNAL_URL` to your subdomain (e.g., `myserver` becomes `https://myserver.zeabur.app`).

## File Storage

The server provides file upload/download capabilities for application assets (images, files, etc.).

### Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STORAGE_TYPE` | No | `local` | Storage backend: `local` or `s3` |
| `STORAGE_PATH` | No | `./storage` | Local storage path (when `STORAGE_TYPE=local`) |
| `STORAGE_MAX_FILE_SIZE_MB` | No | `50` | Maximum file size in MB |
| `STORAGE_CHUNK_SIZE_MB` | No | `5` | Chunk size for chunked uploads |

#### S3 Storage (when `STORAGE_TYPE=s3`)

| Variable | Required | Description |
|----------|----------|-------------|
| `STORAGE_S3_ENDPOINT` | No | S3 endpoint (for S3-compatible services) |
| `STORAGE_S3_BUCKET` | Yes | S3 bucket name |
| `STORAGE_S3_ACCESS_KEY` | Yes | S3 access key |
| `STORAGE_S3_SECRET_KEY` | Yes | S3 secret key |
| `STORAGE_S3_REGION` | No | S3 region |
| `STORAGE_S3_USE_SSL` | No | Use SSL for S3 connections |

### API Endpoints

All storage endpoints require JWT authentication via `Authorization: Bearer <token>` header.

- `POST /storage/upload` - Single file upload
- `POST /storage/chunks/init` - Initialize chunked upload
- `POST /storage/chunks/{storageId}/{chunkIndex}` - Upload chunk
- `POST /storage/{storageId}/complete` - Complete chunked upload
- `GET /storage/{storageId}` - Download file
- `GET /storage/{storageId}/thumb` - Get thumbnail (for images)
- `DELETE /storage/{storageId}` - Delete file
