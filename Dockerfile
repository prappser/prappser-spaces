# Build stage - use pre-built deps image for faster builds
FROM ghcr.io/prappser/prappser-space-deps:latest AS builder

WORKDIR /build

# Copy dependency files (for verification/update if needed)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o prappser-space .

# Runtime stage - minimal Alpine image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy application binary
COPY --from=builder /build/prappser-space .

# Copy migrations
COPY files/migrations ./files/migrations

EXPOSE 4545

CMD ["./prappser-space"]
