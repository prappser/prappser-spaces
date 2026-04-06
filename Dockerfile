# Build stage - use pre-built deps image for faster builds
FROM ghcr.io/prappser/prappser-spaces-deps:latest AS builder

WORKDIR /build

# Copy dependency files (for verification/update if needed)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o prappser-spaces .

# Runtime stage - minimal Alpine image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy application binary
COPY --from=builder /build/prappser-spaces .

# Copy migrations
COPY files/migrations ./files/migrations

EXPOSE 4545

CMD ["./prappser-spaces"]
