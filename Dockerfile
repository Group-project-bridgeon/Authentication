# ============================================================
# Stage 1: builder
# ============================================================
FROM golang:1.27.1-alpine AS builder

# git is needed by some go modules at download time; ca-certificates for HTTPS.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Download dependencies first (layer-cached unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree.
COPY . .

# Build a fully static Linux binary.
# -trimpath removes local file paths from the binary.
# -ldflags "-s -w" strips debug info to reduce binary size.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/auth-service \
    ./cmd/server

# ============================================================
# Stage 2: minimal runtime image
# ============================================================
FROM alpine:3.22

# Install only what the runtime needs.
RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app app

WORKDIR /app

# Copy only the compiled binary from the builder stage.
COPY --from=builder /out/auth-service /app/auth-service

# Drop privileges — run as the non-root "app" user.
USER app

# The service listens on 8080 by default.
EXPOSE 8080

# Docker HEALTHCHECK calls /ready (PostgreSQL-aware).
# /health would pass even when the DB is down, so /ready is the correct target.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:8080/ready >/dev/null 2>&1 || exit 1

# No shell wrapper — exec form ensures signals reach the process directly.
ENTRYPOINT ["/app/auth-service"]
