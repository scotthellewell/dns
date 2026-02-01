# Build stage for Angular web UI
FROM node:22-alpine AS web-builder

WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Build stage for Go binary
FROM golang:1.24-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download || go mod download || go mod download

# Copy source code
COPY . .

# Build the binary for the target architecture
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o dns-server .

# Final stage - minimal runtime image
FROM alpine:3.21

# Install ca-certificates for HTTPS and tzdata for timezones
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 dnsuser

# Create directories for data and web UI
RUN mkdir -p /app/data /app/web/dist/dns-admin/browser && \
    chown -R dnsuser:dnsuser /app

WORKDIR /app

# Copy the binary from go-builder
COPY --from=go-builder /app/dns-server /app/dns-server

# Copy the web UI from web-builder
COPY --from=web-builder /app/web/dist/dns-admin/browser /app/web/dist/dns-admin/browser

# Set ownership
RUN chown -R dnsuser:dnsuser /app

# Expose ports
# DNS ports
EXPOSE 53/udp
EXPOSE 53/tcp
# DNS over TLS
EXPOSE 853/tcp
# Web UI / API (HTTPS)
EXPOSE 443/tcp
# HTTP (for ACME/redirects)
EXPOSE 80/tcp

# Volume mount for persistent data (bbolt database)
VOLUME ["/app/data"]

# Run as non-root user (commented out - DNS needs port 53)
# USER dnsuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider --no-check-certificate https://localhost:443/api/health || exit 1

# Default command
ENTRYPOINT ["/app/dns-server"]
CMD ["-data", "/app/data"]
