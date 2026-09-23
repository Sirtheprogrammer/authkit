# Stage 1: Build the static Go binary
FROM golang:alpine AS builder

WORKDIR /build

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compile statically linked binary with stripped debug info
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -extldflags '-static'" -o authkit ./cmd/authkit

# Stage 2: Final lightweight image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl bash

WORKDIR /app

COPY --from=builder /build/authkit /usr/local/bin/authkit
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Expose HTTP port
EXPOSE 8080

# Create volume for persistent SQLite database and keys
VOLUME ["/data"]

ENV DB_TYPE=sqlite \
    DB_FILE=/data/authkit.db \
    PORT=8080 \
    HOST=0.0.0.0 \
    BASE_URL=http://localhost:8080 \
    JWT_ALGORITHM=RS256

ENTRYPOINT ["authkit"]
CMD ["serve"]
