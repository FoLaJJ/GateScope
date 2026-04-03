# ── Multi-stage build (for local `docker build`) ──────────────────────
# Stage 1: Build frontend
FROM node:22-alpine AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.23-alpine AS backend
RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend /src/web/dist ./web/dist

ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /agentscan ./cmd/agentscan

# Stage 3: Runtime
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S agentscan && adduser -S agentscan -G agentscan

COPY --from=backend /agentscan /usr/local/bin/agentscan
COPY configs/config.yaml.example /etc/agentscan/config.yaml

RUN mkdir -p /data && chown agentscan:agentscan /data
VOLUME ["/data"]

USER agentscan
WORKDIR /data

ENV AGENTSCAN_DATABASE_DSN=/data/agentscan.db \
    AGENTSCAN_LOG_FORMAT=json

EXPOSE 8080

ENTRYPOINT ["agentscan"]
CMD ["server"]
