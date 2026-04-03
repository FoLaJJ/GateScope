APP_NAME    := agentscan
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)
GO          := CGO_ENABLED=1 go
GOFLAGS     := -trimpath

BIN_DIR     := bin
WEB_DIR     := web

.PHONY: all build build-go build-web dev dev-go dev-web test lint clean help

all: build

# ── Build ──────────────────────────────────────────────────────────────

build: build-web build-go ## Build frontend + backend (single binary)

build-go: ## Build Go binary only (expects web/dist to exist)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(APP_NAME) ./cmd/agentscan

build-web: ## Build frontend
	cd $(WEB_DIR) && npm ci && npm run build

# ── Development ────────────────────────────────────────────────────────

dev: ## Run backend in dev mode (hot-reload with air if installed, else go run)
	@which air > /dev/null 2>&1 && air || $(GO) run ./cmd/agentscan server

dev-web: ## Run frontend dev server (Vite HMR)
	cd $(WEB_DIR) && npm run dev

dev-all: ## Run backend + frontend in parallel
	@make dev & make dev-web & wait

mock: ## Run mock OpenClaw server on :18789
	$(GO) run ./cmd/mock-openclaw

# ── Quality ────────────────────────────────────────────────────────────

test: ## Run all Go tests
	$(GO) test ./...

lint: ## Run go vet
	$(GO) vet ./...

# ── Docker ─────────────────────────────────────────────────────────────

docker: ## Build Docker image
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

docker-up: ## Start via docker-compose
	docker compose up -d

docker-down: ## Stop docker-compose
	docker compose down

# ── Misc ───────────────────────────────────────────────────────────────

migrate: ## Run database migrations
	$(GO) run ./cmd/agentscan migrate

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)/ $(WEB_DIR)/dist/ $(WEB_DIR)/node_modules/

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
