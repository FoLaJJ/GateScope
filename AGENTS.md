# AgentScan Repository Guidelines

- File references must be repo-root relative (example: `internal/api/handlers.go:42`); never absolute paths.
- When answering questions, verify claims in source code; do not guess or hallucinate.

## Project Overview

AgentScan is an AI Agent network asset discovery and security audit platform targeting exposed OpenClaw, clawhive, GoGogot, Hermes Agent, and Pincer instances. The system performs layered scanning (L1 port scan → L2 fingerprint → L3 vulnerability check) with a React dashboard frontend.

## Project Structure & Module Organization

```
AgentScan/
├── cmd/agentscan/              # CLI entry (Cobra: server/scan/migrate/version)
├── cmd/mock-openclaw/          # Mock OpenClaw server for testing
├── configs/                    # Config template (config.yaml.example)
├── _data/                      # Runtime data (db + config overrides, gitignored)
├── docs/                       # Design docs (gitignored, local only)
├── internal/                   # All Go business logic
│   ├── core/                   # Infrastructure (zero business deps)
│   │   ├── config/             # Viper config + env vars (AGENTSCAN_*) + validation
│   │   ├── eventbus/           # Async event bus (goroutine pool + panic recovery)
│   │   └── logger/             # zap structured logging (console/json + file)
│   ├── utils/                  # Pure utility functions (stateless)
│   │   ├── iputil/             # IP/CIDR/Range parsing + file import
│   │   └── version/            # Semantic version comparison
│   ├── api/                    # Gin REST API + WebSocket + middleware
│   ├── alert/                  # Alert engine (rule matching + Webhook)
│   ├── auth/                   # JWT auth + bcrypt password hashing
│   ├── engine/                 # L1→L2→L3 scan pipeline orchestration
│   ├── geoip/                  # GeoIP + ASN region scanning
│   ├── intel/                  # Threat intel (FOFA client)
│   ├── models/                 # GORM data models + JSONMap
│   ├── report/                 # Excel report generation (4 sheets)
│   ├── scanner/                # Scanner implementations
│   │   ├── l1/                 # TCP CONNECT port scanner
│   │   ├── l2/                 # HTTP/WS/mDNS fingerprinting probes
│   │   └── l3/                 # CVE matching + auth check + Skills enum + PoC
│   ├── store/                  # GORM persistence (SQLite/PostgreSQL + versioned migration)
│   └── task/                   # Task manager + Cron scheduler
├── web/                        # Frontend (React + Ant Design + ECharts)
├── third_party/openclaw-src/   # OpenClaw source (git submodule, reference only)
└── scripts/                    # Utility scripts
```

### Key Architecture Patterns

- **Dependency direction**: `core/` → `utils/` → `models/` → `store/` → business packages → `api/` → `cmd/`. Never import backwards.
- **Event-driven**: `internal/core/eventbus` decouples scan events from handlers. Topics defined in `eventbus/topics.go`.
- **Pipeline pattern**: `internal/engine/pipeline.go` orchestrates L1→L2→L3 with progress callbacks.
- **Store interface**: `internal/store/store.go` defines the `Store` interface; `gorm.go` implements it.
- **Versioned migrations**: `internal/store/migrator.go` — migrations are Go code (not SQL files). Append new migrations to `var migrations` slice; never reorder or modify existing ones.

## Tech Stack

- **Backend**: Go 1.23+ (Gin, GORM, Cobra, Viper, zap, cron/v3)
- **Frontend**: React + TypeScript + Ant Design + ECharts + Zustand
- **Database**: SQLite (dev) / PostgreSQL (prod)
- **Build**: `go build` (backend), Vite (frontend)

## Build, Test, and Development Commands

### Backend (Go)

- Build all: `go build ./...`
- Run tests: `go test ./...`
- Static analysis: `go vet ./...`
- Tidy deps: `go mod tidy`
- Start server: `go run cmd/agentscan/main.go server`
- Quick scan: `go run cmd/agentscan/main.go scan --targets 192.168.1.0/24`
- Run migrations: `go run cmd/agentscan/main.go migrate`
- Mock OpenClaw: `go run cmd/mock-openclaw/main.go` (listens on :18789)
- CGO is required for SQLite (`mattn/go-sqlite3`).

### Frontend (React)

- Install deps: `cd web && npm install`
- Dev server: `cd web && npm run dev`
- Build: `cd web && npm run build`
- Output goes to `web/dist/` (gitignored).

### Full-stack dev

1. Start mock: `go run cmd/mock-openclaw/main.go`
2. Start backend: `go run cmd/agentscan/main.go server`
3. Start frontend: `cd web && npm run dev`
4. Login: `admin` / `agentscan` (default credentials)

## Configuration

- Config template: `configs/config.yaml.example` — copy to `_data/config.yaml` for local use.
- Viper search order: `./config.yaml` → `./configs/` → `./_data/` → `/etc/agentscan/`
- Environment override prefix: `AGENTSCAN_` (e.g. `AGENTSCAN_SERVER_PORT=9090`)
- Default database DSN: `_data/agentscan.db` (SQLite)
- Production validation: `auth.jwt_secret` must be changed from default when using PostgreSQL driver.

## Coding Style & Conventions

- **Language**: Go (backend), TypeScript (frontend). Use Chinese comments when the codebase already does (project is bilingual).
- Go files should target ~500 LOC max; split when it improves clarity.
- Use `internal/core/logger` (zap) for all logging; never use `fmt.Println` or `log.Println`.
- Use `internal/core/config` for all configuration; never hardcode values.
- Use `internal/core/eventbus` for async cross-module communication; never import business packages into `core/`.
- Error handling: always wrap errors with context using `fmt.Errorf("context: %w", err)`.
- Models: all GORM models live in `internal/models/`. Use `JSONMap` type for flexible JSON fields.
- API handlers: follow the pattern in `internal/api/handlers.go` — input validation → service call → response.
- API errors: use `internal/api/errors.go` helpers for consistent JSON error responses.

### Frontend Conventions

- State management: Zustand stores in `web/src/stores/`.
- API client: `web/src/api/client.ts` — all backend calls go through this.
- Type definitions: `web/src/types/models.ts` (backend mirror) + `web/src/types/index.ts`.
- Components: Ant Design Pro components; custom components in `web/src/components/`.

## Testing Guidelines

- Colocate test files: `*_test.go` next to source.
- Use `github.com/stretchr/testify` for assertions.
- Store tests use `t.TempDir()` for ephemeral SQLite databases.
- Pipeline tests use mock scanners (see `internal/engine/pipeline_test.go`).
- Run `go build ./...` and `go vet ./...` before pushing; both must pass cleanly.
- Packages with tests: `api`, `eventbus`, `engine`, `scanner/l3`, `store`, `iputil`, `version`.

## Commit & PR Guidelines

- Use concise, action-oriented commit messages: `module: action description` (e.g. `api: add pagination to asset list`).
- Group related changes; avoid bundling unrelated refactors.
- Run `go build ./...` and `go test ./...` before committing.
- Never commit `_data/`, `agentscan.db`, `.env` files, or secrets.
- Never commit `node_modules/`, `web/dist/`, or build artifacts.

## Security Notes

- `configs/config.yaml.example` contains dev-only default credentials; these must be changed in production.
- `auth.jwt_secret` validation enforces non-default in postgres mode.
- Never commit real API keys (FOFA, GeoIP license keys).
- The mock OpenClaw server (`cmd/mock-openclaw/`) is for testing only; it simulates vulnerabilities.

## Scanner Architecture

The scan pipeline has three layers:

1. **L1 (Port Scan)**: `internal/scanner/l1/tcp.go` — TCP CONNECT scan with configurable concurrency/rate-limit.
2. **L2 (Fingerprint)**: `internal/scanner/l2/` — HTTP health/config/MCP probes, WebSocket handshake, mDNS discovery.
3. **L3 (Vulnerability)**: `internal/scanner/l3/` — CVE matching (7 CVEs), auth bypass check, Skills enumeration, PoC verification.

Pipeline orchestration lives in `internal/engine/pipeline.go`. It emits events via `eventbus` for real-time progress tracking.

## Database & Migrations

- GORM is the ORM. Both SQLite and PostgreSQL are supported.
- Migrations are code-based in `internal/store/migrator.go` (not external SQL files).
- To add a new migration: append a new `Migration{}` entry to the `migrations` slice with an incremented version string. Never modify existing migrations.
- Connection pool defaults: 25 max open, 5 max idle, 5m max lifetime.

## Git Submodules

- `third_party/openclaw-src` — OpenClaw source code for reference and feature analysis. Read-only; do not modify.

## How to Add New Components

### Adding a new scanner probe (L2)

1. Create `internal/scanner/l2/new_probe.go`
2. Implement probe function matching the pattern in `http.go` / `websocket.go`
3. Wire it into `internal/engine/pipeline.go` L2 stage
4. Add corresponding `AgentType` constant in `internal/models/asset.go` if needed

### Adding a new CVE rule (L3)

1. Add CVE struct to `internal/scanner/l3/cve.go` `cveRules` slice
2. Implement checker function following existing pattern
3. Add test case in `cve_test.go`

### Adding a new API endpoint

1. Add handler in `internal/api/handlers.go`
2. Register route in `internal/api/server.go` route group
3. Add input validation using Gin binding tags
4. Use `internal/api/errors.go` helpers for error responses
5. If new Store method needed, add to `Store` interface first, then implement in `gorm.go`

### Adding a new migration

1. Open `internal/store/migrator.go`
2. Append a new `Migration{}` to `var migrations` with next version (e.g. "003")
3. Never modify or reorder existing migrations
4. Test with `go run cmd/agentscan/main.go migrate`

### Adding a new EventBus implementation (P2+)

1. Create `internal/core/eventbus/redis.go`
2. Implement `EventBus` interface (Publish + Subscribe)
3. Use `MarshalPayload`/`UnmarshalPayload` for serialization (already provided)
4. Wire via config flag in `cmd/agentscan/main.go` server startup

## Frontend Architecture

### State Management

- **Auth state**: Zustand store (`web/src/store/auth.ts`) — JWT token + user info
- **Server data**: TanStack Query v5 — all API data uses query hooks with cache invalidation
- **WebSocket → Query bridge**: `useWSInvalidation` hook invalidates relevant query caches on WS events

### Routing

- React Router v6 with `React.lazy` code splitting per page
- Protected routes check auth token; redirect to `/login` if missing
- Layout component (`web/src/components/Layout.tsx`) wraps all authenticated pages

### Adding a new frontend page

1. Create page component in `web/src/pages/NewPage.tsx`
2. Add lazy route in `web/src/App.tsx`
3. Add API functions in `web/src/api/` (follow existing patterns like `tasks.ts`)
4. Add types in `web/src/types/models.ts` mirroring backend models
5. Use Ant Design components; follow existing color/tag constants in `web/src/constants/`

## Troubleshooting

- SQLite lock errors: ensure only one server instance runs at a time.
- CGO build failures: install C compiler (`xcode-select --install` on macOS).
- Frontend API 404: ensure backend server is running and API base URL matches.
- WebSocket disconnects: check JWT token expiry (default 24h TTL).
- Migration failures: check `schema_migrations` table for partial state; fix and re-run.
- Event delivery issues: check `eventbus` worker pool logs; panics are recovered but logged.
