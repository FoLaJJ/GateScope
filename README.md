# GateScope

[中文文档](README.zh-CN.md)

**Independent AI Agent Exposure Discovery & Security Audit Platform**

> Detect, fingerprint, and assess exposed AI Agent instances across your network — from LAN to the public internet.

---

## Why GateScope?

In early 2026, platforms like OpenClaw, clawhive, GoGogot, Hermes Agent, and Pincer exploded in popularity. Non-technical users deployed AI agents on personal machines with high privileges and default configs, creating a massive attack surface:

- **42,000+** OpenClaw instances exposed on the public internet, 93% with auth bypass
- **Default bind `0.0.0.0:18789`**, 85% directly reachable from the internet
- **341+ malicious skill packages** poisoning the official marketplace
- **1.5M API tokens leaked**, 35K user emails exposed
- Government agencies in China issued formal security advisories; banks and state enterprises banned usage

GateScope provides organizations with end-to-end AI Agent exposure discovery, vulnerability detection, and compliance auditing.

## Features

- **Layered Scanning** — L1 port discovery → L2 fingerprinting → L3 vulnerability verification
- **Multi-Agent Support** — OpenClaw (all versions) + clawhive + GoGogot + Hermes + Pincer
- **CVE Detection** — OpenClaw CVE rule set + auth bypass checks + Skills enumeration + PoC validation
- **Real-time Dashboard** — React + ECharts with WebSocket live updates
- **Task Management** — One-time, scheduled (cron), and recurring scan tasks
- **Alert Engine** — Configurable rules with Webhook notification + DB-persisted history
- **Excel Reports** — 4-sheet export (summary, assets, vulnerabilities, remediation)
- **Threat Intelligence** — FOFA integration for internet-scale discovery
- **GeoIP Ready** — MaxMind GeoLite2 interface for region-based scanning

## Fork Change Notice

This fork keeps the upstream project structure and primary workflows intact. The changes below are additive customizations made for field use and operator convenience rather than a redesign of the original project.

### Fork-specific additions in this branch

- Added a unified `./agentscanctl` control entrypoint for install, build, start, stop, restart, status, logs, environment inspection, DB backup, DB cleanup, and DB reset.
- Added `./gatescopectl` as a branding-friendly wrapper while keeping `agentscanctl` for compatibility.
- Added forwarding wrapper scripts under `scripts/` so existing habits remain usable while `agentscanctl` becomes the primary control surface.
- Fixed SPA asset routing behavior that previously caused repeated `301` redirects for `/index.html`.
- Added login autofill behavior in the web UI so the configured default credentials can be submitted with a single click.
- Added task event persistence and replay, so completed tasks can still show historical events instead of only live WebSocket messages.
- Enhanced task and vulnerability pages to show direct asset context on the web UI, including IP, port, agent type, asset version, auth mode, and expandable evidence details.
- Enhanced Excel export so vulnerability rows include direct asset attribution and no longer rely on report-only context to identify the affected host.
- Preserved full evidence strings for new detections and report exports instead of truncating evidence at scan time.
- Externalized OpenClaw detection data into YAML rule files under `configs/rules/` for easier maintenance.
- Added rule catalog metadata, including rule update date, upstream verification cutoff, rule counts, and consistency checks.
- Added PoC/CVE normalization logic so PoC entries with `cve_id` inherit severity, CVSS, and remediation from the matching CVE rule to reduce drift.
- Adjusted duplicate handling so PoC-confirmed findings take priority over version-only matches for the same asset and CVE.

### Current OpenClaw rule coverage in this fork

- Rule catalog metadata is exposed in the UI and API.
- Current rule metadata in this branch:
  - Rule update date: `2026-04-03`
  - Upstream verification cutoff: `2026-04-02`
  - OpenClaw CVE rules: `36`
  - PoC rules: `4`
- Version-match evidence uses `local_poc_rule=available` to indicate that a local PoC rule exists for the CVE. It does not claim that an independently verified public exploit is universally available.

### Documentation scope

- This README now documents fork-specific operational changes and detection-rule behavior.
- Upstream architecture, original module layout, and general build flow are intentionally left in place.

## Quick Start

### Prerequisites

- Go 1.23+ (with CGO enabled for SQLite)
- Node.js 18+ (for frontend)

### 1. Clone

```bash
git clone <your-repository-url> GateScope
cd GateScope
```

### 2. Configure

```bash
cp configs/config.yaml.example _data/config.yaml
# Edit _data/config.yaml as needed
```

### 3. Run Backend

```bash
go run cmd/agentscan/main.go server
```

### 4. Run Frontend (development)

```bash
cd web && npm install && npm run dev
```

### 5. Login

Open `http://localhost:5173` and sign in with:
- Username: `admin`
- Password: `agentscan`

### One-command runtime control

For packaged or long-running usage, prefer the unified control script:

```bash
./gatescopectl install
./gatescopectl start
./gatescopectl status
./gatescopectl logs --lines 200
./gatescopectl stop
```

Main supported actions include:

- `install`
- `build`
- `start`
- `stop`
- `restart`
- `status`
- `logs`
- `env`
- `doctor`
- `backup-db`
- `cleanup-db`
- `reset-db`

### Quick Start with Docker

```bash
docker run -d --name agentscan -p 8080:8080 \
  -v agentscan-data:/data \
  -e AGENTSCAN_AUTH_JWT_SECRET=my-secret \
  ghcr.io/autoscan/agentscan:latest
```

Or use Docker Compose:

```bash
curl -O <your-published-repository>/docker-compose.yml
docker compose up -d
```

Open `http://localhost:8080`.

### Run a Scan (CLI)

```bash
go run cmd/agentscan/main.go scan --targets 192.168.1.0/24
```

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────┐
│  React SPA  │────▶│  Gin REST API + WebSocket                │
│  Ant Design │◀────│  JWT Auth · CORS · RequestID · AccessLog │
│  ECharts    │     └──────────┬───────────────────────────────┘
└─────────────┘                │
                    ┌──────────▼───────────────┐
                    │    Scan Pipeline Engine   │
                    │  L1 Port → L2 FP → L3 Vuln│
                    └──────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌───────────┐   ┌──────────────┐
        │  EventBus │   │   Store   │   │  Alert Engine│
        │ (pub/sub) │   │(GORM/SQL) │   │  (Webhook)   │
        └──────────┘   └───────────┘   └──────────────┘
```

### Scan Layers

| Layer | Purpose | Implementation |
|-------|---------|----------------|
| **L1** | Port discovery | TCP CONNECT scan, configurable concurrency |
| **L2** | Fingerprinting | HTTP/WebSocket/mDNS probes, agent type identification |
| **L3** | Vulnerability check | CVE matching, auth bypass, Skills enum, PoC |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Go 1.23 · Gin · GORM · Cobra · Viper · zap |
| Frontend | React 18 · TypeScript · Ant Design · ECharts · Zustand · TanStack Query |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Build | `go build` (backend) · Vite (frontend) |

## Project Structure

```
GateScope/
├── cmd/agentscan/          # CLI entry (server/scan/migrate/version)
├── cmd/mock-openclaw/      # Mock target server for testing
├── configs/                # Config template (config.yaml.example)
├── _data/                  # Runtime data — db & config (gitignored)
├── internal/
│   ├── core/               # Infrastructure (config, eventbus, logger)
│   ├── utils/              # Pure utilities (iputil, version)
│   ├── models/             # GORM data models
│   ├── store/              # Persistence layer (SQLite/PostgreSQL)
│   ├── scanner/l1/         # TCP port scanner
│   ├── scanner/l2/         # HTTP/WS/mDNS fingerprinting
│   ├── scanner/l3/         # CVE/Auth/Skills/PoC checks
│   ├── engine/             # L1→L2→L3 pipeline orchestration
│   ├── api/                # REST API + WebSocket
│   ├── auth/               # JWT authentication
│   ├── task/               # Task manager + cron scheduler
│   ├── alert/              # Alert engine
│   ├── report/             # Excel report generator
│   ├── intel/              # FOFA threat intelligence
│   └── geoip/              # GeoIP service
├── web/                    # React frontend
├── AGENTS.md               # AI coding assistant guidelines
└── scripts/                # Utility scripts
```

## Configuration

GateScope uses [Viper](https://github.com/spf13/viper) for configuration with the following priority:

1. CLI flags (`--config path/to/config.yaml`)
2. Environment variables (`AGENTSCAN_SERVER_PORT=9090`)
3. Config file (searched in `./`, `./configs/`, `./_data/`, `/etc/agentscan/`)
4. Built-in defaults

See `configs/config.yaml.example` for all available options.

## Rule Data

OpenClaw rule data in this fork is primarily maintained as YAML and loaded at runtime:

- `configs/rules/openclaw-cves.yaml`
- `configs/rules/pocs.yaml`
- `configs/rules/skills.yaml`

Operational notes:

- CVE matching is version-based when a target version is available.
- PoC validation is handled separately and can override version-only findings for the same asset/CVE pair.
- Rule metadata is surfaced via the API and UI so operators can see the effective update date and verification cutoff.

## Development

```bash
make build        # Build frontend + backend (single binary → bin/agentscan)
make dev          # Run backend (go run or air)
make dev-web      # Run frontend Vite dev server
make dev-all      # Run both in parallel
make test         # go test ./...
make lint         # go vet ./...
make docker       # Build Docker image locally
make help         # Show all targets
```

### Docker

```bash
# Build locally
make docker

# Run with docker-compose
docker compose up -d

# Stop
docker compose down
```

The Docker image is a multi-stage build producing a ~30 MB Alpine image with the frontend embedded.
Data is stored in the `/data` volume. Configure via environment variables (`AGENTSCAN_*`).

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **P1** | L1/L2/L3 scan pipeline, REST API, React dashboard, JWT auth, task management, alerts, Excel reports | Done |
| **P2** | SYN scan, concurrent L2, YAML fingerprint/CVE databases, RBAC, rate limiting, Prometheus metrics, health checks | Planned |
| **P3** | Redis EventBus, ClickHouse time-series, PDF/Word reports, Swagger/OpenAPI | Planned |
| **P4** | Distributed workers (gRPC), multi-tenancy, SSO (LDAP/OAuth2), asset groups, compliance templates, i18n | Future |

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run `go build ./...` and `go test ./...` before committing
4. Use descriptive commit messages (`module: action description`)
5. Open a Pull Request

## License

[MIT](LICENSE)

## Clean Packaging Note

When exporting this fork for delivery or local archival, exclude runtime and dependency artifacts such as:

- `.git/`
- `_data/`
- `bin/`
- `web/node_modules/`
- `web/dist/`
- `*.bak.*`
- `*.backup`

This keeps the release package focused on source, configuration templates, scripts, and documentation only.

## Independent Project Note

This repository is intended to be published and maintained as an independent project rather than an upstream merge branch.

- Public-facing project name: `GateScope`
- Upstream base: `AutoScan/agentscan`
- License basis: `MIT`
- Upstream attribution and derivative-work notes: see [NOTICE](NOTICE)

Compatibility note:

- Internal Go module imports may still reference `github.com/AutoScan/agentscan`.
- This is intentional in the current release to reduce unnecessary refactor risk while keeping the project independently publishable.
