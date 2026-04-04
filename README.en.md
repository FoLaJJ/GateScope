# ClawScan

[中文](README.md)

ClawScan is an independently maintained AI agent exposure discovery and vulnerability auditing project derived from `AutoScan/agentscan`, with field-oriented operational and rule-management enhancements.

This fork is no longer trying to stay a broad, generic agent-scanning platform. It has been intentionally narrowed into an `OpenClaw`-focused detection and auditing build:
- rule coverage, PoC handling, identifier mapping, title normalization, Chinese descriptions, catalog views, and exports are all centered on `OpenClaw`
- UI flows and reporting are tuned for `OpenClaw` exposure investigation rather than upstream-style generic coverage
- as a result, this fork now differs substantially from upstream in maintenance direction, catalog scale, presentation logic, and delivery workflow

Current repository:
- `https://github.com/FoLaJJ/GateScope`

Upstream repository:
- `https://github.com/AutoScan/agentscan`

License:
- `MIT`

Derivative-work notice:
- see [NOTICE](NOTICE)
- Documentation is intentionally reduced to two primary files only: `README.md` and `README.en.md`

## What Changed In This Fork

- Added `./agentscanctl` as the single operational entrypoint for install, build, start, stop, restart, status, logs, environment inspection, DB backup, DB cleanup, and DB reset.
- Removed the `./gatescopectl` alias, Docker delivery files, and the `Makefile`; the repository now keeps a single maintenance path based on `agentscanctl + local Go/Node builds`.
- Further trimmed repository leftovers by removing the unused `cmd/mock-openclaw` entry, legacy shell wrappers, stale `.gitmodules`, and obsolete screenshot assets that no longer participate in the live workflow.
- Fixed repeated SPA `301` redirects for `/index.html`.
- Added login autofill and one-click login.
- Persisted scan task events so completed tasks still show history.
- Exposed direct asset-to-vulnerability mapping in the web UI and exports.
- Preserved fuller evidence in exports.
- Externalized OpenClaw rules into YAML files for easier maintenance.
- Prioritized PoC-confirmed findings over version-only matches for the same asset/CVE.
- Added visible rule-catalog metadata in the UI.
- Removed lazy loading from the task-detail route to avoid occasional first-open crashes after a service restart or refreshed frontend asset set.
- Hardened task-detail rendering for malformed or legacy payloads such as `CVSS`, scan depth, rule issue lists, and target status values, so these no longer fall through to the global error page.
- Extended the same defensive rendering strategy to `Dashboard`, `Tasks`, `Assets`, and `Vulnerabilities`, unifying handling for `CVSS`, percentages, progress values, scan depth strings, and rule-issue arrays so stale or non-standard payloads do not crash the page.

## OpenClaw Rule Coverage

- Rule update date: `2026-04-04`
- Source cutoff: `2026-04-04`
- OpenClaw CVE rules: `238`
- Active CNNVD mappings: `160`
- Local PoC rules: `4`
- Upstream currently ships `7` built-in OpenClaw CVEs; this fork expands that to `238`, a net increase of `231`

Severity breakdown:
- `critical`: `18`
- `high`: `96`
- `medium`: `111`
- `low`: `13`

Rule files:
- `configs/rules/openclaw-cves.yaml`
- `configs/rules/openclaw-id-mappings.yaml`
- `configs/rules/pocs.yaml`
- `configs/rules/skills.yaml`

Detection policy:
- Prefer PoC-confirmed findings first
- Fall back to version-based matching second
- Only `CVE + CNNVD` are rendered as external IDs in the UI and exports
- PoC entries with `cve_id` inherit severity, CVSS, and remediation from the matching CVE rule
- Catalog sync is rate-limited and paged against `cve.org` to avoid burst scraping

## Screenshots

Login:

![ClawScan Login](docs/screenshots/login-current-headless.png)

Vulnerability Center:

![ClawScan Vulnerabilities](docs/screenshots/vulnerability-center-current.png)

Assets:

![ClawScan Assets](docs/screenshots/assets-current.png)

## Quick Start

1. Clone

```bash
git clone https://github.com/FoLaJJ/GateScope.git
cd GateScope
```

2. Prepare config

```bash
cp configs/config.yaml.example _data/config.yaml
```

3. Use the unified control script

```bash
./agentscanctl install
./agentscanctl start
./agentscanctl status
./agentscanctl logs --lines 200
./agentscanctl stop
```

Common extra actions:

```bash
./agentscanctl restart
./agentscanctl backup-db
./agentscanctl cleanup-db
./agentscanctl reset-db
./agentscanctl doctor
./agentscanctl env
```

Default login:
- username: `admin`
- password: `agentscan`

## Repository Layout

```text
.
├── agentscanctl
├── cmd/
├── configs/
│   └── rules/
├── docs/
│   └── screenshots/
├── internal/
├── scripts/
├── web/
├── _data/
├── README.md
├── README.en.md
└── AGENTS.md
```

Notes:
- `agentscanctl` is the only supported operational entrypoint.
- Docker files, compose files, and the Makefile are intentionally removed from this fork.
- The test-only `mock-openclaw` entrypoint, legacy shell wrappers, and upstream submodule placeholder config are also removed so the repository reflects only the current maintenance path.

## Compatibility Note

- Internal Go imports still use `github.com/AutoScan/agentscan`
- This is intentionally retained in the current release to reduce avoidable refactor risk while publishing ClawScan as an independent project
