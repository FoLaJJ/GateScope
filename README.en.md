# GateScope

[中文](README.md)

GateScope is an independently maintained AI agent exposure discovery and vulnerability auditing project derived from `AutoScan/agentscan`, with field-oriented operational and rule-management enhancements.

Current repository:
- `https://github.com/FoLaJJ/GateScope`

Upstream repository:
- `https://github.com/AutoScan/agentscan`

License:
- `MIT`

Derivative-work notice:
- see [NOTICE](NOTICE)

## What Changed In This Fork

- Added `./agentscanctl` as the single operational entrypoint for install, build, start, stop, restart, status, logs, environment inspection, DB backup, DB cleanup, and DB reset.
- Kept `./gatescopectl` as a public-facing alias, but `agentscanctl` is the primary documented entrypoint.
- Fixed repeated SPA `301` redirects for `/index.html`.
- Added login autofill and one-click login.
- Persisted scan task events so completed tasks still show history.
- Exposed direct asset-to-vulnerability mapping in the web UI and exports.
- Preserved fuller evidence in exports.
- Externalized OpenClaw rules into YAML files for easier maintenance.
- Prioritized PoC-confirmed findings over version-only matches for the same asset/CVE.
- Added visible rule-catalog metadata in the UI.

## OpenClaw Rule Coverage

- Rule update date: `2026-04-03`
- Source cutoff: `2026-04-02`
- OpenClaw CVE rules: `36`
- Local PoC rules: `4`
- Upstream currently ships `7` built-in OpenClaw CVEs; this fork expands that to `36`, a net increase of `29`

Severity breakdown:
- `critical`: `8`
- `high`: `18`
- `medium`: `9`
- `low`: `1`

Rule files:
- `configs/rules/openclaw-cves.yaml`
- `configs/rules/pocs.yaml`
- `configs/rules/skills.yaml`

Detection policy:
- Prefer PoC-confirmed findings first
- Fall back to version-based matching second
- PoC entries with `cve_id` inherit severity, CVSS, and remediation from the matching CVE rule

## Screenshots

Login:

![GateScope Login](docs/screenshots/login.png)

Tasks:

![GateScope Tasks](docs/screenshots/tasks.png)

Vulnerabilities:

![GateScope Vulnerabilities](docs/screenshots/vulnerabilities.png)

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

Alias:

```bash
./gatescopectl start
```

Default login:
- username: `admin`
- password: `agentscan`

## Compatibility Note

- Internal Go imports still use `github.com/AutoScan/agentscan`
- This is intentionally retained in the current release to reduce avoidable refactor risk while publishing GateScope as an independent project
