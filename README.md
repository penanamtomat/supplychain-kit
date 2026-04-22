# supplychain-kit

> An open-source CLI tool for Application Security Posture Management (ASPM) — unifies SCA, SAST, secret scanning, reachability analysis, and AI-driven remediation into a single, risk-aware control plane. Runs locally or in CI pipelines with no external services required.

`supplychain-kit` is the reference implementation of the ASPM platform described in [docs/Product Requirements Document (PRD)_ Integrated Application Security Posture Management (ASPM) Platform.md](docs/Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md). It moves security teams from siloed scanning to a cohesive, prioritized risk model that scales with AI-accelerated development.

---

## Why this exists

Modern applications are 70–90% third-party code, supply chain attacks grew 742% year-over-year, and AI assistants are pushing more code into production faster than humans can review it. Traditional ASOC tools generate alert fatigue because they cannot answer the only question that matters: **"Is this vulnerability actually reachable in my running application?"**

This platform answers that question by:

- Generating SBOMs once and continuously matching them against new CVEs (scan-once, monitor-always).
- Building a Code Property Graph (CPG) and correlating it with runtime eBPF telemetry to determine real reachability.
- Calculating a contextual risk score: `Severity × Reachability × Exposure × Criticality`.
- Auto-generating remediation PRs and CSAF 2.0 VEX reports for downstream consumers.

## High-level features

| Capability | Implementation |
| --- | --- |
| SBOM generation | [Syft](https://github.com/anchore/syft) wrapper (CycloneDX 1.5) |
| Vulnerability matching | [Grype](https://github.com/anchore/grype) — SBOM-first, no recompute |
| SAST | [Semgrep](https://semgrep.dev) (rules) + [Joern](https://joern.io) (CPG) |
| Secret scanning | [Gitleaks](https://github.com/gitleaks/gitleaks) |
| Normalization / dedup | DefectDojo-compatible schema in [internal/correlation](internal/correlation/) |
| Reachability | CPG analysis + eBPF runtime confirmation in [internal/reachability](internal/reachability/) |
| Risk scoring | Integrated formula in [internal/scoring/scorer.go](internal/scoring/scorer.go) |
| Remediation | Mend-Renovate-style PRs + LLM agent in [remediation/agents](remediation/agents/) |
| VEX reporting | CSAF 2.0 (Profile 5) in [remediation/reports/vex_generator.py](remediation/reports/vex_generator.py) |
| Quality Gates | Configurable CI gates in [internal/quality](internal/quality/) |

## Tech stack

- **Core engine:** Go 1.22 — high-concurrency CPG/AST processing, REST API, scanner orchestration.
- **Remediation layer:** Python 3.11 — FastAPI, LLM orchestration (Anthropic Claude / OpenAI), CSAF 2.0 generation.
- **Data layer:** PostgreSQL 16 — assets, findings, CPG metadata, audit history.
- **Cache / queue:** Redis 7 — scan job queue, scoring cache.
- **Orchestration:** Docker Compose for local, Helm/Kubernetes manifests for production.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component diagram and data flow.

## Repository layout

```
.
├── cmd/                    # Go binary entry points
│   ├── aspm-api/           # REST API + dashboards (v0.8+)
│   ├── aspm-scanner/       # Scanner orchestrator (CI worker)
│   └── supplychain-kit/    # Operator CLI (local scans, gate checks)
├── internal/               # Private Go packages
│   ├── api/                # HTTP handlers, middleware, routing
│   ├── config/             # Viper-based configuration
│   ├── ingestion/          # Git provider webhook receivers
│   ├── scanner/            # Adapters: syft, grype, semgrep, joern, gitleaks
│   ├── correlation/        # Finding normalization & dedup (DefectDojo-shape)
│   ├── reachability/       # CPG + eBPF reachability engine
│   ├── scoring/            # Integrated Risk Score calculator
│   ├── quality/            # Quality Gate evaluator (CI break/pass)
│   ├── models/             # Domain models (Asset, Finding, SBOM, ...)
│   └── storage/            # PostgreSQL repositories
├── pkg/                    # Public Go packages (importable)
│   ├── types/              # Shared types (CycloneDX, CVSS, ...)
│   └── sbom/               # SBOM helpers
├── remediation/            # Python remediation service
│   ├── api/                # FastAPI server
│   ├── agents/             # LLM remediation + Renovate agent
│   ├── reports/            # CSAF 2.0 VEX generator
│   └── tests/
├── deployments/
│   ├── docker/             # Dockerfiles per service
│   └── k8s/                # Helm-style manifests
├── migrations/             # Versioned SQL migrations
├── configs/                # Sample configuration files
├── docs/                   # PRD + design docs
├── scripts/                # Bootstrap & developer helpers
└── results/                # Local scan reports (gitignored)
```

## Installation

### Prerequisites

- [Go 1.22+](https://go.dev/dl) — required to build from source
- `git` and `curl` — required by the installer
- Scanner tools (installed automatically by `install.sh`): `syft`, `grype`, `gitleaks`, `semgrep`

### One-liner installer (Linux / macOS / Windows Git Bash)

```bash
git clone https://github.com/penanamtomat/supplychain-kit
cd supplychain-kit
bash install.sh
```

The installer will:
1. Verify `go`, `git`, `curl` are available
2. Install `syft`, `grype`, `gitleaks`, `semgrep` to `~/.local/bin`
3. Build and install `supplychain-kit` binary to `~/.local/bin`

**Installer options:**

```bash
bash install.sh                        # full install (all scanner tools)
bash install.sh --no-semgrep           # skip semgrep (if Python is not available)
bash install.sh --prefix /usr/local    # install to a different directory
```

After installation, reload your shell and verify:

```bash
source ~/.bashrc          # or: source ~/.zshrc
supplychain-kit --help
```

### Uninstall

```bash
bash uninstall.sh           # remove supplychain-kit binary only
bash uninstall.sh --tools   # also remove syft, grype, gitleaks, semgrep
```

---

## Usage

### Quick start — one command, full report

The `run` command is the primary way to use supplychain-kit. It scans a repository, evaluates the quality gate, and generates a full report in one step:

```bash
supplychain-kit run <engagement-name> --repo <url-or-path> [--mode sca|sast|all]
```

**Examples:**

```bash
# Scan a remote GitHub repository (cloned automatically, deleted after scan)
supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo

# Scan a local project directory
supplychain-kit run myapp-2026q1 --repo /path/to/project

# Supply chain only (dependency CVEs)
supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo --mode sca

# SAST only (code issues + secrets)
supplychain-kit run myapp-2026q1 --repo /path/to/project --mode sast

# Specific branch or commit
supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo --ref main
```

**What happens when you run this command:**

```
1. Clone repo (if URL)       → temporary directory, auto-deleted after scan
2. syft                      → generate SBOM (software bill of materials)
3. grype                     → match SBOM against CVE database
4. semgrep + gitleaks        → SAST code scan + secret detection
5. Quality gate              → evaluate findings against policy
6. Generate report           → save all output to results/<engagement>/
```

**Output files** saved to `results/<engagement-name>/`:

| File | Description |
|---|---|
| `report.md` | Full markdown report (executive summary + findings table) |
| `findings.json` | All findings in JSON format (for CI / downstream tools) |
| `findings.txt` | Findings as a plain-text table |
| `summary.json` | Counts by severity + metadata |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Pass — no policy violations |
| `1` | Warn — High severity findings present |
| `2` | Fail — Critical severity findings present |

---

### Manage engagements

Each `run` invocation creates an engagement. Use `engage` to review past scans:

```bash
# List all past engagements
supplychain-kit engage list

# Show details of a specific engagement
supplychain-kit engage status myapp-2026q1
```

Example output of `engage list`:
```
ENGAGEMENT        DATE        TOTAL  CRITICAL  HIGH  MEDIUM  LOW
myapp-2026q1      2026-04-22  11     0         4     7       0
myapp-clean       2026-04-21  0      0         0     0       0
```

---

### Scanner modes

| Mode | Scanners used | What it finds |
|---|---|---|
| `sca` | syft → grype | Dependency CVEs (supply chain vulnerabilities) |
| `sast` | semgrep + gitleaks | Code vulnerabilities + hardcoded secrets |
| `all` | all of the above | Everything (default) |

---

### Generate SBOM only (no vulnerability scan)

```bash
# CycloneDX 1.5 JSON (default)
supplychain-kit sbom --repo /path/to/project --out sbom.json

# SPDX 2.3 JSON
supplychain-kit sbom --repo /path/to/project --format spdx --out sbom.spdx.json

# Save to results/<name>/sbom.json
supplychain-kit sbom --repo /path/to/project --target myapp
```

---

### Run individual steps manually

If you need more control, each step can be run separately:

```bash
# 1. Scan only — output JSON findings
supplychain-kit scan --repo /path/to/project --mode sca --out findings.json

# 2. Evaluate quality gate from a findings file
supplychain-kit gate --findings findings.json

# 3. Pipe scan directly into gate (no intermediate file)
supplychain-kit scan --repo . --format json | supplychain-kit gate
```

---

### CI integration (GitHub Actions)

```yaml
- name: Security scan
  run: supplychain-kit run ${{ github.event.repository.name }}-${{ github.run_id }} --repo . --mode all
```

The workflow will fail automatically on Critical findings (exit `2`) or warn on High findings (exit `1`). To allow the workflow to continue even on failures:

```yaml
- name: Security scan
  run: supplychain-kit run myapp --repo . --mode sca
  continue-on-error: true
```

---

### Policy configuration

The default policy warns on High and fails on Critical. Override with a custom file:

```bash
supplychain-kit run myapp --repo . --policy configs/aspm.yaml
```

Policy file format (`configs/aspm.yaml`):

```yaml
quality_gate:
  fail_on:
    - severity: critical
    - severity: high
      max_count: 0   # zero tolerance for High
  warn_on:
    - severity: medium
```

---

## Command reference

| Command | Description |
|---|---|
| `supplychain-kit run <name> --repo <url\|path>` | **Full scan + report in one command** (recommended) |
| `supplychain-kit engage list` | List all past engagements |
| `supplychain-kit engage status <name>` | Show details of a specific engagement |
| `supplychain-kit scan --repo <url\|path>` | Run scan only, no report |
| `supplychain-kit sbom --repo <url\|path>` | Generate SBOM without vulnerability scan |
| `supplychain-kit gate --findings <file>` | Evaluate findings against quality gate policy |

---

## Configuration

Configuration file: `configs/aspm.yaml`. Environment variables use the prefix `ASPM_`.

| Variable | Purpose | Required |
|---|---|---|
| `ASPM_DB_DSN` | Postgres connection string | v0.8+ (server mode only) |
| `ASPM_REDIS_URL` | Redis URL for scan queue | v0.8+ (server mode only) |
| `ASPM_LLM_PROVIDER` | `anthropic` or `openai` | v0.9+ (AI remediation only) |
| `ASPM_LLM_API_KEY` | API key for LLM provider | v0.9+ (AI remediation only) |
| `ASPM_GITHUB_TOKEN` | Token for opening PRs | v0.9+ (AI remediation only) |

> Database and Redis are **not required** in standalone CLI mode. They are introduced in v0.8 for team/server deployments.

## Roadmap

Aligned with the four-phase delivery in the PRD:

1. **Phase 1 — Visibility (M1–M3):** Syft/Grype, Gitleaks, DefectDojo-shaped Single Pane of Glass. *(implemented in this repo)*
2. **Phase 2 — Orchestration & Reachability PoC (M4–M6):** CI Quality Gates and a Joern reachability PoC. *(scaffolded)*
3. **Phase 3 — Intelligence (M7–M10):** Full CPG + eBPF reachability and Agentic SAST.
4. **Phase 4 — Automation (M11–M15):** AI remediation PRs and CSAF 2.0 VEX automation.

## Compliance

The platform produces evidence aligned with:

- **NIST SSDF (SP 800-218)** — provenance and release-integrity attestations.
- **SLSA L1–L3** — build-time integrity claims.
- **OWASP SCVS** — vendor-risk and outdated-component analytics.
- **CSAF 2.0 (Profile 5) VEX** — machine-readable status with CISA justifications.

## License

Apache-2.0. See [LICENSE](LICENSE) (to be added).

## Contributing

This is a reference implementation. Issues and PRs that align with the PRD's four-phase roadmap are welcome.
