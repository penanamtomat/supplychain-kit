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

### One-liner (Linux / macOS / Windows Git Bash)

```bash
bash install.sh
```

This script will:
1. Check prerequisites (`go`, `git`, `curl`)
2. Install scanner tools: `syft`, `grype`, `gitleaks`, `semgrep`
3. Build `supplychain-kit` from source
4. Install the binary to `~/.local/bin` (or `/usr/local/bin` on macOS)

**Options:**

```bash
bash install.sh --no-semgrep           # skip semgrep (no Python required)
bash install.sh --prefix /usr/local    # custom install directory
INSTALL_DIR=/opt/aspm bash install.sh  # via environment variable
```

### Build from source manually

Requires Go 1.22+.

```bash
git clone https://github.com/penanamtomat/supplychain-kit
cd supplychain-kit
go build -o bin/supplychain-kit ./cmd/supplychain-kit
```

### Uninstall

```bash
bash uninstall.sh           # remove supplychain-kit binary only
bash uninstall.sh --tools   # also remove syft, grype, gitleaks, semgrep
```

---

## Usage

### Scan a local repository

```bash
# Supply chain scan (syft → grype): dependency vulnerabilities
supplychain-kit scan --repo /path/to/project --mode sca

# SAST scan (semgrep + gitleaks): code issues and secrets
supplychain-kit scan --repo /path/to/project --mode sast

# Full scan: all scanners
supplychain-kit scan --repo /path/to/project --mode all
```

### Scan a remote repository (no clone needed)

```bash
supplychain-kit scan --repo https://github.com/org/repo --mode sca
supplychain-kit scan --repo https://github.com/org/repo --ref main --mode all
```

The CLI clones the repository into a temporary directory automatically and removes it after the scan completes.

### Output formats

```bash
# Human-readable summary to stderr (default)
supplychain-kit scan --repo . --mode sca

# Table view to stdout
supplychain-kit scan --repo . --mode sca --format table

# JSON findings to a file
supplychain-kit scan --repo . --mode sca --format json --out findings.json

# Save all reports (findings.json, findings.txt, summary.json) to results/<name>/
supplychain-kit scan --repo . --mode all --target myapp
```

### Generate an SBOM

```bash
# CycloneDX 1.5 JSON (default)
supplychain-kit sbom --repo /path/to/project --out sbom.json

# SPDX 2.3 JSON
supplychain-kit sbom --repo /path/to/project --format spdx --out sbom.spdx.json

# Save to results/<name>/sbom.json
supplychain-kit sbom --repo /path/to/project --target myapp
```

### Quality Gate

Evaluate a finding set against a policy and get a structured exit code:

```bash
supplychain-kit scan --repo . --out findings.json
supplychain-kit gate --findings findings.json
# exit 0 → pass, exit 1 → warn (High findings), exit 2 → fail (Critical findings)
```

Or pipe directly without an intermediate file:

```bash
supplychain-kit scan --repo . --format json | supplychain-kit gate
```

**Custom policy** (`--policy configs/aspm.yaml`):

```yaml
quality_gate:
  fail_on:
    - severity: critical
    - severity: high
      max_count: 0
  warn_on:
    - severity: medium
```

### CI integration (GitHub Actions)

```yaml
- name: Scan dependencies
  run: |
    supplychain-kit scan --repo . --mode sca --out findings.json
    supplychain-kit gate --findings findings.json --policy configs/aspm.yaml
```

Exit code `2` (Critical) will fail the workflow; exit code `1` (High) will fail unless you add `continue-on-error: true`.

---

## Configuration

Configuration is layered: defaults → `configs/aspm.yaml` → environment variables (prefix `ASPM_`). See [configs/aspm.yaml](configs/aspm.yaml) for the annotated reference.

Key environment variables:

| Variable | Purpose |
| --- | --- |
| `ASPM_DB_DSN` | Postgres connection string (required in server mode, v0.8+) |
| `ASPM_REDIS_URL` | Redis URL for the scan queue (v0.8+) |
| `ASPM_LLM_PROVIDER` | `anthropic` or `openai` for the remediation agent (v0.9+) |
| `ASPM_LLM_API_KEY` | API key for the chosen provider (v0.9+) |
| `ASPM_GITHUB_TOKEN` | Token used to open remediation PRs (v0.9+) |

> **Note:** Database and Redis are not required in standalone CLI mode (current phase). They are introduced in v0.8.

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
