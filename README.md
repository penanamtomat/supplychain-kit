# supplychain-kit

> Open-source CLI for supply chain security — SCA, SAST, secret scanning, reachability analysis, and risk-aware quality gates in a single binary.

Runs locally. No database, no Docker, no external services. One command to scan, score, and gate your project.

---

## Install

**Linux / macOS (one-liner):**

```bash
curl -fsSL https://raw.githubusercontent.com/penanamtomat/supplychain-kit/main/install.sh | bash
```

**Manual build from source:**

```bash
git clone https://github.com/penanamtomat/supplychain-kit.git
cd supplychain-kit
bash install.sh
```

**Windows:** Not supported natively. Use WSL2: `wsl --install && wsl bash install.sh`

The installer automatically installs scanner tools (`syft`, `grype`, `gitleaks`, `semgrep`, `joern`) and builds the binary.

**Installer options:**

```bash
bash install.sh                        # full install
bash install.sh --no-semgrep           # skip semgrep
bash install.sh --no-pandoc            # skip pandoc (not needed for markdown reports)
bash install.sh --prefix /usr/local    # install to a custom directory
```

**Uninstall:**

```bash
bash uninstall.sh           # remove binary only
bash uninstall.sh --tools   # also remove scanner tools
```

---

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/penanamtomat/supplychain-kit/main/install.sh | bash

# Scan your project (SCA + SAST + secrets + quality gate)
supplychain-kit run myapp-2026q1 --repo /path/to/project

# View results
cat results/myapp-2026q1/report.md
```

**Step-by-step:**

```bash
supplychain-kit init myapp-2026q1 --repo /path/to/project    # bootstrap engagement
supplychain-kit scan --repo /path/to/project --mode sca       # scan dependencies only
supplychain-kit gate --findings results/findings.json         # evaluate quality gate
supplychain-kit report --engagement myapp-2026q1              # generate report
```

---

## What It Does

| Step | Tool | Purpose |
|------|------|---------|
| SBOM generation | [Syft](https://github.com/anchore/syft) | CycloneDX 1.5 software bill of materials |
| Vulnerability matching | [Grype](https://github.com/anchore/grype) | Match SBOM against CVE database |
| Additional SCA | [Trivy](https://trivy.dev), [osv-scanner](https://google.github.io/osv-scanner/) | Extra vulnerability coverage |
| SAST | [Semgrep](https://semgrep.dev) | Code vulnerability detection |
| Secret scanning | [Gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets and credentials |
| Reachability | [Joern](https://joern.io) | Code Property Graph — is the CVE actually reachable? |
| Taint analysis | Built-in | Trace user input to vulnerable sinks |
| Risk scoring | Built-in | `CVSS × Reachability × Exposure × Criticality` |
| Quality gate | Built-in | Pass/warn/fail with configurable policy |

**Key differentiator:** supplychain-kit doesn't just list CVEs — it traces whether user-controlled input can actually reach vulnerable code paths, reducing false positives by ~40%.

---

## Scanner Modes

| Mode | Scanners | What it finds |
|------|----------|---------------|
| `sca` | syft, grype, trivy, osv-scanner, joern | Dependency CVEs + reachability |
| `sast` | semgrep, gitleaks, joern | Code vulnerabilities + secrets + reachability |
| `all` | all of the above | Everything (default) |

---

## Commands

| Command | Description |
|---------|-------------|
| `supplychain-kit run <name> --repo <path>` | Full scan + gate + report (recommended) |
| `supplychain-kit scan --repo <path>` | Scan only, output findings |
| `supplychain-kit gate --findings <file>` | Evaluate quality gate |
| `supplychain-kit sbom --repo <path>` | Generate SBOM (no vulnerability scan) |
| `supplychain-kit report --engagement <name>` | Generate markdown/DOCX report |
| `supplychain-kit engage list` | List all past engagements |
| `supplychain-kit engage status <name>` | Show engagement details |
| `supplychain-kit remediate <findings.json>` | Package-level remediation guidance |
| `supplychain-kit license --engagement <name>` | Scan dependency licenses |
| `supplychain-kit graph <findings.json>` | Dependency graph visualization |
| `supplychain-kit mcp` | Start MCP server (for Claude Code) |

---

## Usage

### Full Scan (one command)

```bash
# Scan a local project
supplychain-kit run myapp-2026q1 --repo /path/to/project

# Scan a remote repo (cloned automatically, deleted after scan)
supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo

# Specific mode
supplychain-kit run myapp-2026q1 --repo /path/to/project --mode sca
supplychain-kit run myapp-2026q1 --repo /path/to/project --mode sast

# Specific branch
supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo --ref main
```

**What happens under the hood:**

```
Clone repo (if URL) → syft (SBOM) → grype (CVEs) → semgrep + gitleaks (SAST) → quality gate → report
```

**Output files** in `results/<engagement>/`:

| File | Description |
|------|-------------|
| `report.md` | Markdown report with executive summary and findings |
| `findings.json` | All findings in JSON |
| `summary.json` | Severity counts + metadata |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Pass — no policy violations |
| `1` | Warn — High severity findings present |
| `2` | Fail — Critical severity findings present |

### Engagement Tracking

```bash
supplychain-kit engage list
```

```
ENGAGEMENT        DATE        TOTAL  CRITICAL  HIGH  MEDIUM  LOW
myapp-2026q1      2026-04-22  11     0         4     7       0
myapp-clean       2026-04-21  0      0         0     0       0
```

### SBOM Generation

```bash
# CycloneDX 1.5 JSON (default)
supplychain-kit sbom --repo /path/to/project --out sbom.json

# SPDX 2.3 JSON
supplychain-kit sbom --repo /path/to/project --format spdx --out sbom.spdx.json
```

### Quality Gate Policies

Three policies included in `configs/`:

| Policy | Behavior | Use case |
|--------|----------|----------|
| `policy-strict.yaml` | Fail on Critical **and** High | `main` branch, pre-release |
| `policy-moderate.yaml` | Fail on Critical, warn on High | Feature branches (default) |
| `policy-permissive.yaml` | Warn only, never fail | Onboarding, legacy repos |

```bash
supplychain-kit gate --findings findings.json --policy configs/policy-strict.yaml
```

### Remediation

```bash
# Package-level remediation guidance with priority ranking
supplychain-kit remediate results/myapp/findings.json

# Show only quick-fix commands (P0/P1 packages)
supplychain-kit remediate results/myapp/findings.json --quick-fix
```

### License Compliance

```bash
supplychain-kit license --engagement myapp
# Output: results/myapp/license-report.md
```

### Dependency Graph

```bash
# ASCII graph (terminal)
supplychain-kit graph results/myapp/findings.json --format ascii

# Mermaid.js (for markdown/docs)
supplychain-kit graph results/myapp/findings.json --format mermaid

# Graphviz DOT
supplychain-kit graph results/myapp/findings.json --format dot
```

### MCP Server (Claude Code)

```bash
# Start MCP server (stdio transport)
supplychain-kit mcp

# Print mcp.json registration snippet
supplychain-kit mcp --print-config
```

Exposes 5 tools for Claude Code automation:

| Tool | Purpose |
|------|---------|
| `init_engagement` | Bootstrap scan engagement |
| `scan_repository` | Run full SCA + SAST + reachability pipeline |
| `generate_sbom` | Generate CycloneDX SBOM via Syft |
| `run_gate` | Evaluate findings against quality gate |
| `generate_report` | Render findings to Markdown/DOCX report |

### Suppression (`.supplychain-ignore`)

Suppress false positives with a `.supplychain-ignore` file in your project root:

```
# Suppress specific CVE
CVE-2023-12345

# Suppress by rule + path pattern
semgrep.tainted-sql  path:internal/legacy/*.go

# Suppress by package with reason
*  package:github.com/dead/pkg  reason:unmaintained, isolated in dev-only code
```

---

## Project Structure

```
supplychain-kit/
├── cmd/supplychain-kit/     # CLI entry point
├── internal/
│   ├── config/              # Configuration (Viper)
│   ├── correlation/         # Finding normalization and dedup
│   ├── graph/               # Dependency graph visualization
│   ├── license/             # License compliance scanning
│   ├── mcp/                 # MCP server for Claude Code
│   ├── models/              # Domain models (Finding, Asset, SBOM)
│   ├── quality/             # Quality gate evaluator
│   ├── reachability/        # CPG reachability engine (Joern)
│   ├── remediation/pkg/     # Package-level remediation
│   ├── report/              # Report generation
│   ├── scanner/             # Scanner adapters (syft, grype, semgrep, joern, gitleaks, trivy, osv)
│   ├── scoring/             # Risk score calculator
│   ├── suppress/            # .supplychain-ignore suppression
│   └── taint/               # Taint analysis engine
├── configs/                 # Policies, semgrep rules, templates
├── remediation/             # Python-based remediation (agents, reports)
├── docs/                    # PRD, development plan, architecture
├── scripts/                 # Developer helpers
└── results/                 # Local scan output (gitignored)
```

---

## Configuration

Config file: `configs/aspm.yaml`. Environment variables use prefix `ASPM_`.

| Variable | Purpose | Required |
|----------|---------|----------|
| `ASPM_SCANNERS_WORK_DIR` | Temp directory for scanner workfiles | No |
| `ASPM_QUALITY_GATE_FAIL_ON` | Override fail-on severity rules | No |
| `ASPM_QUALITY_GATE_WARN_ON` | Override warn-on severity rules | No |

---

## Roadmap

| Version | Focus | Status |
|---------|-------|--------|
| v0.3 – v0.5 | SCA pipeline, SAST pipeline, quality gate | Done |
| v0.6 | Reachability engine + CLI consolidation | Done |
| v0.7 | Dependency-Track + DefectDojo CLI commands | Done |
| v0.8 | Claude Code MCP integration + report generation | Done |
| v0.9 | Taint analysis engine (dependency-aware SAST) | Done |
| v0.9.5 | Remediation, license scanning, dependency graph | Done |
| **v1.0** | **Public release** | **Released** |
| v1.1 | Homebrew, GitHub Action, VEX reports | Planned |
| v1.2 | IaC scanning, container image scanning | Planned |
| v1.3 | ML-enhanced detection | Planned |

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for detailed task breakdown.

---

## Compliance

Produces evidence aligned with:

- **NIST SSDF (SP 800-218)** — provenance and release-integrity attestations
- **SLSA L1–L3** — build-time integrity claims
- **OWASP SCVS** — vendor-risk and outdated-component analytics
- **CSAF 2.0 (Profile 5) VEX** — machine-readable vulnerability status

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and PR process.

See [SECURITY.md](SECURITY.md) for responsible vulnerability disclosure.

## License

Apache-2.0
