# supplychain-kit

![Version](https://img.shields.io/github/v/release/penanamtomat/supplychain-kit?label=version)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Go](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go)

> Open-source CLI for supply chain security — SCA, SAST, secret scanning, reachability analysis, and risk-aware quality gates in a single binary.

Runs locally. No database, no Docker, no external services. One command to scan, score, and gate your project.

---

## How It Works

| | Traditional Scanners | supplychain-kit |
|---|---|---|
| Vulnerability detection | Run grype/trivy, get list of CVEs | Run grype/trivy/osv-scanner, cross-reference with SBOM |
| False positives | Alert on every CVE in dependencies | Trace user input → vulnerable code path via CPG taint analysis |
| Risk prioritization | Sort by CVSS score | `CVSS × Reachability × Exposure × Criticality` |
| Remediation | "Upgrade to version X" | Package-level guidance: P0 fix-now, upgrade commands, breaking notes |
| Quality gate | Manual review of findings | Configurable pass/warn/fail policy with exit codes for CI |
| Reporting | JSON output only | Markdown + DOCX reports with executive summary |
| Suppression | Disable rules globally | `.supplychain-ignore` with CVE/rule/path/package granularity |
| Claude Code | No integration | MCP server with 5 tools + orchestrator agent + knowledge base |

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

## Scanners

| Scanner | Type | Purpose |
|---------|------|---------|
| [Syft](https://github.com/anchore/syft) | SBOM | CycloneDX 1.5 software bill of materials |
| [Grype](https://github.com/anchore/grype) | SCA | Match SBOM against CVE database |
| [Trivy](https://trivy.dev) | SCA | Extra vulnerability coverage |
| [osv-scanner](https://google.github.io/osv-scanner/) | SCA | OSV database matching |
| [Semgrep](https://semgrep.dev) | SAST | Code vulnerability detection (32+ rules) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | Hardcoded secrets and credentials |
| [Joern](https://joern.io) | CPG | Code Property Graph for reachability |
| Built-in | Taint | Trace user input to vulnerable sinks |
| Built-in | Scoring | `CVSS × Reachability × Exposure × Criticality` |
| Built-in | Gate | Pass/warn/fail with configurable policy |

### Scanner Modes

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
| `supplychain-kit init <name> --repo <path>` | Bootstrap engagement directory |

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

## Claude Code Integration

supplychain-kit runs as an MCP server inside Claude Code, providing an agentic security workflow with context-aware analysis.

### Setup

```bash
# Register the MCP server
supplychain-kit mcp --print-config
# Paste output into ~/.claude/mcp.json
```

### Workflow

When you use supplychain-kit in Claude Code, the orchestrator agent runs this pipeline:

```
Phase 1: Init       → Create engagement directory and state tracking
Phase 2: SBOM       → Catalog components via syft (CycloneDX 1.5)
Phase 3: Scan       → SCA + SAST + reachability analysis (7 scanners)
Phase 4: Gate       → Evaluate findings against quality gate policy
Phase 5: Analyze    → Context-aware triage using Claude + knowledge base
Phase 6: Report     → Generate markdown report with remediation guidance
```

### MCP Tools

| Tool | Purpose |
|------|---------|
| `init_engagement` | Bootstrap scan engagement directory + state tracking |
| `scan_repository` | Run full SCA + SAST + reachability pipeline |
| `generate_sbom` | Generate CycloneDX SBOM via Syft |
| `run_gate` | Evaluate findings against quality gate policy |
| `generate_report` | Render findings to Markdown/DOCX report |

### Knowledge Base

The skill includes 7 domain-specific knowledge documents that give Claude context for triage decisions:

| Document | Coverage |
|----------|----------|
| `supply-chain-attacks.md` | Dependency confusion, typosquatting, malicious injection, protestware patterns |
| `cve-severity-guide.md` | CVSS scoring, reachability multipliers, risk score formula |
| `remediation-by-ecosystem.md` | Fix commands for npm, pip, Go, Maven, Cargo, Ruby, Docker |
| `sbom-formats.md` | CycloneDX vs SPDX, NTIA compliance, PURL identifiers |
| `ci-integration-patterns.md` | GitHub Actions, GitLab CI, pre-commit hooks, ArgoCD patterns |
| `ai-ml-supply-chain.md` | Model poisoning, PyPI risks, training pipeline attack surface |
| `risk-scoring-explained.md` | Risk formula breakdown with worked examples |

### Agents

Two specialized agents coordinate the workflow:

| Agent | Role |
|-------|------|
| **Orchestrator** | Coordinates full pipeline: Init → SBOM → Scan → Gate → Analyze → Report |
| **Executor** | Domain-specific tasks: SCA grouping, SAST categorization, analysis prioritization |

### Companion Skills (External)

Extend supplychain-kit with Trail of Bits plugins:

```bash
# Maintainer risk analysis + takeover detection
/plugin install trailofbits/skills/plugins/supply-chain-risk-auditor

# CodeQL + Semgrep + SARIF multi-scanner triage
/plugin install trailofbits/skills/plugins/static-analysis

# Author custom Semgrep rules for project-specific patterns
/plugin install trailofbits/skills/plugins/semgrep-rule-creator
```

| When to invoke | Plugin |
|----------------|--------|
| Suspicious packages found after scan | `supply-chain-risk-auditor` |
| SAST findings need deeper triage | `static-analysis` |
| Recurring vulnerability patterns | `semgrep-rule-creator` |

### Reachability Priority Matrix

Used by the executor agent to prioritize findings:

| Reachability | Severity | Action |
|---|---|---|
| Reachable/Confirmed | Any | Fix now (P0) |
| Unknown | Critical/High | Treat as reachable |
| Unknown | Medium/Low | Next sprint |
| Unreachable | Critical | Next sprint |
| Unreachable | High or below | Monitor |

---

## Project Structure

```
supplychain-kit/
├── cmd/supplychain-kit/     # CLI entry point (cobra commands)
├── internal/
│   ├── config/              # Configuration (Viper)
│   ├── correlation/         # Finding normalization and dedup
│   ├── graph/               # Dependency graph (DOT, Mermaid, ASCII)
│   ├── license/             # License compliance scanning
│   ├── mcp/                 # MCP server (5 tools, stdio transport)
│   ├── models/              # Domain models (Finding, Asset, SBOM)
│   ├── quality/             # Quality gate evaluator
│   ├── reachability/        # CPG reachability engine (Joern)
│   ├── remediation/pkg/     # Package-level remediation
│   ├── report/              # Report generation (Markdown + DOCX)
│   ├── scanner/             # Scanner adapters (syft, grype, semgrep, joern, gitleaks, trivy, osv)
│   ├── scoring/             # Risk score calculator
│   ├── suppress/            # .supplychain-ignore suppression
│   └── taint/               # Taint analysis engine (source detection, propagation, sink matching)
├── configs/
│   ├── policy-*.yaml        # Quality gate policies (strict, moderate, permissive)
│   ├── semgrep-rules/       # Custom Semgrep rules (TypeScript + Python)
│   ├── hooks/               # Git hooks (pre-commit gate, post-scan summary)
│   └── report-templates/    # Markdown report templates
├── .claude/
│   ├── agents/              # Orchestrator + executor agents
│   └── skills/supplychain-kit/
│       ├── SKILL.md         # Skill definition
│       └── knowledge/       # 7 domain knowledge documents
├── remediation/             # Python-based remediation (agents, VEX reports)
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
