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

- **Core engine:** Go — single static binary, no runtime dependencies.
- **Scanners:** Syft, Grype, Semgrep, Gitleaks, Joern (all external CLIs, installed separately).
- **No database, no Redis, no Docker required** — runs anywhere a Go binary can run.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component diagram and data flow.

## Repository layout

```
.
├── cmd/
│   └── supplychain-kit/    # CLI entry point
├── internal/               # Private Go packages
│   ├── agenticsast/        # Snippet-level SAST (used in v0.8 Claude Code integration)
│   ├── config/             # Viper-based configuration (configs/aspm.yaml)
│   ├── correlation/        # Finding normalization & dedup
│   ├── defectdojo/         # DefectDojo API client (used by v0.7 CLI commands)
│   ├── deptrack/           # Dependency-Track API client (used by v0.7 CLI commands)
│   ├── models/             # Domain models (Asset, Finding, SBOM, ...)
│   ├── quality/            # Quality Gate evaluator (CI break/pass)
│   ├── reachability/       # CPG reachability engine (Joern + static analysis)
│   ├── scanner/            # Adapters: syft, grype, semgrep, joern, gitleaks
│   └── scoring/            # Integrated Risk Score calculator
├── pkg/                    # Public Go packages (importable)
│   ├── types/              # Shared types (CycloneDX, CVSS, ...)
│   └── sbom/               # SBOM helpers
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

## Quick Start

### Install

```bash
# One-liner (Linux / macOS)
curl -fsSL https://raw.githubusercontent.com/penanamtomat/supplychain-kit/main/install.sh | bash

# Or download the binary from GitHub Releases
# https://github.com/penanamtomat/supplychain-kit/releases/latest
```

### Scan your project

```bash
# All-in-one scan + report + quality gate
supplychain-kit run my-engagement --repo /path/to/your/project

# Supply chain only
supplychain-kit run my-engagement --repo /path/to/your/project --mode sca

# SAST + secrets only
supplychain-kit run my-engagement --repo /path/to/your/project --mode sast
```

### Step-by-step

```bash
supplychain-kit init my-engagement --repo /path/to/your/project
supplychain-kit scan --repo /path/to/your/project --format json > results/findings.json
supplychain-kit gate --findings results/findings.json
supplychain-kit report --engagement my-engagement
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

Full workflow — scans on every push and pull request, fails the pipeline on Critical findings:

```yaml
name: Security Scan

on:
  push:
    branches: [main, dev]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install supplychain-kit
        run: bash <(curl -fsSL https://raw.githubusercontent.com/penanamtomat/supplychain-kit/main/install.sh)

      - name: Run security scan
        run: |
          supplychain-kit run ${{ github.event.repository.name }}-${{ github.run_number }} \
            --repo . \
            --mode all \
            --policy configs/policy-strict.yaml

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: results/
```

Exit codes are handled automatically by GitHub Actions:
- Exit `0` → pipeline passes
- Exit `1` → pipeline fails (warn policy triggered)
- Exit `2` → pipeline fails (Critical found)

To scan without blocking the pipeline (report only):

```yaml
      - name: Security scan (non-blocking)
        run: supplychain-kit run myapp --repo . --mode sca
        continue-on-error: true
```

Two-step variant — scan then gate separately (useful for uploading artifacts before gating):

```yaml
      - name: Scan
        run: supplychain-kit scan --repo . --format json --out findings.json

      - name: Upload findings
        uses: actions/upload-artifact@v4
        with:
          name: findings
          path: findings.json

      - name: Quality gate
        run: supplychain-kit gate --findings findings.json --policy configs/policy-strict.yaml
```

---

### CI integration (GitLab CI)

```yaml
security-scan:
  stage: test
  image: ubuntu:22.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl git
    - bash <(curl -fsSL https://raw.githubusercontent.com/penanamtomat/supplychain-kit/main/install.sh)
    - export PATH="$PATH:$HOME/.local/bin"
  script:
    - supplychain-kit run $CI_PROJECT_NAME-$CI_PIPELINE_ID --repo . --mode all
  artifacts:
    when: always
    paths:
      - results/
    expire_in: 30 days
  allow_failure: false
```

Non-blocking variant (report only, pipeline never fails):

```yaml
security-scan:
  script:
    - supplychain-kit run $CI_PROJECT_NAME-$CI_PIPELINE_ID --repo . --mode all
  allow_failure: true
```

---

### Policy configuration

Three ready-made policies are included in `configs/`:

| File | Behaviour | Use case |
|---|---|---|
| `policy-strict.yaml` | Fail on Critical **and** High | `main` branch, pre-release gate |
| `policy-moderate.yaml` | Fail on Critical, warn on High | Feature branches (default) |
| `policy-permissive.yaml` | Warn only, never fail | Onboarding, legacy repos |

```bash
# Use a specific policy
supplychain-kit gate --findings findings.json --policy configs/policy-strict.yaml

# Pipe scan output directly into gate (no intermediate file)
supplychain-kit scan --repo . --format json | supplychain-kit gate --policy configs/policy-moderate.yaml
```

Custom policy format:

```yaml
quality_gate:
  fail_on:
    - severity: critical
    - severity: high
      max_count: 0   # zero tolerance
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
| `ASPM_SCANNERS_WORK_DIR` | Temp directory for scanner workfiles | No (default: `/tmp/aspm-work`) |
| `ASPM_QUALITY_GATE_FAIL_ON` | Override fail-on severity rules | No |
| `ASPM_QUALITY_GATE_WARN_ON` | Override warn-on severity rules | No |

## Roadmap

| Version | Focus | Status |
|---------|-------|--------|
| v0.3–v0.5 | SCA pipeline, SAST pipeline, Quality Gate | ✅ Done |
| v0.6 | Reachability engine + CLI consolidation | 🔧 In Progress |
| v0.7 | Dependency-Track & DefectDojo CLI commands | Planned |
| v0.8 | Claude Code MCP integration + Agentic SAST | Planned |
| v1.0 | Binary release, docs, Homebrew | Planned |

See [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) for detailed task breakdown.

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
