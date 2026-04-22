# Integrated ASPM Platform

> An open Application Security Posture Management (ASPM) platform that unifies SAST, SCA, secret scanning, reachability analysis, and AI-driven remediation into a single, risk-aware control plane.

This project is the reference implementation of the ASPM platform described in [docs/Product Requirements Document (PRD)_ Integrated Application Security Posture Management (ASPM) Platform.md](docs/Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md). It moves security teams from siloed scanning to a cohesive, prioritized risk model that scales with AI-accelerated development.

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
│   ├── aspm-api/           # REST API + dashboards
│   ├── aspm-scanner/       # Scanner orchestrator (CI worker)
│   └── aspm-cli/           # Operator CLI (local scans, gate checks)
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
└── tests/                  # End-to-end / integration tests
```

## Quickstart

### Prerequisites

- Docker + Docker Compose (or Podman)
- Go 1.22+ and Python 3.11+ (only if building from source)
- The following CLIs available on `PATH` for the scanner adapters: `syft`, `grype`, `semgrep`, `gitleaks`. The orchestrator falls back to containerized invocations when absent.

### Local stack (recommended)

```bash
# 1. Bring up Postgres, Redis, the API, the scanner worker, and the remediation service
docker compose -f deployments/docker/docker-compose.yml up -d

# 2. Run database migrations
make migrate

# 3. Trigger an end-to-end scan against a target repository
./bin/aspm-cli scan --repo https://github.com/OWASP/NodeGoat --tag demo

# 4. Open the API
curl http://localhost:8080/api/v1/findings | jq
```

### Build from source

```bash
make build           # Builds all Go binaries into ./bin
make python-deps     # Creates a virtualenv for the remediation layer
make test            # Runs unit tests for both Go and Python sides
make lint            # golangci-lint + ruff
```

## Configuration

Configuration is layered: defaults → `configs/aspm.yaml` → environment variables (prefix `ASPM_`). See [configs/aspm.yaml](configs/aspm.yaml) for the annotated reference.

Key environment variables:

| Variable | Purpose |
| --- | --- |
| `ASPM_DB_DSN` | Postgres connection string |
| `ASPM_REDIS_URL` | Redis URL for the scan queue |
| `ASPM_LLM_PROVIDER` | `anthropic` or `openai` for the remediation agent |
| `ASPM_LLM_API_KEY` | API key for the chosen provider |
| `ASPM_GITHUB_TOKEN` | Token used to open remediation PRs |

## Quality Gates

CI integrations call `aspm-cli gate` after a scan finishes. The exit code is non-zero whenever a finding crosses the configured policy. A typical policy:

```yaml
quality_gate:
  fail_on:
    - severity: critical
      reachable: true
    - severity: high
      reachable: true
      max_count: 0
  warn_on:
    - severity: medium
```

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
