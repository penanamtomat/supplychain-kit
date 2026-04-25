# Architecture — supplychain-kit

This document describes the technical architecture of supplychain-kit v1.0 — a single-binary CLI tool for supply chain security scanning. It is the authoritative reference for component boundaries, data flow, and extension points.

## 1. Design principles

1. **Single binary, zero infrastructure.** No database, no Redis, no Docker. The tool runs anywhere a Go binary can execute.
2. **Reachability over severity.** A `Critical` CVE in unreachable code is downgraded; a reachable `Medium` finding is escalated. The risk score expresses this.
3. **Adapter-first scanners.** Every scanner is a thin adapter behind a Go interface. Swapping Semgrep for CodeQL is a config change, not a refactor.
4. **Deterministic gates.** Quality gates take a normalized finding set as input and produce a binary pass/fail with a deterministic explanation.
5. **CLI-first, MCP-optional.** All features work via CLI commands. The MCP server exposes the same pipeline as tools for Claude Code automation.

## 2. System components

```
┌─────────────────────────────────────────────────────────────────┐
│                     supplychain-kit CLI                         │
│                     cmd/supplychain-kit/main.go                 │
│                                                                 │
│  Commands: run | scan | gate | sbom | report | remediate |     │
│            license | graph | engage | mcp | init               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Scanner Adapters                            │
│                      internal/scanner/                           │
│  ┌────────┐ ┌───────┐ ┌─────────┐ ┌──────────┐ ┌────────────┐  │
│  │  syft  │ │ grype │ │ semgrep │ │ gitleaks │ │   joern    │  │
│  │ (SBOM) │ │ (CVE) │ │  (SAST) │ │ (secrets)│ │   (CPG)    │  │
│  └────────┘ └───────┘ └─────────┘ └──────────┘ └────────────┘  │
│  ┌────────┐ ┌───────────────┐                                   │
│  │ trivy  │ │  osv-scanner  │                                   │
│  │ (SCA)  │ │     (SCA)     │                                   │
│  └────────┘ └───────────────┘                                   │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                Correlation & Normalization                       │
│                internal/correlation                              │
│   - De-duplicate across scanners                                 │
│   - Map to common models.Finding schema                          │
│   - Fingerprint: (rule_id, file, line, package, version)        │
└──────────────────────────┬───────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
┌─────────────────────────┐  ┌──────────────────────────────────┐
│  Reachability Engine    │  │  Taint Analysis Engine            │
│  internal/reachability  │  │  internal/taint                   │
│   - CPG path search     │  │   - Source detection (HTTP, env,  │
│   - eBPF confirmation   │  │     file, CLI args)               │
│   - Confidence scoring  │  │   - Propagation (BFS via CPG)     │
│                         │  │   - Sanitizer detection            │
│                         │  │   - Sink matching (CVE symbols)   │
│                         │  │   - Path pruning (false pos ~40%) │
└───────────┬─────────────┘  └──────────────┬───────────────────┘
            │                                │
            ▼                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Risk Scoring                                 │
│                     internal/scoring                             │
│       Score = CVSS × Reachability × Exposure × Criticality       │
└──────────────────────────┬───────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌─────────────────┐
│ Quality Gate │  │   Report     │  │   Remediation    │
│ internal/    │  │  internal/   │  │   internal/      │
│  quality     │  │   report     │  │    remediation/  │
│              │  │              │  │      pkg         │
│ Pass/Warn/  │  │ Markdown +   │  │ Package grouping │
│ Fail        │  │ SARIF + DOCX │  │ Priority ranking │
└──────────────┘  └──────────────┘  └─────────────────┘
```

### 2.1 CLI Entry Point (`cmd/supplychain-kit/main.go`)

Cobra-based CLI with 14 subcommands. The `run` command is the primary entry point — it chains scan, gate, and report in one invocation. Each command can also be run independently for finer control.

Key commands and their pipeline role:

| Command | Pipeline Role |
|---------|---------------|
| `run` | Full pipeline: scan → gate → report |
| `scan` | Scanner orchestration only |
| `gate` | Quality gate evaluation from findings file |
| `sbom` | SBOM generation only (no CVE matching) |
| `report` | Render findings to Markdown/DOCX |
| `remediate` | Package-level remediation guidance |
| `mcp` | MCP server for Claude Code integration |

### 2.2 Scanner Adapters (`internal/scanner/`)

Every scanner implements a common interface:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, req ScanRequest) (Result, error)
}
```

Adapters shell out to the underlying CLI tool (`syft`, `grype`, etc.) and parse their JSON output. If a tool is not installed, the adapter returns `ErrBinaryNotFound` and is skipped gracefully.

The `Registry` manages which adapters run based on scan mode (`sca`, `sast`, `all`):

| Mode | Adapters |
|------|----------|
| `sca` | syft, grype, trivy, osv-scanner, joern |
| `sast` | semgrep, gitleaks, joern |
| `all` | all of the above |

### 2.3 Correlation & Normalization (`internal/correlation`)

Maps each adapter's native output into a common `models.Finding` shape. De-duplicates by `(rule_id, file_path, line, package, version)` fingerprint. Each finding carries a `Source` field identifying which scanner produced it.

### 2.4 Reachability Engine (`internal/reachability`)

- **Static path:** ingests CPG exports from Joern (`graphson` JSON), traverses from first-party sources (controllers, message handlers) to sinks (vulnerable function symbols from CVE metadata).
- **Runtime path:** optional eBPF sensor confirming a library is loaded into the running process. Graceful degradation if eBPF is unavailable.
- **Confidence scoring:** the engine emits a `confidence` value per finding so downstream consumers can weight results appropriately.

### 2.5 Taint Analysis Engine (`internal/taint`)

Bridges SCA and SAST findings by tracing whether user-controlled input can reach vulnerable code:

- **Source detection** (`source_detector.go`): identifies user-controlled input entry points from CPG — HTTP handlers (Express, Flask, FastAPI, Django, Gin, Echo), environment variables, file reads, CLI arguments.
- **Propagation** (`propagator.go`): BFS traversal from sources through call graph, tracking taint across function boundaries via CPG edges.
- **Sanitizer registry** (`sanitizer.go`): 100+ known sanitizers across ecosystems (DOMPurify, validator.js, SQLAlchemy, shlex.quote, pathlib.Path). Recognized sanitizers break the taint chain.
- **Sink matching** (`sink_matcher.go`): matches tainted nodes against CVE-affected function symbols from Grype/Trivy metadata.
- **Path pruning:** max path length 15, max branching factor 3, confidence threshold 0.3. Reduces false positives by ~40%.

### 2.6 Risk Scoring (`internal/scoring`)

```
Risk Score = Severity(CVSS) × Reachability × Exposure × Criticality
```

| Factor | Range | Source |
|--------|-------|--------|
| Severity | 0.0 – 10.0 | CVSS v3.1 base score from Grype/NVD |
| Reachability | 0.1 (unreachable) or 1.0 (reachable) | Reachability + taint engine |
| Exposure | 0.5 (internal) – 1.5 (internet-facing) | Asset metadata |
| Criticality | 0.5 (sandbox) – 2.0 (production-tier-0) | Asset tagging |

### 2.7 Quality Gates (`internal/quality`)

Deterministic function: `Evaluate(findings, policy) → Decision`. The CLI returns:
- Exit `0` — pass
- Exit `1` — warn (policy triggered but not blocking)
- Exit `2` — fail (critical findings or policy violation)

Three built-in policies: `strict`, `moderate`, `permissive`. Custom policies via YAML.

### 2.8 Remediation (`internal/remediation/pkg`)

Go-native package-level remediation. Groups findings by package, detects ecosystem (npm, pip, maven, go, cargo, nuget), and generates:
- Priority ranking (P0 fix-immediately through P3 monitor)
- Upgrade commands per package manager
- Quick-fix mode for P0/P1 packages only

### 2.9 Report Generation (`internal/report`)

Outputs findings in multiple formats:
- **Markdown** — per-finding report with executive summary
- **SARIF** — for CI platform integration
- **DOCX** — via Pandoc (graceful degradation if not installed)

### 2.10 MCP Server (`internal/mcp`)

Stdio-based MCP server for Claude Code integration. Exposes 5 tools:

| Tool | Maps to |
|------|---------|
| `init_engagement` | Engagement directory bootstrap |
| `scan_repository` | Full SCA + SAST + reachability pipeline |
| `generate_sbom` | CycloneDX SBOM via Syft |
| `run_gate` | Quality gate evaluation |
| `generate_report` | Markdown/DOCX report generation |

### 2.11 Supporting Packages

| Package | Purpose |
|---------|---------|
| `internal/config` | Viper-based configuration (YAML + env vars) |
| `internal/models` | Domain models (Finding, Asset, SBOM, Severity) |
| `internal/suppress` | `.supplychain-ignore` parser and matcher |
| `internal/graph` | Dependency graph visualization (DOT, Mermaid, ASCII) |
| `internal/license` | License compliance scanning and policy evaluation |
| `internal/defectdojo` | DefectDojo API client (optional push) |
| `internal/deptrack` | Dependency-Track API client (optional push) |

## 3. Data flow

A typical scan via `supplychain-kit run myapp --repo /path/to/project`:

```
1. Init          → Create results/myapp/ directory structure + state.json
2. SBOM          → syft generates CycloneDX 1.5 JSON
3. CVE matching  → grype matches SBOM against vulnerability database
4. SAST          → semgrep scans code with 32+ security rules
5. Secrets       → gitleaks scans for hardcoded credentials
6. Reachability  → joern CPG loaded, paths traced from sources to sinks
7. Taint         → user input traced to vulnerable code, false positives pruned
8. Correlation   → all findings normalized and de-duplicated
9. Scoring       → each finding annotated with risk score
10. Gate         → findings evaluated against policy → PASS/WARN/FAIL
11. Report       → markdown report saved to results/myapp/report.md
```

## 4. Claude Code integration

supplychain-kit runs as an MCP server inside Claude Code sessions. The orchestrator agent (`.claude/agents/orchestrator.md`) coordinates the pipeline via MCP tools, while the executor agent (`.claude/agents/executor.md`) handles domain-specific triage.

A knowledge base of 7 documents (`.claude/skills/supplychain-kit/knowledge/`) provides domain context for reachability decisions, remediation commands per ecosystem, and supply chain attack patterns.

Companion skills from Trail of Bits extend analysis:
- `supply-chain-risk-auditor` — maintainer risk + takeover detection
- `static-analysis` — CodeQL + Semgrep + SARIF triage
- `semgrep-rule-creator` — custom rule authoring

## 5. Concurrency model

All scanners run via Go goroutines within the CLI process. The orchestrator uses per-adapter semaphores (`max_parallel_syft`, `max_parallel_grype`, etc.) to bound concurrent IO. Correlation is idempotent on fingerprint, so repeated runs produce consistent results.

## 6. Failure modes

| Failure | Mitigation |
|---------|------------|
| Scanner CLI not installed | Adapter returns `ErrBinaryNotFound`, scan continues without that scanner |
| Joern CPG too large for memory | Results streamed line-by-line; graceful degradation to `ReachUnknown` |
| Grype DB stale | Self-checks DB age on startup, warns if older than 24h |
| Pandoc not installed | DOCX generation skipped, Markdown report still produced |

## 7. Extension points

- **New scanner:** implement `internal/scanner.Scanner`, register in `internal/scanner/registry.go`.
- **New taint source pattern:** add detection rules in `internal/taint/source_detector.go`.
- **New sanitizer:** add to the registry in `internal/taint/sanitizer.go`.
- **New report format:** add renderer in `internal/report/`.
- **New quality policy:** add YAML file in `configs/`.
- **New MCP tool:** add definition + handler in `internal/mcp/server.go`.

## 8. Out of scope

- DAST — the platform consumes DAST findings via DefectDojo import, but does not run DAST scanners.
- Cloud workload protection — delegated to existing CWPP tools.
- Secret rotation — Gitleaks discovers secrets; rotation is delegated to the customer's IAM/secret manager.
- Database / REST API / server mode — removed in v0.6 CLI consolidation. All features are CLI-only.
