# Architecture — Integrated ASPM Platform

This document describes the technical architecture that implements the PRD ([docs/Product Requirements Document (PRD)_ Integrated Application Security Posture Management (ASPM) Platform.md](docs/Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md)). It is the authoritative reference for component boundaries, data flow, and extension points.

## 1. Design principles

1. **Scan-once, monitor-always.** SBOMs are generated on commit and persisted; CVE matching is a database join, not a re-scan.
2. **Reachability over severity.** A `Critical` CVE in unreachable code is downgraded; an `Info` finding on a hot path is escalated. The risk score expresses this.
3. **Adapter-first scanners.** Every scanner is a thin adapter behind a Go interface, so swapping Semgrep for CodeQL is a config change, not a refactor.
4. **Deterministic gates.** Quality gates take a normalized finding set as input and produce a binary pass/fail with a deterministic explanation.
5. **Human-in-the-loop remediation.** Remediation agents propose, never apply. Production-critical branches require Security Champion approval.

## 2. System components

```
                  ┌─────────────────────┐
                  │  Git Providers      │
                  │  (GitHub / GitLab / │
                  │   Bitbucket)        │
                  └──────────┬──────────┘
                             │ webhook (push, PR)
                             ▼
                  ┌─────────────────────┐
                  │  Ingestion Layer    │
                  │  internal/ingestion │
                  └──────────┬──────────┘
                             │ scan job (Redis)
                             ▼
┌──────────────┐   ┌────────────────────┐   ┌──────────────────┐
│  CLI / CI    │──►│  Scanner Worker    │──►│  Scanner Adapters│
│  supplychain-kit    │   │  cmd/aspm-scanner  │   │  syft / grype /  │
└──────────────┘   └──────────┬─────────┘   │  semgrep / joern │
                              │             │  / gitleaks      │
                              │             └────────┬─────────┘
                              │                      │
                              ▼                      ▼
                  ┌────────────────────────────────────────┐
                  │  Correlation & Normalization           │
                  │  internal/correlation                  │
                  │   - de-dup across scanners             │
                  │   - DefectDojo-shape common schema     │
                  └──────────────────┬─────────────────────┘
                                     │
                                     ▼
                  ┌────────────────────────────────────────┐
                  │  Reachability Engine                   │
                  │  internal/reachability                 │
                  │   - CPG path search (Joern export)     │
                  │   - eBPF runtime confirmation          │
                  └──────────────────┬─────────────────────┘
                                     │
                                     ▼
                  ┌────────────────────────────────────────┐
                  │  Risk Scoring Engine                   │
                  │  internal/scoring                      │
                  │   Score = CVSS × Reach × Exp × Crit    │
                  └──────────────────┬─────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
   ┌───────────────────┐  ┌───────────────────┐  ┌────────────────────┐
   │  PostgreSQL       │  │  REST API         │  │  Remediation Layer │
   │  internal/storage │  │  cmd/aspm-api     │  │  remediation/      │
   │  - assets         │  │  - findings       │  │  - LLM PR agent    │
   │  - findings       │  │  - dashboards     │  │  - Renovate logic  │
   │  - sboms / cpg    │  │  - quality gate   │  │  - VEX (CSAF 2.0)  │
   └───────────────────┘  └───────────────────┘  └────────────────────┘
```

### 2.1 Ingestion Layer (`internal/ingestion`)

- HMAC-verified webhook receivers for GitHub, GitLab, Bitbucket.
- Translates provider-specific events into a `ScanRequest{repo, ref, trigger}` enqueued on Redis.
- Maintains the asset inventory (Goal: 100% real-time visibility).

### 2.2 Scanner Worker (`cmd/aspm-scanner`)

- Long-running worker that consumes Redis jobs and fans out to adapters concurrently (Go goroutines, bounded by per-tool semaphores).
- Each adapter implements:
  ```go
  type Scanner interface {
      Name() string
      Scan(ctx context.Context, req ScanRequest) (Result, error)
  }
  ```
- The worker invokes the underlying CLI (`syft`, `grype`, `semgrep`, `gitleaks`) directly when present; otherwise it shells into the official OCI image. This keeps the worker self-contained on developer laptops and bullet-proof in CI.

### 2.3 Correlation & Normalization (`internal/correlation`)

- Maps each adapter's native output into a common `models.Finding` shape (compatible with the DefectDojo "Generic Findings" import schema for interoperability).
- De-duplicates by `(rule_id, file_path, line, package, version)` fingerprint. SAST/DAST findings pointing at the same root cause merge into one record with multiple `Sources`.
- Persists raw outputs alongside the normalized record for audit and re-correlation.

### 2.4 Reachability Engine (`internal/reachability`)

- Static path: ingests CPG exports from Joern (`graphson` JSON), traverses from first-party "sources" (controllers, message handlers) to "sinks" (vulnerable function symbols extracted from the CVE's affected ranges).
- Runtime path: optional eBPF sensor stream (uprobes on shared library entry points) confirming a library is *actually* loaded into the running process address space. Confirmed reachability locks the multiplier to `1.0`.
- Trade-off (per PRD §7): dynamic-language call resolution is best-effort. The engine emits a `confidence` value so consumers can decide how to weight it.

### 2.5 Risk Scoring (`internal/scoring`)

Implements:

```
Risk Score = Severity(CVSS) × Reachability × Exposure × Criticality
```

| Factor | Range | Source |
| --- | --- | --- |
| Severity | 0.0 – 10.0 | CVSS v3.1 base score from Grype / NVD |
| Reachability | 0.1 (unreachable) or 1.0 (reachable / eBPF confirmed) | Reachability engine |
| Exposure | 0.5 (internal) – 1.5 (internet-facing) | Asset metadata |
| Criticality | 0.5 (sandbox) – 2.0 (production-tier-0) | Asset tagging |

Output is normalized to a 0–100 risk score with a categorical label for dashboards.

### 2.6 Quality Gates (`internal/quality`)

A gate is a deterministic function `Evaluate(findings, policy) -> Decision`. Decisions carry the violating findings so CI can render a useful failure log. The CLI returns exit code `2` for fail and `1` for warn so that pipelines distinguish "block the merge" from "annotate the PR."

### 2.7 Remediation Layer (`remediation/`)

A separate Python service because the ecosystem for LLM orchestration, CSAF tooling, and dependency-resolver libraries (e.g., `pip-tools`, `npm-check-updates`, `dependabot-core` ports) is markedly stronger than in Go.

- **Renovate-compatible agent** (`remediation/agents/renovate_agent.py`): given a vulnerable `(package, version_range)`, computes the nearest non-vulnerable upgrade that satisfies the manifest's existing constraints, then opens a PR via the relevant Git provider API.
- **LLM remediation agent** (`remediation/agents/llm_agent.py`): for first-party SAST findings (e.g., a Semgrep `tainted-sql-string` rule), prompts a Claude or OpenAI model with the function body + rule explanation and proposes a refactor. Always surfaced as a PR review comment, never auto-merged.
- **VEX generator** (`remediation/reports/vex_generator.py`): emits CSAF 2.0 Profile 5 documents using CISA status justifications:
  - `vulnerable_code_not_present` — the reachability engine proved the path is dead.
  - `inline_mitigation_already_exist` — a WAF rule or compensating control is registered.
  - `vulnerable_code_cannot_be_controlled_by_adversary` — input source is trusted and authenticated.

### 2.8 REST API (`cmd/aspm-api`)

- `chi`-based HTTP router, OpenAPI 3.1 spec generated at build time.
- JWT auth (issuer pluggable: OIDC, GitHub OAuth).
- Endpoints (selected):
  - `POST /api/v1/scans` — kick off a scan
  - `GET  /api/v1/findings` — paginated, filterable
  - `GET  /api/v1/assets/{id}/risk` — current rolled-up risk
  - `POST /api/v1/quality-gate/evaluate` — synchronous gate check
  - `POST /api/v1/vex` — request a VEX document for a release tag

### 2.9 Storage (`internal/storage`)

PostgreSQL 16 with the schema in [migrations/](migrations/). Highlights:

- `assets` — repos, services, deployments; tagged with `environment`, `tier`, `internet_facing`.
- `sboms` — full CycloneDX 1.5 documents stored as `JSONB`, indexed by purl on a side table for fast CVE matching.
- `findings` — normalized findings with FKs to assets and sboms; carries `risk_score`, `reachable`, `vex_status`.
- `cpg_metadata` — Joern CPG export pointers (large blobs live in object storage).
- `scan_runs` — provenance for SLSA + audit.

## 3. Data flow walkthrough

A typical scan of a feature branch:

1. Developer pushes to `feature/payments`. GitHub fires a webhook.
2. Ingestion validates the HMAC and enqueues `ScanRequest`.
3. Scanner worker fans out: Syft generates an SBOM, Grype matches it, Semgrep + Gitleaks run in parallel against the checkout, Joern produces a CPG when configured.
4. Correlation normalizes every adapter output into `models.Finding` and stores raw + normalized to Postgres.
5. Reachability engine reads the CPG and, for each Grype hit, walks from sources to the affected symbol. If eBPF telemetry exists for the asset, it overrides the static verdict.
6. Scoring annotates each finding with the integrated risk score.
7. Quality Gate runs against the policy attached to the asset; if the PR violates, the CLI exits non-zero, blocking the merge.
8. For new findings above the auto-remediation threshold, the remediation service either opens a Renovate-style PR (SCA) or a Claude-authored review comment (SAST).
9. On release tag, `supplychain-kit vex --tag v1.4.0` emits a CSAF 2.0 document signed and published as a GitHub Release artifact.

## 4. Concurrency model

- **Scanner worker:** one goroutine per scan job, with a per-adapter semaphore (`max_parallel_syft`, etc.) to avoid IO storms. Jobs are at-least-once; correlation is idempotent on `(scan_run_id, fingerprint)`.
- **API:** stateless; horizontally scalable behind a load balancer.
- **Remediation:** FastAPI + `asyncio`; LLM calls are streamed and cached in Redis keyed by `(rule_id, code_hash)` to avoid duplicate spend.

## 5. Failure modes & mitigations

| Failure | Mitigation |
| --- | --- |
| CPG too large to fit in memory | Joern runs in a sidecar container with its own memory budget; results streamed line-by-line. |
| LLM provider outage | Remediation agent degrades to "suggest dependency upgrade only" mode and surfaces a banner on the dashboard. |
| Webhook flood from monorepo | Ingestion debounces by `(repo, ref)` for a configurable window (default 30s). |
| Grype DB stale | Scanner worker self-checks DB age on startup and refuses to run if older than 24h unless `--allow-stale-db`. |

## 6. Extension points

- **New scanner:** implement `internal/scanner.Scanner`, register it in [internal/scanner/registry.go](internal/scanner/registry.go).
- **New risk factor:** add a column to `findings`, extend [internal/scoring/scorer.go](internal/scoring/scorer.go), and bump the policy version.
- **New compliance report:** add a Python module under `remediation/reports/` and a CLI subcommand; the underlying normalized data model already covers SSDF, SLSA, and SCVS attributes.

## 7. Out of scope (explicitly)

- DAST (the platform consumes DAST findings via DefectDojo import, but does not run a DAST scanner itself).
- Cloud workload protection (delegated to existing CWPP tools; this platform consumes their alerts as additional `Source` entries on a finding).
- Identity/secret rotation (Gitleaks discovers; rotation is delegated to the customer's IAM/secret manager).
