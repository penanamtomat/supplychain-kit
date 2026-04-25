# Development Plan — supplychain-kit

> Referensi: [PRD](./Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md) · [ARCHITECTURE.md](../ARCHITECTURE.md)

`supplychain-kit` adalah **open-source CLI tool** untuk supply chain scanning (SCA) dan static analysis (SAST) — dijalankan langsung di device lokal developer atau di pipeline CI tanpa ketergantungan pada server, database, atau Docker.

**Prinsip pengembangan:** CLI-only, standalone (tanpa database, Redis, atau Docker), satu binary (`supplychain-kit`), engine berfungsi penuh sebelum integrasi eksternal ditambahkan.

---

## 🗓️ Roadmap ke Public Release — Target: 19 Juni 2026

> 55 hari tersisa. Prioritas: polish yang sudah ada, selesaikan fitur kritis yang masih unchecked, siapkan distribusi dan dokumentasi.

### Fase 1 — Engine Completion (26 Apr – 18 Mei)

| Item | Target | Prioritas |
|------|--------|-----------|
| Report generation: Markdown + DOCX | 5 Mei | 🔴 Kritis |
| `supplychain-kit init` + `run` one-liner | 5 Mei | 🔴 Kritis |
| Python taint analysis (Joern Python frontend) | 12 Mei | 🔴 Kritis |
| JavaScript/TypeScript taint support | 18 Mei | 🟡 Tinggi |
| Two-tier agent architecture (orchestrator + executor) | 18 Mei | 🟡 Tinggi |

**Alasan fase ini kritis:** Report generation + `run` one-liner adalah yang pertama dilihat user baru. Python taint adalah differentiator terkuat — mayoritas supply chain attack vector ada di Python (PyPI, ML tooling).

### Fase 2 — Distribution & Polish (19 Mei – 8 Juni)

| Item | Target | Prioritas |
|------|--------|-----------|
| Binary release via goreleaser (Linux/macOS, amd64/arm64) | 25 Mei | 🔴 Kritis |
| Homebrew formula | 1 Juni | 🟡 Tinggi |
| GitHub Actions reusable workflow (`uses: supplychain-kit/action@v1`) | 1 Juni | 🟡 Tinggi |
| VEX report CSAF 2.0 | 5 Juni | 🟡 Tinggi |
| README: demo GIF, arsitektur diagram, quick-start 3 langkah | 8 Juni | 🔴 Kritis |
| `CONTRIBUTING.md`, `SECURITY.md`, issue templates | 8 Juni | 🟢 Normal |

### Fase 3 — Final Hardening (9–19 Juni)

| Item | Target | Prioritas |
|------|--------|-----------|
| Bug fix dari rc testing | 15 Juni | 🔴 Kritis |
| Man page + `--help` yang informatif | 15 Juni | 🟢 Normal |
| SLSA level check, NIST SSDF compliance output | 17 Juni | 🟡 Tinggi |
| Full end-to-end demo test (real repo scan → report) | 18 Juni | 🔴 Kritis |
| Tag `v1.0.0`, push goreleaser release | 19 Juni | 🔴 Kritis |

---

## Status Saat Ini — v0.9 ✅ + v0.9.5 (In Progress)

- v0.9 selesai: taint analysis engine (TaintContext, PathPruner, SanitizerRegistry), SARIF output, `.supplychain-ignore` suppression, goreleaser config
- v0.9.5 in progress: report generation, `init`/`run` commands, Python taint support

- v0.6 selesai: reachability engine fix, CLI consolidation (hapus server/worker), static CPG via Joern, e2e gate tests
- v0.7 hampir selesai: Dependency-Track CLI, DefectDojo CLI, scanner expansion (Trivy + osv-scanner)
- v0.7 **SELESAI** — semua item sudah di-checklist

---

## v0.3 — SCA Pipeline Berfungsi Penuh ✅

**Tujuan:** `supplychain-kit scan --mode sca` menghasilkan laporan dependency vulnerability yang akurat dari repositori nyata.

Supply chain scanning adalah inti dari tools ini: siapa saja yang bergantung pada library apa, dan apakah library tersebut mengandung CVE yang diketahui.

### Perbaikan Pipeline Syft → Grype

- [x] Pisahkan eksekusi scanner menjadi dua fase di orchestrator
- [x] Pass SBOM path dari hasil syft ke `Request.SBOMPath` sebelum grype dijalankan

### Flag `--mode` pada CLI Scan

- [x] `--mode sca` — hanya jalankan syft + grype
- [x] `--mode sast` — hanya jalankan semgrep + gitleaks
- [x] `--mode all` — jalankan semua scanner (default)

### Output yang Bisa Dibaca Manusia

- [x] Default output: ringkasan ke stderr (jumlah finding per severity)
- [x] `--format json` — full findings JSON ke stdout/file
- [x] `--format table` — tabel temuan ke stdout
- [x] Exit code: `0` jika tidak ada Critical/High, `1` jika ada High, `2` jika ada Critical

### Command `supplychain-kit sbom`

- [x] `supplychain-kit sbom --repo <path> --out sbom.json`
- [x] Support `--format spdx`

### Test

- [x] Test pipeline SCA end-to-end
- [x] Test bahwa grype tidak berjalan jika syft gagal
- [x] Test flag `--mode sca`

---

## v0.4 — SAST Pipeline Berfungsi Penuh ✅

**Tujuan:** `supplychain-kit scan --mode sast` menghasilkan temuan code vulnerability dan secret dari repositori nyata.

### Semgrep Integration

- [x] Verifikasi `semgrep --json` output parsing terhadap versi semgrep terkini (1.75+)
- [x] Flag `--semgrep-config <rule>`
- [x] Filtering direktori `vendor/`, `node_modules/`, `.git/`
- [x] Deduplikasi findings

### Gitleaks Integration

- [x] Mode `--no-git`: scan working directory tanpa git history
- [x] Mode `--git-history`: scan git history untuk secret
- [x] Support `.gitleaksignore`

### Output Gabungan SCA + SAST

- [x] `supplychain-kit scan --mode all` menampilkan ringkasan gabungan
- [x] Setiap finding menampilkan link ke dokumentasi atau advisory

### Test

- [x] Test semgrep parsing terhadap fixture berbagai severity
- [x] Test gitleaks parsing terhadap fixture secret
- [x] Test deduplication

---

## v0.5 — Quality Gate & CI Integration ✅

**Tujuan:** Tools bisa menjadi penjaga (gate) di pipeline CI dengan satu perintah.

### CLI `gate` Command

- [x] `supplychain-kit gate --findings <file.json>`
- [x] Default policy: fail jika ada Critical, warn jika ada High
- [x] `--policy <file.yaml>`
- [x] Exit code: `0` (pass), `1` (warn), `2` (fail)

### Template Policy

- [x] `configs/policy-strict.yaml`
- [x] `configs/policy-moderate.yaml`
- [x] `configs/policy-permissive.yaml`

### Pipeline One-liner

- [x] `supplychain-kit scan --repo . --format json | supplychain-kit gate`
- [x] Contoh GitHub Actions snippet di README
- [x] Contoh GitLab CI snippet di README

### Test

- [x] Test gate dengan findings fixture Critical → exit 2
- [x] Test gate dengan findings fixture High → exit 1
- [x] Test gate dengan findings kosong → exit 0

---

## v0.6 — Reachability Engine + CLI Consolidation

**Tujuan:** Perbaiki bug reachability engine dan konsolidasi ke CLI-only (hapus semua kode server/worker).

### Bug Fixes Reachability

- [x] Fix `minConfidence` logic terbalik di `internal/reachability/engine.go` — ganti `min` → `max`, cap `0.95`
- [x] Wire reachability engine ke CLI `scan` command di `cmd/supplychain-kit/main.go` (tambahkan `reach.Analyze()` setelah `correlation.Merge()`)

### CLI Consolidation (Hapus Non-CLI)

- [x] Hapus `cmd/aspm-api/` (REST API server)
- [x] Hapus `cmd/aspm-scanner/` (worker/server mode)
- [x] Hapus semua Redis dependency dari `go.mod`
- [x] Hapus `internal/api/`, `internal/ingestion/`, `internal/storage/` (server-only packages)
- [x] Strip HTTP handler dari `internal/agenticsast/` (pertahankan `Analyse()` untuk v0.8)
- [x] Update README: hapus referensi server mode, fokus pada CLI usage

### Static Reachability (CPG via Joern) — sudah diimplementasikan, perbaiki saja

- [x] Parser CPG GraphSON JSON dari export Joern
- [x] Graph traversal dari first-party sources ke third-party sinks
- [x] Ekstraksi sinks dari affected function symbols di metadata Grype
- [x] Output per finding: `reachable bool`, `confidence float64`, `path []string`
- [x] Fallback: jika Joern tidak tersedia, default `reachable = unknown`

### Risk Score

- [x] Reachability multiplier terintegrasi ke scoring: `0.1` (unreachable) atau `1.0` (reachable)
- [x] Output tabel menampilkan kolom `reachable` dan `risk_score`

### eBPF Runtime Confirmation _(opsional, Linux kernel 5.8+)_

- [x] Interface `RuntimeConfirmer` di `internal/reachability/`
- [x] Graceful degradation jika tidak tersedia

### Test

- [x] Tambah regression test `TestCapConfidence_IncreasesWithMoreImports` — membuktikan confidence naik sesuai jumlah import
- [x] Test end-to-end: `scan → gate → exit code` benar (`internal/quality/e2e_test.go` — 6 skenario: critical/high/low/empty/mixed/reachability policy)

---

## v0.7 — Dependency Tracking & DefectDojo CLI

**Tujuan:** `supplychain-kit` bisa push hasil scan ke Dependency-Track dan DefectDojo langsung dari CLI, tanpa server atau database lokal.

### Dependency-Track CLI

- [x] `supplychain-kit deptrack upload --url <dt-url> --api-key <key> --sbom sbom.json` — upload SBOM ke Dependency-Track
- [x] `supplychain-kit deptrack status --url <dt-url> --api-key <key> --project <id>` — polling status vulnerability
- [x] `supplychain-kit deptrack sync --repo .` — kombinasi: scan SBOM lalu langsung upload
- [x] Support konfigurasi via `configs/aspm.yaml` (url, api-key, project-id)
- [x] Graceful degradation: jika Dependency-Track tidak tersedia, lanjut tanpa error fatal

### DefectDojo CLI

- [x] `supplychain-kit defectdojo push --url <url> --api-key <key> --findings findings.json`
- [x] Map normalized findings ke DefectDojo finding format
- [x] Support `--engagement-id` dan `--product` sebagai parameter

### Scanner Expansion — Trivy & osv-scanner

- [x] `internal/scanner/trivy/trivy.go` — adapter untuk `trivy fs` / `trivy sbom`, parse JSON output Trivy
- [x] `internal/scanner/osvscanner/osvscanner.go` — adapter untuk `osv-scanner --recursive` / `--sbom`, parse OSV JSON output
- [x] `SourceTrivy` dan `SourceOSVScanner` ditambahkan ke models
- [x] Kedua adapter terdaftar di `sca` mode dan `all` mode di `buildRegistry`
- [x] `scan --mode sca` menjalankan 4 scanner: syft → grype → trivy → osv-scanner
- [x] Graceful degradation via `ErrBinaryNotFound` — scanner yang tidak terinstall di-skip dengan warning

### Test

- [x] Mock HTTP tests: `internal/deptrack/client_test.go` — 5 test cases (EnsureProject existing/create, UploadBOM, GetFindings, HTTP error)
- [x] Mock HTTP tests: `internal/defectdojo/client_test.go` — 4 test cases (EnsureEngagement, PushFindings, empty findings, HTTP error)
- [x] Test `sync` command end-to-end dengan syft terinstall (`internal/deptrack/sync_e2e_test.go` — real syft + mock DT server, SBOM 204KB)

---

## v0.8 — Claude Code Integration (Agentic Supply Chain Security)

**Tujuan:** `supplychain-kit` berjalan sepenuhnya sebagai agentic tool di dalam Claude Code — user cukup berikan engagement name dan path repo, Claude otomatis menjalankan seluruh pipeline scan, analisis, dan laporan. Cocok untuk semua persona: developer, security engineer, AI/ML engineer — baik yang sedang membangun product maupun yang sudah ship ke production.

**Referensi desain:** Terinspirasi dari tooling pentest profesional dengan adaptasi ke domain supply chain: bukan active attack, tapi contextual risk analysis — "CVE ini di mana, seberapa bahaya untuk kode KAMU, dan bagaimana fix-nya."

**Target:** Public release v1.0 dengan distribusi komunitas open-source.

**Catatan Penting:**
- API remediation Claude terpisah (`--ai` flag) telah digantikan dengan template-based remediation (internal/remediation)
- Gunakan template-based sebagai default untuk analisis findings
- Claude Code session analysis (Opsi 3 di bawah) adalah fitur opsional untuk improvement masa depan

---

### 1. MCP Server (Prioritas Utama — Entry Point Otomasi)

MCP adalah backbone utama v0.8. Semua otomasi Claude Code mengalir melalui ini.

- [x] `supplychain-kit mcp` — jalankan sebagai MCP server (stdio transport) — `internal/mcp/server.go`
- [x] Tool `init_engagement` — buat engagement baru: nama, repo path, policy, output dir
- [x] Tool `scan_repository` — jalankan full pipeline scan (SCA + SAST + reachability), return structured findings
- [x] Tool `generate_sbom` — hasilkan SBOM dari repo (Syft), return path + summary
- [x] Tool `run_gate` — evaluasi findings terhadap policy, return pass/warn/fail + violations
- [ ] Tool `analyze_finding` — analisis satu finding dengan template-based remediation, return explanation + fix suggestion
- [x] Tool `generate_report` — render findings ke Markdown report, simpan ke engagement dir
- [x] Setiap tool return structured JSON: `{status, data, summary, errors}`
- [x] Registrasi otomatis: generate `~/.claude/mcp.json` snippet via `supplychain-kit mcp --print-config`

---

### 2. Two-Tier Agent Architecture

Mengikuti pola Orchestrator + Executor dari pentest-kit, diadaptasi ke supply chain workflow.

- [x] `.claude/agents/orchestrator.md` — Orchestrator agent: koordinasi full engagement workflow
  - Terima: engagement name, repo path, optional policy + mode
  - Jalankan fase secara berurutan via MCP tools: Init → SBOM → Scan → Gate → Analyze → Report
  - Monitor progress, handle error gracefully, ringkaskan hasil ke user
  - **Tidak pernah** jalankan binary langsung — semua via MCP tools
- [x] `.claude/agents/executor.md` — Executor agent: spesialis per domain (SCA, SAST, Analysis)

---

### 3. Custom Claude Code Skill `/security-scan`

Slash command yang mengaktifkan full agentic workflow dari Claude Code chat.

- [x] `.claude/skills/supplychain-kit/` — skill sudah terinstall dan berfungsi via `/supplychain-kit`
  - [x] Prompt user untuk: engagement name, repo path, scan mode
  - [x] Policy preset support
  - [x] Summary report di akhir pipeline
- [ ] Onboarding flow improvement — two-tier orchestrator/executor agent pattern

---

### 4. Knowledge Base (Dynamic — `.claude/skills/supplychain-kit/knowledge/`)

Knowledge base dinamis yang meningkat seiring perkembangan ancaman. Mencakup semua persona (developer, security engineer, AI/ML engineer).

- [x] `supply-chain-attacks.md` — pola serangan supply chain: dependency confusion, typosquatting, malicious package injection, protestware
- [x] `cve-severity-guide.md` — cara baca CVSS, kapan CVE kritis vs dapat ditoleransi, konteks reachability
- [x] `remediation-by-ecosystem.md` — playbook fix per ekosistem: npm, pip, Go, Maven, Cargo
- [x] `sbom-formats.md` — CycloneDX vs SPDX, kapan pakai mana, compliance context (NTIA, EO 14028)
- [x] `ci-integration-patterns.md` — cara pasang gate di GitHub Actions, GitLab CI, Jenkins, ArgoCD
- [x] `ai-ml-supply-chain.md` — risiko khusus AI/ML engineer: model poisoning, malicious PyPI, dependency chain
- [x] `risk-scoring-explained.md` — penjelasan risk score supplychain-kit: CVSS × reachability × fix availability

---

### 5. `supplychain-kit init` Command

Command baru untuk bootstrap engagement.

- [x] `supplychain-kit init <engagement> --repo <path> [--policy <preset>] [--out <dir>]`
- [x] Buat struktur direktori: `results/<engagement>/findings/`, `reports/`, `sbom/`, `state.json`
- [x] `state.json`: track fase yang sudah selesai (Init → SBOM → SCA → SAST → Gate → Report)
- [ ] `supplychain-kit status <engagement>` — saat ini baca summary.json, perlu wire ke state.json untuk progress fase

---

### 6. Template-Based Remediation

- [x] `configs/report-templates/finding.md.tmpl` — template Markdown per finding dengan remediation section
- [x] Remediation priority dipengaruhi reachability:
  - `reachable: YES` → "Fix segera. Prioritas 1."
  - `reachable: NO` → "Fix di sprint berikutnya."
  - `reachable: UNKNOWN` → "Treat as reachable sampai terbukti sebaliknya."

---

### 7. Report Generation (Markdown + DOCX)

**Prinsip report:** Bahasa teknis penuh, remediation harus clear + actionable + lengkap.

- [x] `supplychain-kit report --engagement <name> --format markdown` — render per-finding Markdown
- [x] `supplychain-kit report --engagement <name> --format docx` — generate DOCX via Pandoc
- [x] `supplychain-kit report --engagement <name> --format all` — generate keduanya sekaligus
- [x] Template Markdown per finding (`configs/report-templates/finding.md.tmpl`) — sudah ada
- [x] Pandoc sebagai renderer DOCX dengan graceful degradation jika tidak terinstall
- [ ] `supplychain-kit report --check-deps` — verifikasi Pandoc terinstall
- [ ] Template DOCX cover page + appendix SBOM (saat ini hanya convert markdown ke docx)

---

### 8. Claude Code Hooks Templates

- [x] `configs/hooks/pre-commit.sh` — jalankan `supplychain-kit gate` sebelum commit, block jika Critical
- [x] `configs/hooks/post-scan.sh` — setelah scan, upload ke Dependency-Track (opsional)
- [x] `configs/hooks/claude-stop.sh` — hook untuk Claude Code `Stop` event
- [ ] Instruksi setup di README: cara register hook ke `.claude/settings.json`

---

### 9. Test

- [ ] Test MCP server: jalankan `supplychain-kit mcp` sebagai subprocess, kirim JSON-RPC request, validasi response
- [ ] Test `init` command: verifikasi struktur direktori dan `state.json` dibuat dengan benar
- [ ] Test `report` command: verifikasi Markdown + DOCX di-generate dari fixture findings
- [ ] Integration test skill + MCP: simulasikan full workflow dari skill invocation sampai report

---

## v0.9 — Taint Analysis Engine (Dependency-Aware SAST)

**Tujuan:** supplychain-kit mampu membuktikan apakah sebuah CVE di dependency benar-benar exploitable melalui kode user — bukan hanya "package ini vulnerable", tapi "user input dari endpoint ini bisa trigger CVE ini". Ini adalah fitur yang **tidak ada di tools open source manapun** saat ini.

**Konteks kompetitif:**
- Semgrep Supply Chain, Endor Labs, Snyk — semua berbayar/SaaS untuk fitur ini
- CodeQL bisa melakukan ini tapi butuh GitHub Advanced Security dan setup complex
- supplychain-kit akan menjadi satu-satunya standalone open-source CLI dengan kemampuan ini

**Fondasi yang sudah ada:** Joern CPG (Call Property Graph) sudah diimplementasikan di v0.6. Taint engine dibangun di atas infrastruktur yang sama.

**Status:** ✅ **COMPLETED** — Taint analysis engine fully implemented dan integrated.

### Taint Analysis Engine

- [x] `internal/taint/source_detector.go` — deteksi user-controlled input entry points:
  - [x] HTTP handler parameters (gin, echo, net/http, fasthttp, flask, express, spring, dll)
  - [x] Environment variables yang di-read ke variabel
  - [x] File read operations dengan path dari user
  - [x] CLI argument parsing
- [x] `internal/taint/propagator.go` — trace taint melalui call graph Joern:
  - [x] Forward propagation: dari source → melalui function calls → ke sink
  - [x] Sanitizer detection: input yang sudah di-validate/escape dianggap clean
  - [x] Inter-procedural: trace melewati function boundaries
- [x] `internal/taint/sink_matcher.go` — cocokkan tainted call dengan CVE sink symbols:
  - [x] Ambil affected function symbols dari metadata Grype/Trivy
  - [x] Match dengan node di CPG yang tainted
  - [x] Output: confirmed exploitable path dengan source → propagation chain → sink
- [x] Integrasi ke `scan` command: findings dengan confirmed taint path mendapat label `confirmed_exploitable`
- [x] Output di report:
  ```
  REACHABLE:    confirmed_exploitable
  RISK_SCORE:   95.00
  TAINT_PATH:   user_input → ... → torch.load
  ```

### Multi-Language Support (bertahap)

- [x] Go — via Joern Go frontend (sudah tersedia)
- [x] Python — source detection untuk Flask/FastAPI/Django ditambahkan ke source_detector.go
- [x] JavaScript/TypeScript — source detection untuk Express/Fastify/NestJS ditambahkan ke source_detector.go
- [ ] Java — via Joern Java frontend (belum)

### Test

- [x] Unit test source_detector: fixture HTTP handlers berbagai framework → detect sources correctly
- [x] Unit test propagator: fixture call graph dengan taint chain → propagasi benar
- [x] Unit test sink_matcher: fixture CVE sink symbols → match dengan CPG nodes
- [x] E2E test: repo dengan known vulnerable pattern → output `confirmed_exploitable` dengan path yang benar (`go test -tags integration`)

**Catatan Implementasi:**
- Engine menggunakan BFS untuk trace taint path dari sources ke sinks
- Mendukung sanitizer detection (validate, escape, filter, type_check)
- Reachability status baru: `ReachConfirmedExploit` untuk findings yang confirmed exploitable
- CPG loading mendukung directory format dari joern-export (~1, ~2 files)
- Report output menampilkan taint path dalam format `source → ... → sink`

---

## v0.9.5 — Report Generation + One-liner Workflow + Python Taint

**Tujuan:** Lengkapi output pipeline (report) dan sederhanakan UX menjadi satu perintah. Tambah Python taint untuk menjangkau supply chain ML/AI.

**Deadline fase ini: 18 Mei 2026**

### Report Generation

- [x] `supplychain-kit report --engagement <name> --format markdown` — sudah implemented
- [x] `supplychain-kit report --engagement <name> --format docx` — via Pandoc, sudah implemented
- [x] `supplychain-kit report --engagement <name> --format all` — sudah implemented
- [x] Template Markdown per finding (`configs/report-templates/finding.md.tmpl`) — sudah ada
- [x] Pandoc sebagai renderer DOCX — graceful degradation jika tidak terinstall
- [ ] Template cover page DOCX dan appendix SBOM

### `supplychain-kit init` + `supplychain-kit run`

- [x] `supplychain-kit init <engagement> --repo <path> [--policy <preset>] [--out <dir>]` — sudah implemented
  - [x] Buat struktur: `results/<engagement>/findings/`, `sbom/`, `reports/`, `state.json`
  - [x] `state.json` track fase: Init → SBOM → SCA → SAST → Gate → Report
- [x] `supplychain-kit run <engagement> --repo <path> --mode all` — sudah implemented sebagai one-liner
  - [x] Pipeline: scan → gate → report dalam satu command
  - [x] Progress output ke stderr, final summary ke stdout
- [ ] `supplychain-kit status <engagement>` — wire ke state.json (engageStatusCmd ada tapi belum baca state.json)

### Python Taint Analysis

- [x] Map Python HTTP framework sources: Flask `request.*`, FastAPI `Query()`/`Body()`, Django `request.GET/POST`
- [ ] Map Python sink patterns di `SanitizerRegistry`: `subprocess.run`, `eval`, `exec`, `pickle.loads`, `torch.load`, `yaml.load` sebagai non-sanitizer (dangerous)
- [ ] Test: fixture Flask app dengan known vulnerable pattern → detect taint path

### JavaScript/TypeScript Taint

- [x] Source patterns: Express `req.body`, `req.query`, `req.params` + NestJS decorators — ditambahkan ke source_detector.go
- [ ] Sink patterns di SanitizerRegistry: `eval`, `child_process.exec`, `dangerouslySetInnerHTML`

### Test

- [ ] Test `init` command: verifikasi struktur direktori dan `state.json`
- [ ] Test `report` command: fixture findings → validate Markdown output
- [ ] Test Python taint: fixture Flask app → confirmed_exploitable

---

## v1.0 — Production CLI

**Tujuan:** Stabil, terdokumentasi, siap digunakan komunitas luas.

**Deadline: 19 Juni 2026**

### Distribution

- [ ] Binary release via goreleaser — `.goreleaser.yaml` sudah ada, tinggal trigger
  - Linux/macOS, amd64/arm64 (Windows via WSL)
  - Cosign signing + SBOM per release (sudah di goreleaser config)
- [ ] Homebrew formula: `brew tap penanamtomat/tap && brew install supplychain-kit`
- [ ] GitHub Actions reusable workflow: `uses: penanamtomat/supplychain-kit/action@v1`
  - Input: `repo-path`, `mode`, `policy`, `fail-on`
  - Output: SARIF ke GitHub Security tab + summary comment di PR

### Compliance & Security Posture

- [ ] `supplychain-kit vex --tag v1.0.0` — VEX report CSAF 2.0
- [ ] Compliance output: NIST SSDF mapping, SLSA level check
- [ ] `supplychain-kit sign` — sign SBOM dengan cosign (sudah ada di goreleaser, expose ke CLI)

### Documentation

- [ ] README: demo GIF (asciinema), arsitektur diagram, quick-start 3 langkah
- [ ] Man page (`docs/supplychain-kit.1`)
- [ ] `--help` yang informatif: contoh command di setiap subcommand
- [ ] `CONTRIBUTING.md`, `SECURITY.md`, issue + PR templates
- [ ] `docs/ARCHITECTURE.md` — update diagram dengan komponen taint engine

### Final Hardening

- [ ] E2E demo test: scan real repo (supplychain-kit sendiri) → full report
- [ ] Benchmark: waktu scan repo 100K LOC < 60 detik (tanpa Joern)
- [ ] Tag `v1.0.0` + goreleaser release ke GitHub Releases

---

## Catatan Pengembangan

**Prinsip CLI-Only:**

- Satu binary: `supplychain-kit`
- Tidak ada REST API server, tidak ada Redis, tidak ada PostgreSQL, tidak ada Docker
- Semua fitur harus bisa dijalankan dengan `supplychain-kit <command>` tanpa dependensi runtime eksternal
- Integrasi eksternal (Dependency-Track, DefectDojo, Claude Code) bersifat opsional dan dikonfigurasi via `configs/aspm.yaml`

**Urutan prioritas engine:**
```
SCA (syft→grype→trivy→osv) → SAST (semgrep+gitleaks+joern) → Gate → Reachability → Dep Tracking → Claude Code MCP → AI Remediation
```

**Mode operasi yang didukung:**

| Mode | Kebutuhan | Cocok Untuk |
|------|-----------|-------------|
| Standalone | Binary CLI saja | Developer lokal, CI sederhana |
| With tracking | CLI + Dependency-Track/DefectDojo (opsional) | Tim, tracking vulnerability |
| Claude Code (Agentic) | CLI + MCP + Claude Code (v0.8+) | Full otomasi: init → scan → analyze → report tanpa intervensi manual |

**Target user (v0.8+):**

Semua persona engineer yang membangun atau sudah memiliki product software. Target user adalah engineer yang **sudah paham CVE dan security** — tools ini tidak menyederhanakan, tapi memperkuat kemampuan analisis mereka:
- **Developer** — prevention di awal development, pre-commit gate, tahu CVE mana yang benar-benar perlu di-fix sekarang
- **Security Engineer** — audit menyeluruh, policy enforcement, tracking CVE, reachability-aware triage
- **AI/ML Engineer** — risiko supply chain khusus ML: PyPI poisoning, model dependency chain, training pipeline attack surface

**Filosofi report:**
- Bahasa teknis penuh — tidak ada simplifikasi yang tidak perlu
- Remediation harus **clear, complete, dan actionable**: exact command, breaking changes, verify step
- Reachability mengubah prioritas remediation: `REACHABLE` → fix sekarang, `UNREACHABLE` → fix next sprint, `UNKNOWN` → treat as reachable
- Format dual: **Markdown** untuk terminal/GitHub/CI, **DOCX** via Pandoc untuk stakeholder/meeting

**Desain agentic workflow (v0.8):**
```
User: /security-scan
  → Skill tanya: engagement name, repo path, policy
  → Orchestrator agent jalankan via MCP:
      1. init_engagement  → buat struktur hasil
      2. generate_sbom    → SBOM dari repo
      3. scan_repository  → SCA + SAST + reachability
      4. run_gate         → evaluasi policy
      5. analyze_finding  → template-based remediation top-N findings
      6. generate_report  → Markdown report
  → User terima: summary + gate verdict + report path
```

_Pick any unchecked item, open an issue, and submit a PR to `dev`._

**Status v0.8:** Sebagian besar selesai — MCP server, knowledge base, skill, init command, report generation, hooks templates, two-tier agent files sudah implemented. Item yang masih pending: `analyze_finding` MCP tool, `status` command wire ke state.json, `report --check-deps`, template DOCX cover page.

---
