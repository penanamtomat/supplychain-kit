# Development Plan — supplychain-kit

> Referensi: [PRD](./Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md) · [ARCHITECTURE.md](../ARCHITECTURE.md)

`supplychain-kit` adalah **open-source CLI tool** untuk supply chain scanning (SCA) dan static analysis (SAST) — dijalankan langsung di device lokal developer atau di pipeline CI tanpa ketergantungan pada server, database, atau Docker.

**Prinsip pengembangan:** CLI-only, standalone (tanpa database, Redis, atau Docker), satu binary (`supplychain-kit`), engine berfungsi penuh sebelum integrasi eksternal ditambahkan.

---

## Status Saat Ini — v0.7 (In Progress)

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

**Referensi desain:** Terinspirasi dari pentest-kit (BlackHat-level tool) dengan adaptasi ke domain supply chain: bukan active attack, tapi contextual risk analysis — "CVE ini di mana, seberapa bahaya untuk kode KAMU, dan bagaimana fix-nya."

**Target publikasi:** BlackHat Europe (proposal level)

**Catatan Penting:**
- API remediation Claude terpisah (`--ai` flag) telah digantikan dengan template-based remediation (internal/remediation)
- Gunakan template-based sebagai default untuk analisis findings
- Claude Code session analysis (Opsi 3 di bawah) adalah fitur opsional untuk improvement masa depan

---

### 1. MCP Server (Prioritas Utama — Entry Point Otomasi)

MCP adalah backbone utama v0.8. Semua otomasi Claude Code mengalir melalui ini.

- [ ] `supplychain-kit mcp` — jalankan sebagai MCP server (stdio transport)
- [ ] Tool `init_engagement` — buat engagement baru: nama, repo path, policy, output dir
- [ ] Tool `scan_repository` — jalankan full pipeline scan (SCA + SAST + reachability), return structured findings
- [ ] Tool `generate_sbom` — hasilkan SBOM dari repo (Syft), return path + summary
- [ ] Tool `run_gate` — evaluasi findings terhadap policy, return pass/warn/fail + violations
- [ ] Tool `analyze_finding` — kirim satu finding ke Claude API, terima AI explanation + remediation suggestion
- [ ] Tool `generate_report` — render findings ke Markdown report, simpan ke engagement dir
- [ ] Setiap tool return structured JSON: `{status, data, summary, errors}`
- [ ] Registrasi otomatis: generate `~/.claude/mcp.json` snippet via `supplychain-kit mcp --print-config`

---

### 2. Two-Tier Agent Architecture

Mengikuti pola Orchestrator + Executor dari pentest-kit, diadaptasi ke supply chain workflow.

- [ ] `.claude/agents/orchestrator.md` — Orchestrator agent: koordinasi full engagement workflow
  - Terima: engagement name, repo path, optional policy + mode
  - Jalankan fase secara berurutan via MCP tools: Init → SBOM → Scan → Gate → Analyze → Report
  - Monitor progress, handle error gracefully, ringkaskan hasil ke user
  - **Tidak pernah** jalankan binary langsung — semua via MCP tools
- [ ] `.claude/agents/executor.md` — Executor agent: spesialis per domain
  - SCA Executor: orchestrate syft → grype → trivy → osv-scanner
  - SAST Executor: orchestrate semgrep + gitleaks + joern
  - Analysis Executor: kirim findings ke Claude API untuk AI remediation

---

### 3. Custom Claude Code Skill `/security-scan`

Slash command yang mengaktifkan full agentic workflow dari Claude Code chat.

- [ ] `.claude/skills/security-scan/SKILL.md` — entry point skill
  - Prompt user untuk: engagement name, repo path, scan mode (`sca`/`sast`/`all`/`full`)
  - Optional: policy preset (`strict`/`moderate`/`permissive`), output format
  - Panggil Orchestrator agent, tampilkan progress live ke user
  - Tampilkan summary report di akhir: total findings, top CVEs, gate result, path ke report
- [ ] Onboarding flow mirip pentest-kit:
  1. User: `/security-scan`
  2. Skill tanya: engagement name? repo path? policy?
  3. Claude jalankan full pipeline otomatis
  4. User menunggu — Claude kirim progress update tiap fase
  5. Hasil: formatted report + gate verdict + top-N AI remediation suggestions

---

### 4. Knowledge Base (Dynamic — `.claude/skills/security-scan/knowledge/`)

Knowledge base dinamis yang meningkat seiring perkembangan ancaman. Mencakup semua persona (developer, security engineer, AI/ML engineer).

- [ ] `supply-chain-attacks.md` — pola serangan supply chain: dependency confusion, typosquatting, malicious package injection, protestware
- [ ] `cve-severity-guide.md` — cara baca CVSS, kapan CVE kritis vs dapat ditoleransi, konteks reachability
- [ ] `remediation-by-ecosystem.md` — playbook fix per ekosistem: npm (`npm audit fix`), pip (`pip-audit`), Go (`go get -u`), Maven, Cargo
- [ ] `sbom-formats.md` — CycloneDX vs SPDX, kapan pakai mana, compliance context (NTIA, EO 14028)
- [ ] `ci-integration-patterns.md` — cara pasang gate di GitHub Actions, GitLab CI, Jenkins, ArgoCD
- [ ] `ai-ml-supply-chain.md` — risiko khusus AI/ML engineer: model poisoning via HuggingFace, malicious PyPI packages untuk ML tooling, dependency chain di training pipeline
- [ ] `risk-scoring-explained.md` — penjelasan risk score supplychain-kit: CVSS × reachability × fix availability

---

### 5. `supplychain-kit init` Command

Command baru untuk bootstrap engagement (mirip `pentest-kit init`).

- [ ] `supplychain-kit init <engagement> --repo <path> [--policy <preset>] [--out <dir>]`
- [ ] Buat struktur direktori: `results/<engagement>/findings.json`, `reports/`, `sbom/`, `state.json`
- [ ] `state.json`: track fase yang sudah selesai (Init → SBOM → SCA → SAST → Gate → Report)
- [ ] `supplychain-kit status <engagement>` — tampilkan progress engagement

---

### 6. AI-Powered Remediation via Claude API

- [ ] `internal/claudeai/remediation.go` — kirim finding ke Claude API, terima structured remediation
- [ ] `supplychain-kit analyze --findings findings.json [--top 10]` — AI analysis top-N findings
- [ ] Output per finding: technical explanation + reachability-aware fix recommendation + upgrade command + breaking change warning + verify step
- [ ] Support `ANTHROPIC_API_KEY` via env var atau `configs/aspm.yaml`
- [ ] Graceful degradation: jika API key tidak ada, skip AI analysis tanpa error fatal
- [ ] Remediation priority dipengaruhi reachability:
  - `reachable: YES` → "Fix segera. Prioritas 1."
  - `reachable: NO` → "Fix di sprint berikutnya."
  - `reachable: UNKNOWN` → "Treat as reachable sampai terbukti sebaliknya."

---

### 7. Report Generation (Markdown + DOCX)

**Prinsip report:** Bahasa teknis penuh, remediation harus clear + actionable + lengkap. Target audience adalah engineer yang sudah paham CVE — bukan simplified, tapi informatif dan tidak ada yang perlu diasumsikan sendiri.

- [ ] `supplychain-kit report --engagement <name> --format markdown` — render per-finding Markdown
- [ ] `supplychain-kit report --engagement <name> --format docx` — generate DOCX via Pandoc
- [ ] `supplychain-kit report --engagement <name> --format all` — generate keduanya sekaligus
- [ ] Template Markdown per finding (`configs/report-templates/finding.md.tmpl`):
  ```
  ## [SEVERITY] CVE-XXXX-XXXXX — <package> <version>

  Affected:     <package> <version>
  Introduced:   <dependency chain>
  CWE:          CWE-XXXX (<name>)
  Reachable:    YES | NO | UNKNOWN — <call path jika reachable>
  Exploit:      Public PoC available | No known exploit

  REMEDIATION:
    Fix:        Upgrade <package> to ≥<fixed-version>
    Command:    <exact package manager command>
    Breaking:   <none | describe breaking changes>
    Verify:     <command untuk verifikasi setelah fix>

  REFERENCES:
    Advisory:   <URL>
    NVD:        <URL>
  ```
- [ ] Template DOCX: cover page, executive summary (total findings per severity, gate verdict), findings table, per-finding detail, appendix SBOM
- [ ] Pandoc sebagai renderer DOCX — tidak perlu library tambahan, sudah tersedia di mayoritas Linux/macOS
- [ ] `supplychain-kit report --check-deps` — verifikasi Pandoc terinstall

---

### 8. Claude Code Hooks Templates

- [ ] `configs/hooks/pre-commit.sh` — jalankan `supplychain-kit gate` sebelum commit, block jika Critical
- [ ] `configs/hooks/post-scan.sh` — setelah scan, upload ke Dependency-Track (opsional)
- [ ] `configs/hooks/claude-stop.sh` — hook untuk Claude Code `Stop` event: tampilkan summary engagement aktif
- [ ] Instruksi setup di README: cara register hook ke `.claude/settings.json`

---

### 9. Test

- [ ] Test MCP server: jalankan `supplychain-kit mcp` sebagai subprocess, kirim JSON-RPC request, validasi response
- [ ] Test `init` command: verifikasi struktur direktori dan `state.json` dibuat dengan benar
- [ ] Test `analyze` command: mock Claude API, verifikasi remediation di-parse dan di-output dengan benar
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

### Taint Analysis Engine

- [ ] `internal/taint/source_detector.go` — deteksi user-controlled input entry points:
  - HTTP handler parameters (gin, echo, net/http, fasthttp, flask, express, spring, dll)
  - Environment variables yang di-read ke variabel
  - File read operations dengan path dari user
  - CLI argument parsing
- [ ] `internal/taint/propagator.go` — trace taint melalui call graph Joern:
  - Forward propagation: dari source → melalui function calls → ke sink
  - Sanitizer detection: input yang sudah di-validate/escape dianggap clean
  - Inter-procedural: trace melewati function boundaries
- [ ] `internal/taint/sink_matcher.go` — cocokkan tainted call dengan CVE sink symbols:
  - Ambil affected function symbols dari metadata Grype/Trivy
  - Match dengan node di CPG yang tainted
  - Output: confirmed exploitable path dengan source → propagation chain → sink
- [ ] Integrasi ke `scan` command: findings dengan confirmed taint path mendapat label `exploitable: CONFIRMED`
- [ ] Output di report:
  ```
  Reachable:    CONFIRMED EXPLOITABLE
  Taint path:   POST /api/data → handler.go:47 (user_input)
                → utils/fetch.go:23 (url = user_input)
                → requests.get(url)  ← CVE-2024-XXXX sink
  ```

### Multi-Language Support (bertahap)

- [ ] Go — via Joern Go frontend (sudah tersedia)
- [ ] Python — via Joern Python frontend
- [ ] JavaScript/TypeScript — via Joern JS frontend
- [ ] Java — via Joern Java frontend

### Test

- [ ] Unit test source_detector: fixture HTTP handlers berbagai framework → detect sources correctly
- [ ] Unit test propagator: fixture call graph dengan taint chain → propagasi benar
- [ ] Unit test sink_matcher: fixture CVE sink symbols → match dengan CPG nodes
- [ ] E2E test: repo dengan known vulnerable pattern → output `exploitable: CONFIRMED` dengan path yang benar

---

## v1.0 — Production CLI

**Tujuan:** Stabil, terdokumentasi, siap digunakan komunitas.

- [ ] Binary release via GitHub Releases (Linux/macOS/Windows, amd64/arm64)
- [ ] Homebrew formula
- [ ] Full documentation: README lengkap, man page, `--help` yang informatif
- [ ] `supplychain-kit vex --tag v1.0.0` — VEX report CSAF 2.0
- [ ] Compliance output: NIST SSDF, SLSA level check
- [ ] `CONTRIBUTING.md`, `SECURITY.md`, issue templates
- [ ] GitHub Actions reusable workflow: `uses: supplychain-kit/action@v1`

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
      5. analyze_finding  → AI remediation top-N CVE
      6. generate_report  → Markdown report
  → User terima: summary + gate verdict + report path
```

_Pick any unchecked item, open an issue, and submit a PR to `dev`._
	### 6. AI-Powered Remediation via Claude Code Session

	- [ ] Tool `analyze_finding_claude` - kirim single finding ke Claude Code untuk analisis
	- [ ] CLI flag `--use-session` - untuk memilih Claude Code session
	- [ ] Session context: repo path, engagement, scan results terkirim ke Claude Code
	- [ ] Prompt optimization: analisis findings dalam konteks session yang kaya
	- [ ] Graceful degradation: jika Claude Code tidak tersedia, fallback ke template-based

	**Catatan:** Fitur ini opsional untuk improvement masa depan. Default tetap gunakan template-based remediation.
