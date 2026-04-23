# Development Plan — supplychain-kit

> Referensi: [PRD](./Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md) · [ARCHITECTURE.md](../ARCHITECTURE.md)

`supplychain-kit` adalah **open-source CLI tool** untuk supply chain scanning (SCA) dan static analysis (SAST) — dijalankan langsung di device lokal developer atau di pipeline CI tanpa ketergantungan pada server, database, atau Docker.

**Prinsip pengembangan:** CLI-only, standalone (tanpa database, Redis, atau Docker), satu binary (`supplychain-kit`), engine berfungsi penuh sebelum integrasi eksternal ditambahkan.

---

## Status Saat Ini — v0.6 (In Progress)

- SCA pipeline (syft → grype), SAST pipeline (semgrep + gitleaks), quality gate, dan reachability engine sudah diimplementasikan
- Bug kritis ditemukan di v0.6: reachability engine tidak terhubung ke CLI dan confidence logic terbalik
- Sedang dalam proses fix + konsolidasi ke CLI-only

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
- [ ] Test end-to-end: `scan → gate → exit code` benar

---

## v0.7 — Dependency Tracking & DefectDojo CLI

**Tujuan:** `supplychain-kit` bisa push hasil scan ke Dependency-Track dan DefectDojo langsung dari CLI, tanpa server atau database lokal.

### Dependency-Track CLI

- [ ] `supplychain-kit deptrack upload --url <dt-url> --api-key <key> --sbom sbom.json` — upload SBOM ke Dependency-Track
- [ ] `supplychain-kit deptrack status --url <dt-url> --api-key <key> --project <id>` — polling status vulnerability
- [ ] `supplychain-kit deptrack sync --repo .` — kombinasi: scan SBOM lalu langsung upload
- [ ] Support konfigurasi via `configs/aspm.yaml` (url, api-key, project-id)
- [ ] Graceful degradation: jika Dependency-Track tidak tersedia, lanjut tanpa error fatal

### DefectDojo CLI

- [ ] `supplychain-kit defectdojo push --url <url> --api-key <key> --findings findings.json`
- [ ] Map normalized findings ke DefectDojo finding format
- [ ] Support `--engagement-id` dan `--product-id` sebagai parameter

### Test

- [ ] Mock HTTP client untuk test upload tanpa server nyata
- [ ] Test `sync` command end-to-end dengan fixture SBOM

---

## v0.8 — Claude Code Integration

**Tujuan:** `supplychain-kit` bisa digunakan sebagai tool di dalam Claude Code via MCP dan slash commands, sekaligus mendukung agentic SAST.

### MCP Server Mode

- [ ] `supplychain-kit mcp` — jalankan sebagai MCP server (stdio transport)
- [ ] Expose tools: `scan_repository`, `generate_sbom`, `run_gate`, `check_reachability`
- [ ] Setiap tool menerima parameter dan mengembalikan structured JSON result
- [ ] Panduan registrasi di `~/.claude/mcp.json` atau project `.claude/mcp.json`

### Agentic SAST via Claude Skill

- [ ] Buat Claude Code skill: `/security-scan` — trigger `supplychain-kit scan` dari dalam Claude Code
- [ ] Skill menerima path repo, mode (`sca`/`sast`/`all`), dan format output
- [ ] Hasil scan ditampilkan sebagai formatted report di Claude Code chat
- [ ] Integrasi dengan GitHub tools: bisa scan PR diff, bukan hanya full repo

### Claude Code Hooks Integration

- [ ] Template pre-commit hook yang memanggil `supplychain-kit gate`
- [ ] Template post-scan hook yang bisa trigger upload ke Dependency-Track

### Test

- [ ] Test MCP server dengan MCP test client
- [ ] Test skill dengan sample repository

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
SCA (syft→grype) → SAST (semgrep+gitleaks) → Gate → Reachability → Dep Tracking → Claude Code MCP
```

**Mode operasi yang didukung:**

| Mode | Kebutuhan | Cocok Untuk |
|------|-----------|-------------|
| Standalone | Binary CLI saja | Developer lokal, CI sederhana |
| With tracking | CLI + Dependency-Track/DefectDojo (opsional) | Tim, tracking vulnerability |
| Claude Code | CLI + MCP (v0.8+) | Agentic workflow, AI-assisted security review |

_Pick any unchecked item, open an issue, and submit a PR to `dev`._
