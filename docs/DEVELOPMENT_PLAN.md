# Development Plan — supplychain-kit

> Referensi: [PRD](./Product%20Requirements%20Document%20%28PRD%29_%20Integrated%20Application%20Security%20Posture%20Management%20%28ASPM%29%20Platform.md) · [ARCHITECTURE.md](../ARCHITECTURE.md)

`supplychain-kit` adalah platform ASPM (_Application Security Posture Management_) yang didistribusikan sebagai **open-source CLI tool** — dijalankan langsung di device lokal developer atau di pipeline CI tanpa ketergantungan pada layanan eksternal berbayar.

**Prinsip pengembangan saat ini:** CLI-first, standalone (tanpa database atau Docker), engine berfungsi penuh sebelum lapisan infrastruktur ditambahkan.

---

## Status Saat Ini — v0.2 (Foundation + Scanner Scaffold)

- Tiga binary Go berhasil di-build: `aspm-api`, `aspm-scanner`, `supplychain-kit`
- Lima scanner adapter sudah mengeksekusi CLI nyata dengan graceful degradation
- `supplychain-kit scan --repo <path|url>` sudah mendukung local path dan remote URL
- Unit test untuk semua scanner adapter (8 package lulus)
- `scripts/install-tools.sh` tersedia untuk instalasi tool scanner
- Quality gate dan scoring engine sudah terimplementasi dan tested

---

## v0.3 — SCA Pipeline Berfungsi Penuh

**Tujuan:** `supplychain-kit scan --mode sca` menghasilkan laporan dependency vulnerability yang akurat dari repositori nyata.

Supply chain scanning adalah inti dari tools ini: siapa saja yang bergantung pada library apa, dan apakah library tersebut mengandung CVE yang diketahui.

### Perbaikan Pipeline Syft → Grype

Saat ini syft dan grype berjalan secara concurrent, padahal grype membutuhkan SBOM output dari syft. Ini adalah bug yang harus diperbaiki sebelum SCA bisa dipakai.

- [x] Pisahkan eksekusi scanner menjadi dua fase di orchestrator:
  - Fase 1: jalankan `syft` sendiri, tunggu selesai, dapatkan path SBOM
  - Fase 2: jalankan `grype` (dengan path SBOM dari fase 1) + scanner lain secara concurrent
- [x] Pass SBOM path dari hasil syft ke `Request.SBOMPath` sebelum grype dijalankan

### Flag `--mode` pada CLI Scan

- [x] `--mode sca` — hanya jalankan syft + grype (supply chain analysis)
- [x] `--mode sast` — hanya jalankan semgrep + gitleaks (code analysis)
- [x] `--mode all` — jalankan semua scanner (default)

### Output yang Bisa Dibaca Manusia

- [x] Default output: ringkasan ke stderr (jumlah finding per severity)
- [x] `--format json` — full findings JSON ke stdout/file (default sebelumnya)
- [x] `--format table` — tabel temuan ke stdout (rule_id, severity, package, fix)
- [x] Exit code: `0` jika tidak ada Critical/High, `1` jika ada High, `2` jika ada Critical

### Command `supplychain-kit sbom`

- [x] `supplychain-kit sbom --repo <path> --out sbom.json` — hasilkan SBOM CycloneDX 1.5 tanpa scan vulnerability
- [x] Support `--format spdx` sebagai alternatif output

### Test

- [x] Test pipeline SCA end-to-end menggunakan repository fixture Go kecil yang sudah diketahui mengandung CVE
- [x] Test bahwa grype tidak berjalan jika syft gagal (tidak ada SBOM)
- [x] Test flag `--mode sca` hanya menjalankan syft dan grype

---

## v0.4 — SAST Pipeline Berfungsi Penuh

**Tujuan:** `supplychain-kit scan --mode sast` menghasilkan temuan code vulnerability dan secret dari repositori nyata.

### Semgrep Integration

- [x] Verifikasi `semgrep --json` output parsing terhadap versi semgrep terkini (1.75+)
- [x] Flag `--semgrep-config <rule>` untuk override ruleset (default: `p/owasp-top-ten`)
- [x] Filtering: abaikan findings dari direktori `vendor/`, `node_modules/`, `.git/`
- [x] Deduplikasi: findings dari baris yang sama tidak muncul dua kali

### Gitleaks Integration

- [x] Mode `--no-git`: scan working directory tanpa git history (sudah ada, verifikasi berfungsi)
- [x] Mode `--git-history`: scan git history untuk secret yang sudah ter-commit (opsional)
- [x] Suppress rule: dukung `.gitleaksignore` file di root repo

### Output Gabungan SCA + SAST

- [x] `supplychain-kit scan --mode all` menampilkan ringkasan gabungan:
  - Bagian SCA: dependency vulnerabilities
  - Bagian SAST: code findings
  - Bagian Secrets: secret findings
- [x] Setiap finding menampilkan link ke dokumentasi atau advisory

### Test

- [x] Test semgrep parsing terhadap fixture yang mengandung berbagai severity
- [x] Test gitleaks parsing terhadap fixture yang mengandung secret
- [x] Test deduplication: finding yang sama dari dua scanner collapse menjadi satu

---

## v0.5 — Quality Gate & CI Integration

**Tujuan:** Tools bisa menjadi penjaga (gate) di pipeline CI dengan satu perintah.

### CLI `gate` Command

- [x] `supplychain-kit gate --findings <file.json>` berjalan penuh (tanpa `--policy` pun ada default)
- [x] Default policy: fail jika ada Critical, warn jika ada High
- [x] `--policy <file.yaml>` untuk override policy
- [x] Exit code: `0` (pass), `1` (warn), `2` (fail)
- [x] Output human-readable ke stderr, JSON ke stdout

### Template Policy

- [x] `configs/policy-strict.yaml` — fail pada Critical dan High
- [x] `configs/policy-moderate.yaml` — fail pada Critical saja
- [x] `configs/policy-permissive.yaml` — warn saja, tidak pernah fail

### Pipeline One-liner

- [x] `supplychain-kit scan --repo . --format json | supplychain-kit gate` bisa dipakai tanpa file perantara
- [x] Contoh GitHub Actions snippet di README
- [x] Contoh GitLab CI snippet di README

### Test

- [x] Test gate dengan findings fixture yang berisi Critical → harus exit 2
- [x] Test gate dengan findings fixture yang berisi High saja → harus exit 1
- [x] Test gate dengan findings fixture kosong → harus exit 0

---

## v0.6 — Reachability Engine

**Tujuan:** Platform membedakan CVE yang benar-benar exploitable dari yang tidak, mengurangi noise hingga 90%.

### Static Reachability (CPG via Joern)

- [ ] Parser CPG GraphSON JSON dari export Joern
- [ ] Graph traversal dari first-party sources ke third-party sinks
- [ ] Ekstraksi sinks dari affected function symbols di metadata Grype
- [ ] Output per finding: `reachable bool`, `confidence float64`, `path []string`
- [ ] Fallback: jika Joern tidak tersedia, default `reachable = true` (conservative)

### Risk Score Update

- [ ] Reachability multiplier terintegrasi ke scoring: `0.1` (unreachable) atau `1.0` (reachable)
- [ ] Output tabel menampilkan kolom `reachable` dan `risk_score`

### eBPF Runtime Confirmation _(opsional, Linux kernel 5.8+)_

- [ ] Interface `RuntimeConfirmer` di `internal/reachability/`
- [ ] Graceful degradation jika tidak tersedia

---

## v0.7 — Agentic SAST & DefectDojo

**Tujuan:** Platform menganalisis kode AI-generated sebelum commit, dan bisa push ke DefectDojo.

### Agentic SAST

- [ ] `internal/agenticsast/` — terima code snippet, return findings via semgrep
- [ ] API endpoint: `POST /api/v1/agentic-sast/analyze`
- [ ] Dokumentasi integrasi dengan Claude Code dan GitHub Copilot

### DefectDojo & Dependency-Track

- [ ] `internal/defectdojo/` — push normalized findings
- [ ] `internal/deptrack/` — upload SBOM, polling vuln status
- [ ] Keduanya opsional (dikonfigurasi di `configs/aspm.yaml`)

---

## v0.8 — REST API & Webhook Ingestion

**Tujuan:** Platform bisa menerima event dari Git provider dan dioperasikan via API (mulai butuh database).

### REST API

- [ ] `POST /api/v1/scans` — trigger scan async
- [ ] `GET /api/v1/findings` — paginated findings
- [ ] `GET /api/v1/assets/{id}/risk` — risk score per asset
- [ ] Auth: API key sederhana

### Webhook Ingestion

- [ ] GitHub, GitLab, Bitbucket webhook receivers
- [ ] Enqueue ke Redis
- [ ] Debounce per `(repo, ref)` 30 detik

### Storage Layer (Database Masuk di Sini)

- [ ] PostgreSQL via Docker Compose wajib dikonfigurasi
- [ ] `make dev` alias untuk `docker-compose up`
- [ ] README quickstart server mode

---

## v0.9 — AI Remediation Agent

**Tujuan:** Platform menghasilkan proposal perbaikan otomatis.

### SCA Remediation

- [ ] `remediation/agents/renovate_agent.py` — buka PR upgrade dependency
- [ ] Support `go.mod`, `package.json`, `requirements.txt`, `pom.xml`
- [ ] Redis caching untuk lookup versi

### SAST Remediation

- [ ] `remediation/agents/llm_agent.py` — Claude API (prompt caching aktif)
- [ ] Output sebagai PR review comment, tidak pernah auto-merge
- [ ] Fallback ke OpenAI jika Anthropic tidak tersedia

---

## v1.0 — Production Ready

**Tujuan:** Stabil, terdokumentasi, siap digunakan komunitas.

- [ ] VEX report CSAF 2.0 (`supplychain-kit vex --tag v1.0.0`)
- [ ] Compliance reports: NIST SSDF, SLSA, OWASP SCVS
- [ ] Full documentation site (GitHub Pages)
- [ ] Binary release via GitHub Releases (Linux/macOS, amd64/arm64)
- [ ] Homebrew formula
- [ ] `CONTRIBUTING.md`, `SECURITY.md`, issue templates

---

## Catatan Pengembangan

**Urutan prioritas engine (sebelum infrastruktur):**
```
SCA (syft→grype) → SAST (semgrep+gitleaks) → Gate → Reachability → API → Remediation
```

**Dua mode operasi yang harus selalu didukung:**

| Mode | Kebutuhan | Cocok Untuk |
|------|-----------|-------------|
| Standalone | Binary CLI saja | Developer lokal, CI sederhana |
| Server | PostgreSQL + Redis (v0.8+) | Tim, histori scan, tracking |

Database tidak wajib sampai v0.8. Semua fitur inti (scan, gate, reachability) harus berjalan tanpa database.

---

_Pick any unchecked item, open an issue, and submit a PR to `dev`._
