# AI/ML Supply Chain Risks

## Overview

AI/ML engineers face a **unique and underappreciated** supply chain attack surface. The attack vectors go beyond npm/pip packages — they include model weights, datasets, and training pipeline infrastructure.

## HuggingFace Model Poisoning

**Attack:** Malicious weights or pickle exploits embedded in `.pkl`, `.bin`, or `safetensors` files uploaded to HuggingFace Hub.

**Real incidents:**
- PyTorch pretrained models with malicious pickle payload (2023)
- Multiple HuggingFace repos hosting `*.pt` files with reverse shells

**Detection:**
- Use `safetensors` format over `pickle` — safetensors is non-executable
- Scan with `modelscan` before loading: `pip install modelscan && modelscan -p model.bin`
- Never use `torch.load()` without `weights_only=True` (PyTorch 2.0+)

**supplychain-kit relevance:** SAST scanner (semgrep) can flag unsafe `torch.load()` calls without `weights_only=True`.

## Malicious PyPI Packages Targeting ML Tooling

High-value targets for attackers: packages with ML in the name, GPU utilities, CUDA wrappers.

**Known patterns:**
- `torchvision`-adjacent packages with typosquatted names
- `transformers` forks with `postinstall` exfiltration
- CUDA toolkit wrappers that steal API keys from environment

**Detection:** `pip-audit`, `osv-scanner`, and `grype` all cover PyPI CVE databases. Run `supplychain-kit scan --repo . --mode sca` on any ML project.

## Training Data Poisoning

**Attack:** Attacker poisons a public dataset (e.g. Common Crawl, GitHub Copilot training data) to introduce backdoors or biased model behaviour.

**Not directly detectable by supplychain-kit** (requires dataset integrity tooling), but the SBOM can document dataset provenance for compliance.

## Dependency Chain in Training Pipelines

ML training pipelines often have deep dependency chains:
```
your_code
  → transformers 4.x
    → tokenizers (Rust-backed)
      → sentencepiece
  → torch 2.x
    → CUDA 12.x (system-level)
  → datasets
    → pyarrow (C++-backed)
```

Each level is an attack surface. Key risk: **C-extension packages** (`tokenizers`, `pyarrow`) are harder to audit — prioritise scanning these for CVEs.

## GPU Driver / CUDA Supply Chain

CUDA toolkit and GPU drivers are typically delivered via system package managers (apt, yum) or NVIDIA's own installer — outside standard package manager audit scope.

**Mitigation:** Use container images with pinned CUDA base (e.g. `nvcr.io/nvidia/pytorch:24.01-py3`), verify image digest, run `trivy image` on the container.

## MLflow / Experiment Tracking Vulnerabilities

MLflow has had multiple CVEs (SSRF, path traversal, RCE) — commonly deployed internally without updates.

**supplychain-kit detection:** `grype` and `osv-scanner` will flag MLflow CVEs in Python dependency scan. Check for:
- CVE-2023-6977 (path traversal)
- CVE-2024-27133 (RCE via YAML deserialization)

## Recommendations for AI/ML Engineers

1. Run `supplychain-kit scan --repo . --mode sca` on every ML project before deploying
2. Use `safetensors` for model weight storage — never raw pickle
3. Pin model versions on HuggingFace: `from_pretrained("model@commit_sha")`
4. Scan container images with `trivy image` as part of training infrastructure CI
5. Document dataset provenance in SBOM metadata (CycloneDX 1.5 `data` component type)
