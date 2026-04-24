# SBOM Formats

## CycloneDX vs SPDX

| Feature | CycloneDX | SPDX |
|---|---|---|
| Primary use | Vulnerability management, supply chain risk | License compliance, legal review |
| Format versions | 1.0–1.6 (JSON, XML) | 2.2–2.3 (JSON, YAML, RDF, TV) |
| Tool support | Grype, Trivy, Dependency-Track | FOSSA, Black Duck, GitHub |
| Component metadata | Rich (PURL, hashes, services, vulnerabilities) | Comprehensive (relationships, license expressions) |
| supplychain-kit default | CycloneDX 1.5 JSON | Available via `--format spdx` |

**supplychain-kit uses CycloneDX by default** because Grype and Trivy consume it natively for vulnerability matching.

## CycloneDX Key Fields

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "hashes": [{"alg": "SHA-256", "content": "..."}]
    }
  ]
}
```

**PURL (Package URL):** Universal identifier — `pkg:<type>/<namespace>/<name>@<version>`. Used by Grype for CVE matching.

## Compliance Context

**NTIA Minimum Elements (US Executive Order 14028):**
- Supplier name, component name, version
- Unique identifier (PURL or CPE)
- Dependency relationship
- Author of SBOM data
- Timestamp

CycloneDX 1.5 satisfies all NTIA minimum elements.

**FDA (Medical Devices):** CycloneDX preferred. Submit SBOM as part of 510(k) premarket submission.

**EU Cyber Resilience Act (CRA):** SBOM required for products with digital elements. CycloneDX or SPDX accepted.

## Generating SBOMs with supplychain-kit

```sh
# CycloneDX (default)
supplychain-kit sbom --repo . --out sbom.json

# SPDX
supplychain-kit sbom --repo . --format spdx --out sbom-spdx.json

# As part of engagement (saved to results/<eng>/sbom/)
supplychain-kit run myapp --repo .
# or via MCP:
# generate_sbom(engagement="myapp", repo="/path/to/repo")
```

## SBOM Attestation

For supply chain provenance, pair the SBOM with:
- **SLSA provenance** (`slsa-verifier`) — proves build from source
- **Sigstore/cosign** — signs and verifies SBOM integrity
- **in-toto** — links source → build → deploy attestations
