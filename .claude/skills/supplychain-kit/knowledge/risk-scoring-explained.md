# Risk Score Explained

## Formula

```
risk_score = cvss_base × reachability_multiplier × tier_multiplier
```

## Components

### CVSS Base Score (0.0–10.0)

Sourced from NVD or the scanner that reported the finding. If absent (SAST rule without CVE), estimated from severity:
- CRITICAL → 9.0
- HIGH → 7.5
- MEDIUM → 5.0
- LOW → 2.5
- INFO → 0.5

### Reachability Multiplier

| Reachability | Multiplier | Rationale |
|---|---|---|
| `reachable` | 1.0 | Vulnerable symbol called, evidence at file:line |
| `unknown` | 0.5 | Imported but symbol not resolvable — conservative |
| `unreachable` | 0.1 | Dev-only dep or never imported in production |

**Design decision (v1.1):** Three values only — no more `confirmed_exploitable` or `runtime_confirmed`. `unknown` is 0.5 (conservative) not 0.7. When in doubt, treat as reachable.

### Tier Multiplier

Configured in `configs/aspm.yaml` per asset tier:
- Tier 1 (production-critical): 1.0
- Tier 2 (production): 0.8
- Tier 3 (staging): 0.5
- Tier 4 (dev/test): 0.3

Default tier for CLI scans: 2 (production).

## Example Calculations

| CVE | CVSS | Reachability | Tier | Risk Score | Priority |
|---|---|---|---|---|---|
| Log4Shell (CVE-2021-44228) | 10.0 | reachable | 1 | 10.0 | P0 |
| Same CVE, unreachable | 10.0 | unreachable | 1 | 1.0 | next-sprint |
| CVE-2023-1234 | 5.0 | reachable | 2 | 4.0 | fix-now |
| CVE-2023-5678 | 9.8 | unreachable | 4 | 0.29 | monitor |

## Using Risk Score for Prioritisation

```
supplychain-kit scan --repo . --format table
```

Output is sorted by risk_score descending. Top-N findings with highest risk_score are the ones `analyze_finding` prioritises for AI remediation.

## Relationship to EPSS

EPSS (Exploit Prediction Scoring System) is a probability-based score (0–1) for likelihood of exploitation in the wild within 30 days. 

supplychain-kit does not currently consume EPSS, but when available in scanner output (Grype supports it), it can be factored in:

```
adjusted_risk = risk_score × (1 + epss_score)
```

A CVE with EPSS=0.95 (actively exploited in wild) should be escalated regardless of reachability analysis results.

## Gate Policy Thresholds

From `configs/policy-strict.yaml`:
```yaml
quality_gate:
  fail_on_critical: true
  fail_on_high: true
  warn_on_medium: true
  max_risk_score: 7.0   # fail if any finding exceeds this
```

Risk score threshold overrides severity-only gating — a medium severity finding with risk_score=8.5 (reachable in prod) will trigger gate failure under strict policy.
