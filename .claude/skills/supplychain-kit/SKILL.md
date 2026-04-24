# supplychain-kit — Security Scan Skill

Automated supply chain security pipeline: SCA + SAST + reachability analysis + AI remediation.

## Trigger

Use this skill when the user wants to scan a repository for supply chain vulnerabilities, dependency CVEs, secrets, or code issues — or when they invoke `/security-scan`.

## Setup Check

Before starting, verify the MCP server is registered. If `supplychain-kit mcp` is not in the MCP server list:
```sh
supplychain-kit mcp --print-config
```
Paste the output into `~/.claude/mcp.json` (or `.claude/mcp.json` in the project).

## Onboarding Flow

```
User: /security-scan  (or asks to scan a repo)

1. Ask (if not provided):
   - Engagement name (e.g. myapp-2026q1)
   - Repository path (absolute local path or git URL)
   - Scan mode: sca | sast | all  [default: all]
   - Policy file path: configs/policy-{strict,moderate,permissive}.yaml  [default: configs/aspm.yaml]

2. Confirm parameters, then run using correct CLI syntax:

   # Full end-to-end scan (recommended)
   supplychain-kit run <engagement> --repo <path> --mode all --policy configs/policy-moderate.yaml

   # Or step-by-step
   supplychain-kit init <engagement>
   supplychain-kit scan --repo <path> --target <engagement> --mode all
   supplychain-kit gate --findings results/<engagement>/findings.json --policy configs/policy-moderate.yaml

   # AI remediation: use current Claude Code session (NO API key needed)
   # Read findings.json and perform analysis within this session
   supplychain-kit report --engagement <engagement>

3. Send progress update at each phase:
   ✓ Init      — engagement directory created
   ✓ SBOM      — N components catalogued
   ✓ Scan      — N findings (CRITICAL:X HIGH:Y MEDIUM:Z LOW:W)
   ✓ Gate      — PASS | WARN | FAIL
   ✓ Analyze   — top-10 findings with AI remediation (using current Claude Code session)
   ✓ Report    — saved to results/<engagement>/report.md

4. Final summary:
   ## Scan Complete — <engagement>
   | | |
   |---|---|
   | Total findings | N |
   | Critical | X |
   | High | Y |
   | Gate | PASS/WARN/FAIL |
   | Report | results/<engagement>/report.md |

   Top-3 findings with remediation commands listed inline.
```

## Important CLI Notes

- **`run` command**: `--policy` expects a YAML file path, not a preset name. Use: `configs/policy-{strict,moderate,permissive}.yaml`
- **`scan` command**: Does NOT have `--policy` flag. Use `run` for end-to-end with policy, or `gate` separately.
- **`analyze` command**: DEPRECATED - Do NOT use. Instead, perform AI analysis directly in this Claude Code session by reading findings.json.
- **File paths**: Findings are stored at `results/<engagement>/findings.json` (flat structure, not in a `findings/` subdirectory)
- **Report output**: Generated at `results/<engagement>/report.md` (not in `reports/` subdirectory)

## Knowledge Base

Reference these files for context during analysis:

- [Supply Chain Attack Patterns](knowledge/supply-chain-attacks.md)
- [CVE Severity Guide](knowledge/cve-severity-guide.md)
- [Remediation by Ecosystem](knowledge/remediation-by-ecosystem.md)
- [SBOM Formats](knowledge/sbom-formats.md)
- [CI Integration Patterns](knowledge/ci-integration-patterns.md)
- [AI/ML Supply Chain Risks](knowledge/ai-ml-supply-chain.md)
- [Risk Score Explained](knowledge/risk-scoring-explained.md)

## Companion Skills (Trail of Bits)

Install these for extended analysis capabilities:

```sh
# Maintainer risk + dependency takeover assessment
/plugin install trailofbits/skills/plugins/supply-chain-risk-auditor

# CodeQL + Semgrep + SARIF multi-scanner triage
/plugin install trailofbits/skills/plugins/static-analysis

# Author custom Semgrep rules for project-specific patterns
/plugin install trailofbits/skills/plugins/semgrep-rule-creator
```

**When to invoke companion skills:**
- After a scan finds suspicious packages → invoke `supply-chain-risk-auditor` for maintainer analysis
- When SAST findings need deeper triage → invoke `static-analysis` for CodeQL cross-validation
- When recurring vulnerability patterns appear → invoke `semgrep-rule-creator` to codify the pattern

## MCP Tools Available

| Tool | Purpose |
|---|---|
| `init_engagement` | Bootstrap engagement directory + state tracking |
| `scan_repository` | SCA + SAST + reachability (returns structured findings) |
| `generate_sbom` | CycloneDX SBOM via syft |
| `run_gate` | Policy evaluation → pass/warn/fail |
| `generate_report` | Markdown report per finding |

**IMPORTANT**: For AI remediation analysis, use the current Claude Code session directly by reading `results/<engagement>/findings.json`. DO NOT call the CLI's `analyze` command - it requires a separate API key.

## Reachability Priority Rules

| Reachability | Severity | Action |
|---|---|---|
| reachable / confirmed | any | Fix now — P0 |
| unknown | critical / high | Treat as reachable — fix now |
| unknown | medium / low | Next sprint |
| unreachable | critical | Next sprint |
| unreachable | ≤ high | Monitor |
