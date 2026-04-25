# Security Policy

## Reporting a Vulnerability

We take security bugs seriously. If you discover a vulnerability in **supplychain-kit**, please report it responsibly:

- **GitHub Private Advisory** (preferred): [Report a vulnerability](https://github.com/penanamtomat/supplychain-kit/security/advisories/new)
- **Email**: Send details to the maintainer via GitHub profile contact

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The affected version(s)

## Response Time

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Critical fix | Within 7 days |
| Non-critical fix | Next release cycle |

## Scope

**In scope:**
- Vulnerabilities in the `supplychain-kit` binary and its Go source code
- Issues in the MCP server implementation
- Bugs in the installer scripts (`install.sh`, `uninstall.sh`)

**Out of scope:**
- False positives or false negatives from third-party scanner tools (`syft`, `grype`, `semgrep`, `gitleaks`, `joern`)
- Vulnerabilities in dependencies of those third-party tools
- Issues that require unrealistic configurations (e.g., intentionally disabling all safety checks)

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.0.x  | Yes |
| v0.9.x  | Best-effort |
| < v0.9  | No |

## Disclosure Policy

We follow coordinated disclosure:
1. Reporter submits privately.
2. Maintainer acknowledges and begins investigation.
3. Fix is developed and validated.
4. Fix is released alongside an advisory with credit to the reporter (unless anonymity is requested).
