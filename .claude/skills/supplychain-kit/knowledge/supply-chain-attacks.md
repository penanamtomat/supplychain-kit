# Supply Chain Attack Patterns

## Dependency Confusion

**Attack:** Attacker publishes a public package with the same name as an internal private package but a higher version number. Package managers that check public registries first pull the malicious version.

**Detection signals:**
- Package version unexpectedly high (e.g. internal lib at 1.0.0, public version at 9.9.9)
- Package author mismatch between expected org and publisher
- No prior public history for the package

**Mitigation:** Scope packages (e.g. `@org/pkg` for npm), configure registry to prefer private, pin exact versions with lockfile integrity checks.

## Typosquatting

**Attack:** Malicious package named to exploit typos: `reqeusts` (Python), `lodahs` (npm), `cros-env` vs `cross-env`.

**Detection signals:** Package name deviates by 1–2 characters from a well-known package; very few downloads; recent publish date; no README.

**Tools:** `pip-audit`, `npm audit`, `grype`, `osv-scanner` — all detect known typosquats in their databases.

## Malicious Package Injection (Maintainer Compromise)

**Attack:** Attacker compromises a legitimate maintainer's credentials and pushes a malicious version of a trusted package (e.g. `event-stream` 2018, `ua-parser-js` 2021, `colors`/`faker` protestware 2022).

**Detection signals:**
- Sudden version bump with no changelog
- New maintainer added shortly before release
- Postinstall/preinstall scripts added in package.json
- Supply chain risk auditor shows maintainer count drop

**Mitigation:** Pin to exact versions with lockfile, monitor for unexpected version bumps in CI, use `npm audit signatures`.

## Protestware / Intentional Sabotage

**Attack:** Maintainer intentionally adds destructive code (e.g. `node-ipc` 2022 — wiped files on Russian/Belarusian IPs).

**Detection signals:** Sudden large diff with no issue/PR context; geo-conditional code; obfuscated logic in otherwise simple package.

## Build Pipeline Compromise (CI/CD Poisoning)

**Attack:** Compromised GitHub Actions workflow, malicious action version bump, or poisoned build artifact (SolarWinds pattern).

**Detection signals:** Unsigned build artifacts, unverified action versions (`uses: action@main` vs pinned SHA), unexpected network calls during build.

**Mitigation:** Pin actions to commit SHA, use SLSA provenance, verify SBOM against build artifact.

## Transitive Dependency Risk

Most CVEs in modern supply chains are in **transitive** dependencies — not direct ones. A project may have 5 direct deps but 500 transitive.

Key insight for remediation: upgrading a direct dep often resolves multiple transitive CVEs. Check dependency tree before fixing each CVE individually.
