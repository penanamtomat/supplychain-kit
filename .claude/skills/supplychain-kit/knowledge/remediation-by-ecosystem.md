# Remediation Playbook by Ecosystem

## Go

```sh
# Upgrade specific dependency
go get github.com/org/pkg@v1.2.3

# Upgrade all dependencies to latest minor/patch
go get -u ./...

# Audit (requires govulncheck)
govulncheck ./...

# Tidy after changes
go mod tidy

# Verify module checksums
go mod verify
```

**Transitive deps:** Edit `go.mod` directly with `replace` directive for forks, or `go get` the indirect dep explicitly.

## npm / Node.js

```sh
# Audit and fix automatically (safe upgrades only)
npm audit fix

# Force fix including breaking changes (REVIEW OUTPUT FIRST)
npm audit fix --force

# Upgrade specific package
npm install package@1.2.3

# Check exact vulnerability
npm audit --json | jq '.vulnerabilities'

# Verify lockfile integrity (npm 7+)
npm ci --audit
```

**Note:** `npm audit fix --force` may introduce breaking changes. Always run tests after.

## Python / pip

```sh
# Audit dependencies
pip-audit

# Upgrade specific package
pip install "package>=1.2.3"

# With Poetry
poetry update package
poetry show --outdated

# With pip-tools
pip-compile --upgrade-package package requirements.in
pip-sync requirements.txt
```

## Maven / Java

```sh
# Check for dependency updates
mvn versions:display-dependency-updates

# Upgrade dependency (edit pom.xml then)
mvn versions:use-dep-version -Dincludes=groupId:artifactId -DdepVersion=1.2.3

# Audit with OWASP Dependency Check
mvn org.owasp:dependency-check-maven:check
```

## Gradle / Java / Kotlin

```sh
# List outdated dependencies
gradle dependencyUpdates

# Update wrapper
gradle wrapper --gradle-version 8.x.x

# OWASP check
gradle dependencyCheckAnalyze
```

## Rust / Cargo

```sh
# Audit
cargo audit

# Upgrade specific crate
cargo update -p crate-name --precise 1.2.3

# Full upgrade
cargo update
```

## Ruby / Bundler

```sh
# Audit
bundle audit check --update

# Upgrade specific gem
bundle update gem-name

# Lock to safe version
# Edit Gemfile: gem 'name', '>= 1.2.3'
bundle install
```

## Docker / Container Images

```sh
# Scan with trivy
trivy image image-name:tag

# Update base image in Dockerfile
# FROM ubuntu:22.04 → FROM ubuntu:24.04

# Rebuild and rescan
docker build -t image:new . && trivy image image:new
```

## Universal Verify Step Pattern

After any upgrade:
1. Run `supplychain-kit gate --findings results/<eng>/findings/findings.json` to confirm CVE resolved
2. Run project test suite
3. Check for introduced deprecation warnings
4. Re-run `supplychain-kit scan --repo . --mode sca` to verify clean
