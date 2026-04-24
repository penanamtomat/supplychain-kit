# CI Integration Patterns

## GitHub Actions

```yaml
# .github/workflows/supply-chain-security.yml
name: Supply Chain Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install supplychain-kit
        run: |
          curl -sSfL https://github.com/penanamtomat/supplychain-kit/releases/latest/download/install.sh | sh
          sudo mv supplychain-kit /usr/local/bin/

      - name: Run scan + gate
        run: |
          supplychain-kit run ${{ github.repository_owner }}-${{ github.event.repository.name }} \
            --repo . \
            --mode all \
            --policy moderate
        # Exit code 2 = CRITICAL → fail CI
        # Exit code 1 = HIGH → warn only (remove 'continue-on-error' to block)

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: results/*/
```

## GitLab CI

```yaml
# .gitlab-ci.yml
supply-chain-scan:
  stage: test
  image: ubuntu:24.04
  script:
    - apt-get update -qq && apt-get install -y curl
    - curl -sSfL https://github.com/penanamtomat/supplychain-kit/releases/latest/download/install.sh | sh
    - mv supplychain-kit /usr/local/bin/
    - supplychain-kit run ${CI_PROJECT_NAME}-${CI_COMMIT_SHORT_SHA}
        --repo .
        --mode all
        --policy moderate
  artifacts:
    when: always
    paths:
      - results/
    reports:
      # Future: emit SARIF for GitLab security dashboard
```

## Pre-commit Hook

```sh
# Install via supplychain-kit
cp configs/hooks/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Or register in .claude/settings.json (Claude Code hook):
# "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{"type": "command", "command": "supplychain-kit gate --findings results/current/findings.json"}] }] }
```

`configs/hooks/pre-commit.sh`:
```sh
#!/bin/sh
supplychain-kit gate --findings results/current/findings.json
exit_code=$?
if [ $exit_code -eq 2 ]; then
  echo "BLOCKED: Critical vulnerabilities detected. Run: supplychain-kit scan --repo . --format table"
  exit 1
fi
```

## ArgoCD / GitOps

Add a pre-sync hook:
```yaml
# argo-app.yaml
spec:
  syncPolicy:
    syncOptions:
      - RespectIgnoreDifferences=true
  hooks:
    - name: supply-chain-gate
      command: ["supplychain-kit", "gate", "--findings", "results/prod/findings.json", "--policy", "strict"]
      when: PreSync
```

## Quality Gate Exit Codes

| Exit code | Meaning | CI behaviour |
|---|---|---|
| 0 | PASS | Continue |
| 1 | WARN (High findings) | Continue with warning |
| 2 | FAIL (Critical findings) | Block pipeline |

Use `|| true` to downgrade FAIL to warning in non-blocking pipelines:
```sh
supplychain-kit gate --findings findings.json || true
```
