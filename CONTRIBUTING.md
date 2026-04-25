# Contributing to supplychain-kit

Thank you for your interest in contributing! This guide covers the basics.

## Development Setup

### Prerequisites

- **Go 1.22+** — [download](https://go.dev/dl)
- **git**, **curl** — required by the installer
- Scanner tools (installed automatically by `install.sh`): `syft`, `grype`, `gitleaks`, `semgrep`

### Quick Start

```bash
git clone https://github.com/penanamtomat/supplychain-kit.git
cd supplychain-kit
bash install.sh
```

### Build from Source

```bash
go build -o bin/supplychain-kit ./cmd/supplychain-kit/
```

For a versioned build:

```bash
go build -ldflags "-X main.version=$(git describe --tags --always)" -o bin/supplychain-kit ./cmd/supplychain-kit/
```

### Run Tests

```bash
go test ./...
```

Run a specific package:

```bash
go test ./internal/taint/ -v
```

### Coding Conventions

- Run `gofmt` and `go vet` before committing — no separate style guide.
- Follow standard Go project layout: `cmd/` for entry points, `internal/` for private packages, `pkg/` for importable packages.
- Keep the single-binary constraint: no CGO, no runtime dependencies beyond scanner CLIs.
- Write table-driven tests for new functionality.

### Submitting Changes

1. Fork the repository or create a branch from `main`.
2. Make your changes with clear, descriptive commit messages.
3. Ensure `go build ./...` and `go test ./...` pass.
4. Open a Pull Request against `main`.

PRs that align with the [development roadmap](docs/DEVELOPMENT_PLAN.md) are prioritized for review.

### Reporting Issues

- Open a [GitHub Issue](https://github.com/penanamtomat/supplychain-kit/issues) with a clear description and steps to reproduce.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).
