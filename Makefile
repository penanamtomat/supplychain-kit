SHELL := bash
GOFLAGS ?=
DSN ?= postgres://aspm:aspm@localhost:5432/aspm?sslmode=disable

.PHONY: help build test lint python-deps python-test migrate up down

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n",$$1,$$2}'

build: ## Build all Go binaries into ./bin
	@mkdir -p bin
	go build $(GOFLAGS) -o bin/aspm-api      ./cmd/aspm-api
	go build $(GOFLAGS) -o bin/aspm-scanner  ./cmd/aspm-scanner
	go build $(GOFLAGS) -o bin/aspm-cli      ./cmd/aspm-cli

test: ## Run Go unit tests
	go test ./... -count=1

lint: ## Static analysis (requires golangci-lint)
	golangci-lint run ./...

python-deps: ## Create a virtualenv for the remediation layer
	python -m venv .venv && \
		. .venv/bin/activate && \
		pip install -U pip && \
		pip install -r remediation/requirements.txt

python-test: ## Run Python tests
	. .venv/bin/activate && pytest remediation/tests -q

migrate: ## Apply SQL migrations
	psql "$(DSN)" -f migrations/0001_init.sql

up: ## Start the dev stack
	docker compose -f deployments/docker/docker-compose.yml up -d --build

down: ## Stop the dev stack
	docker compose -f deployments/docker/docker-compose.yml down -v
