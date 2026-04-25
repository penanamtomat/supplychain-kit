SHELL := bash
GOFLAGS ?=
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BINARY := supplychain-kit

.PHONY: help build test lint clean install

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n",$$1,$$2}'

build: ## Build supplychain-kit binary
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/supplychain-kit/

test: ## Run Go unit tests
	go test ./... -count=1

lint: ## Static analysis (requires golangci-lint)
	golangci-lint run ./...

clean: ## Remove build artifacts
	rm -rf bin/ dist/

install: build ## Install binary to GOPATH/bin
	@cp bin/$(BINARY) $(GOPATH)/bin/$(BINARY) 2>/dev/null || cp bin/$(BINARY) $(HOME)/go/bin/$(BINARY)
	@echo "Installed to $(HOME)/go/bin/$(BINARY)"
