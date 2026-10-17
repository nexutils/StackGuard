BINARY  := stackguard
PKG     := github.com/nexutils/StackGuard
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

GO      ?= go
GOFLAGS := -trimpath

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build bin/stackguard
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/stackguard

.PHONY: install
install: ## Install stackguard into $GOPATH/bin
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/stackguard

.PHONY: test
test: ## Run tests
	$(GO) test ./...

.PHONY: test-race
test-race: ## Run tests with the race detector and coverage
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: cover
cover: test-race ## Open the coverage report in a browser
	$(GO) tool cover -html=coverage.out

.PHONY: golden
golden: ## Regenerate golden files after an intentional output change
	$(GO) test ./internal/parser/... ./internal/reporters/... -update

.PHONY: fuzz
fuzz: ## Run each fuzz target for 30s
	$(GO) test -run='^$$' -fuzz='^FuzzParsePath$$' -fuzztime=30s ./internal/engine/query
	$(GO) test -run='^$$' -fuzz='^FuzzParseConfig$$' -fuzztime=30s ./internal/parser/nginx
	$(GO) test -run='^$$' -fuzz='^FuzzMaskNonCode$$' -fuzztime=30s ./internal/parser/jenkins

.PHONY: bench
bench: ## Run benchmarks
	$(GO) test -run='^$$' -bench=. -benchmem ./internal/engine/

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: rules-validate
rules-validate: ## Validate the built-in rules
	$(GO) run ./cmd/stackguard rules --validate

.PHONY: docs
docs: ## Regenerate docs/rules from the built-in rules
	$(GO) run ./tools/docgen -out docs/rules

.PHONY: examples
examples: build ## Scan the example projects
	./bin/$(BINARY) scan examples --fail-on none

.PHONY: playground
playground: ## Build the playground WASM binary for local dev
	GOOS=js GOARCH=wasm $(GO) build -o web/stackguard.wasm ./cmd/playground
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" web/wasm_exec.js
	@echo "Serve web/ with a local HTTP server, e.g.: python3 -m http.server -d web 8080"

.PHONY: snapshot
snapshot: ## Build release artifacts locally with GoReleaser
	goreleaser release --snapshot --clean

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin dist coverage.out
