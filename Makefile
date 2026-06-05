HOMEDIR := $(shell pwd)
OUTDIR  := $(HOMEDIR)/output

GOPKGS    := $$(go list ./...| grep -vE "vendor|/cmd")
COVERPKGS := $$(go list ./... | tr '\n' ',' | sed 's/,$$//')

BINARY   := bitflip
BINARY6  := bitflip6
BINARYBA := baize
COVERAGE_FILE := coverage.out
COVERAGE_HTML := coverage.html

# Colors for terminal output
COLOR_RESET  := \033[0m
COLOR_BOLD   := \033[1m
COLOR_GREEN  := \033[32m
COLOR_YELLOW := \033[33m
COLOR_BLUE   := \033[34m

# make, make all
all: prepare compile package

prepare:
	go mod download

# make compile
compile: build build6 build-baize
build:
	go build -o $(HOMEDIR)/$(BINARY) ./cmd/bitflip/

build6:
	go build -o $(HOMEDIR)/$(BINARY6) ./cmd/bitflip6/

build-baize:
	go build -o $(HOMEDIR)/$(BINARYBA) ./cmd/baize/

## test: Run all tests
test: prepare
	go test -race -timeout=120s -v -cover $(GOPKGS) -coverprofile=$(COVERAGE_FILE)

## test-short: Run tests in short mode
test-short:
	@echo "$(COLOR_BLUE)Running tests (short mode)...$(COLOR_RESET)"
	go test -short ./...

## test-race: Run tests with race detector
test-race:
	@echo "$(COLOR_BLUE)Running tests with race detector...$(COLOR_RESET)"
	go test -race ./...

## test-coverage: Run tests with coverage and generate HTML report
test-coverage:
	@echo "$(COLOR_BLUE)Running tests with coverage...$(COLOR_RESET)"
	go test -coverprofile=$(COVERAGE_FILE) -covermode=atomic -coverpkg=$(COVERPKGS) $(GOPKGS)
	@echo "$(COLOR_GREEN)Coverage report generated: $(COVERAGE_FILE)$(COLOR_RESET)"
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "$(COLOR_GREEN)HTML coverage report: $(COVERAGE_HTML)$(COLOR_RESET)"

## treemap: Generate SVG treemap of test coverage
treemap: test-coverage
	go-cover-treemap -coverprofile $(COVERAGE_FILE) > coverage.svg
	@echo "$(COLOR_GREEN)SVG coverage treemap: coverage.svg$(COLOR_RESET)"

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "$(COLOR_BLUE)Running tests (verbose)...$(COLOR_RESET)"
	go test -v -count=1 ./...

## benchmark: Run benchmarks
benchmark:
	@echo "$(COLOR_BLUE)Running benchmarks...$(COLOR_RESET)"
	go test -bench=. -benchmem ./...

## test-codec: Run codec package tests only
test-codec:
	@echo "$(COLOR_BLUE)Running codec tests...$(COLOR_RESET)"
	go test -v ./sonar/codec/...

## test-stat: Run stat package tests only
test-stat:
	@echo "$(COLOR_BLUE)Running stat tests...$(COLOR_RESET)"
	go test -v ./stat/...

## test-client: Run client package tests only
test-client:
	@echo "$(COLOR_BLUE)Running client tests...$(COLOR_RESET)"
	go test -v ./sonar/client/...

## test-server: Run server package tests only
test-server:
	@echo "$(COLOR_BLUE)Running server tests...$(COLOR_RESET)"
	go test -v ./sonar/server/...

## test-config: Run config package tests only
test-config:
	@echo "$(COLOR_BLUE)Running config tests...$(COLOR_RESET)"
	go test -v ./sonar/config/...

# make package
package:
	rm -rf $(OUTDIR)
	mkdir -p $(OUTDIR)
	mv $(BINARY) $(OUTDIR)/
	mv $(BINARY6) $(OUTDIR)/
	mv $(BINARYBA) $(OUTDIR)/

# make lint
lint:
	golangci-lint run ./...

## fmt: Format all Go files
fmt:
	@echo "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)"
	gofmt -s -w .
	@echo "$(COLOR_GREEN)Code formatted successfully$(COLOR_RESET)"

## fmt-check: Check if code is formatted
fmt-check:
	@echo "$(COLOR_BLUE)Checking code formatting...$(COLOR_RESET)"
	@test -z "$$(gofmt -l .)" || (echo "$(COLOR_YELLOW)The following files need formatting:$(COLOR_RESET)" && gofmt -l . && exit 1)
	@echo "$(COLOR_GREEN)All files are properly formatted$(COLOR_RESET)"

## vet: Run go vet
vet:
	@echo "$(COLOR_BLUE)Running go vet...$(COLOR_RESET)"
	go vet ./...

## check: Run fmt-check, vet, and lint
check: fmt-check vet lint
	@echo "$(COLOR_GREEN)All checks passed!$(COLOR_RESET)"

# make clean
clean:
	go clean
	rm -rf $(OUTDIR)
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML) coverage.svg

## tidy: Tidy and verify dependencies
tidy:
	@echo "$(COLOR_BLUE)Tidying dependencies...$(COLOR_RESET)"
	go mod tidy
	go mod verify
	@echo "$(COLOR_GREEN)Dependencies tidied$(COLOR_RESET)"

## install-tools: Install development tools
install-tools:
	@echo "$(COLOR_BLUE)Installing development tools...$(COLOR_RESET)"
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@which go-cover-treemap > /dev/null || (echo "Installing go-cover-treemap..." && \
		go install github.com/nikolaydubina/go-cover-treemap@latest)
	@echo "$(COLOR_GREEN)Tools installed$(COLOR_RESET)"

## ci: Run continuous integration checks
ci: prepare check test-race test-coverage
	@echo "$(COLOR_GREEN)CI checks passed!$(COLOR_RESET)"

## snapshot: Build local snapshot with goreleaser (no publish)
snapshot:
	goreleaser build --snapshot --clean

## deploy: Create a release with goreleaser
deploy:
	goreleaser release --clean

## help: Display this help message
help:
	@echo "$(COLOR_BOLD)nettools - Makefile Commands$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Usage:$(COLOR_RESET)"
	@echo "  make $(COLOR_GREEN)<target>$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Available targets:$(COLOR_RESET)"
	@awk '/^## / { \
		sub(/^## /, ""); \
		split($$0, a, ":"); \
		printf "  $(COLOR_GREEN)%-18s$(COLOR_RESET)- %s\n", a[1], a[2]; \
	}' Makefile

.PHONY: all prepare compile test test-short test-race test-coverage treemap test-verbose benchmark \
        test-codec test-stat test-client test-server test-config \
        lint fmt fmt-check vet check clean tidy install-tools ci help build build6 build-baize package \
        snapshot deploy
