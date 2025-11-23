# NoshiTalk Makefile
# Build, test, and manage the NoshiTalk encrypted chat system

.PHONY: all build build-all test test-verbose clean install lint fmt vet help
.PHONY: server cli-client gui-client web-client

# Build settings
GO := go
BINARY_DIR := bin
LDFLAGS := -ldflags="-s -w"
BUILD_FLAGS := -trimpath

# Version info
VERSION := 2.0.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Default target
all: build-all

# Build all components
build-all: server cli-client gui-client web-client
	@echo "All components built successfully"
	@ls -la $(BINARY_DIR)/

# Individual component builds
server:
	@echo "Building server..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/noshitalk-server ./cmd/server

cli-client:
	@echo "Building CLI client..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/noshitalk-cli ./cmd/cli-client

gui-client:
	@echo "Building GUI client..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/noshitalk-gui ./cmd/gui-client

web-client:
	@echo "Building web client..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/noshitalk-web ./cmd/web-client

# Run tests
test:
	@echo "Running tests..."
	$(GO) test ./pkg/... -cover

test-verbose:
	@echo "Running tests (verbose)..."
	$(GO) test ./pkg/... -v -cover

test-race:
	@echo "Running tests with race detector..."
	$(GO) test ./pkg/... -race -cover

# Coverage report
coverage:
	@echo "Generating coverage report..."
	@mkdir -p coverage
	$(GO) test ./pkg/... -coverprofile=coverage/coverage.out
	$(GO) tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "Coverage report: coverage/coverage.html"

# Benchmarks
bench:
	@echo "Running benchmarks..."
	$(GO) test ./pkg/... -bench=. -benchmem

# Code quality
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || echo "golangci-lint not installed"
	golangci-lint run ./...

fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

vet:
	@echo "Running go vet..."
	$(GO) vet ./...

# Dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download

tidy:
	@echo "Tidying modules..."
	$(GO) mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BINARY_DIR)
	rm -rf coverage
	$(GO) clean -cache -testcache

# Install binaries to GOPATH/bin
install: build-all
	@echo "Installing binaries..."
	cp $(BINARY_DIR)/noshitalk-server $(GOPATH)/bin/ 2>/dev/null || true
	cp $(BINARY_DIR)/noshitalk-cli $(GOPATH)/bin/ 2>/dev/null || true
	cp $(BINARY_DIR)/noshitalk-gui $(GOPATH)/bin/ 2>/dev/null || true
	cp $(BINARY_DIR)/noshitalk-web $(GOPATH)/bin/ 2>/dev/null || true
	@echo "Installed to GOPATH/bin"

# Development helpers
dev-server: server
	@echo "Starting server in development mode..."
	./$(BINARY_DIR)/noshitalk-server

dev-web: web-client
	@echo "Starting web client in development mode..."
	./$(BINARY_DIR)/noshitalk-web

# Build for release (all platforms)
release: clean
	@echo "Building release binaries..."
	@mkdir -p $(BINARY_DIR)/release
	# Linux AMD64
	GOOS=linux GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-cli-linux-amd64 ./cmd/cli-client
	GOOS=linux GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-web-linux-amd64 ./cmd/web-client
	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-cli-linux-arm64 ./cmd/cli-client
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-cli-darwin-amd64 ./cmd/cli-client
	# macOS ARM64 (M1/M2)
	GOOS=darwin GOARCH=arm64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-cli-darwin-arm64 ./cmd/cli-client
	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_DIR)/release/noshitalk-cli-windows-amd64.exe ./cmd/cli-client
	@echo "Release binaries built in $(BINARY_DIR)/release/"
	@ls -la $(BINARY_DIR)/release/

# Security check
security:
	@echo "Running security checks..."
	@which gosec > /dev/null || echo "gosec not installed (go install github.com/securego/gosec/v2/cmd/gosec@latest)"
	gosec ./... || true

# Help
help:
	@echo "NoshiTalk Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build all components (default)"
	@echo "  build-all    - Build all components"
	@echo "  server       - Build server only"
	@echo "  cli-client   - Build CLI client only"
	@echo "  gui-client   - Build GUI client only"
	@echo "  web-client   - Build web client only"
	@echo "  release      - Build release binaries for all platforms"
	@echo ""
	@echo "Test targets:"
	@echo "  test         - Run tests with coverage"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-race    - Run tests with race detector"
	@echo "  coverage     - Generate HTML coverage report"
	@echo "  bench        - Run benchmarks"
	@echo ""
	@echo "Quality targets:"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  lint         - Run golangci-lint"
	@echo "  security     - Run security checks"
	@echo ""
	@echo "Other targets:"
	@echo "  deps         - Download dependencies"
	@echo "  tidy         - Tidy go.mod"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install binaries to GOPATH/bin"
	@echo "  help         - Show this help"
