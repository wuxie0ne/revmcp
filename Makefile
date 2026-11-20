.PHONY: all build build-agent-linux-amd64 build-agent-linux-arm64 build-hub test test-e2e vet lint verify-static clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN_DIR := bin

all: build

build: build-hub build-agent-linux-amd64 build-agent-linux-arm64

build-agent-linux-amd64:
	@mkdir -p $(BIN_DIR)
	cd agent && mise exec -- env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="$(LDFLAGS)" -o ../$(BIN_DIR)/revmcp-agent-linux-amd64 ./cmd/revmcp-agent

build-agent-linux-arm64:
	@mkdir -p $(BIN_DIR)
	cd agent && mise exec -- env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags="$(LDFLAGS)" -o ../$(BIN_DIR)/revmcp-agent-linux-arm64 ./cmd/revmcp-agent

build-hub:
	@mkdir -p $(BIN_DIR)
	cd hub && mise exec -- env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="$(LDFLAGS)" -o ../$(BIN_DIR)/revmcp-hub ./cmd/revmcp-hub

verify-static: build-agent-linux-amd64
	@echo "Checking static linkage of $(BIN_DIR)/revmcp-agent-linux-amd64:"
	@if command -v ldd >/dev/null 2>&1; then \
		out=$$(ldd $(BIN_DIR)/revmcp-agent-linux-amd64 2>&1 || true); \
		echo "$$out"; \
		echo "$$out" | grep -E "not a dynamic executable|statically linked" >/dev/null; \
	fi
	@ls -lh $(BIN_DIR)/revmcp-agent-linux-amd64

test:
	cd proto && mise exec -- go test -race -v ./...
	cd agent && mise exec -- go test -race -v ./...
	cd hub   && mise exec -- go test -race -v ./...

test-e2e: build-agent-linux-amd64
	cd hub && REVMCP_AGENT_BIN=$(CURDIR)/$(BIN_DIR)/revmcp-agent-linux-amd64 mise exec -- go test -race -v ./internal/e2e/...

vet:
	cd proto && mise exec -- go vet ./...
	cd agent && mise exec -- go vet ./...
	cd hub   && mise exec -- go vet ./...

lint:
	cd proto && mise exec -- golangci-lint run --config ../.golangci.yml ./...
	cd agent && mise exec -- golangci-lint run --config ../.golangci.yml ./...
	cd hub   && mise exec -- golangci-lint run --config ../.golangci.yml ./...

clean:
	rm -rf $(BIN_DIR)
