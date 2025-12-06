.PHONY: help all build server cli example test test-race test-coverage clean run run-server run-example format lint

# Default target
.DEFAULT_GOAL := help

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
BLUE   := \033[0;34m
NC     := \033[0m

# Binary names
BIN_DIR := bin
SERVER_BIN := $(BIN_DIR)/evoting-server
CLI_BIN := $(BIN_DIR)/evoting-cli
EXAMPLE_BIN := $(BIN_DIR)/evoting-example

help:
	@echo "$(BLUE)E-Voting System - Available targets:$(NC)"
	@echo ""
	@echo "$(GREEN)Building:$(NC)"
	@echo "  make all          - Build all binaries (server + cli + example)"
	@echo "  make server       - Build the API server with web interface"
	@echo "  make cli          - Build the CLI verification tool"
	@echo "  make example      - Build the example application"
	@echo ""
	@echo "$(GREEN)Running:$(NC)"
	@echo "  make run-server   - Start the API server (http://localhost:8080)"
	@echo "  make run-example  - Run the example application"
	@echo ""
	@echo "$(GREEN)Testing:$(NC)"
	@echo "  make test         - Run all tests"
	@echo "  make test-race    - Run tests with race detection"
	@echo "  make test-coverage- Generate test coverage report"
	@echo ""
	@echo "$(GREEN)Maintenance:$(NC)"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make format       - Format code with gofmt"
	@echo "  make lint         - Run linter (requires golangci-lint)"
	@echo ""

build: cli

cli:
	@echo "$(BLUE)Building CLI tool...$(NC)"
	@mkdir -p $(BIN_DIR)
	@go build -o $(CLI_BIN) ./cmd/cli
	@echo "$(GREEN)✓ Build complete: $(CLI_BIN)$(NC)"

test:
	@echo "$(BLUE)Running library unit tests...$(NC)"
	@go test ./... -v

test-race:
	@echo "$(BLUE)Running tests with race detection...$(NC)"
	@go test ./... -v -race

test-cli: cli
	@echo "$(BLUE)Running CLI integration tests...$(NC)"
	@python3 cli_test.py
	@echo "$(BLUE)Running CLI integrity tests...$(NC)"
	@python3 integrity_test.py

test-coverage:
	@echo "$(BLUE)Generating test coverage report...$(NC)"
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report generated: coverage.html$(NC)"

format:
	@echo "$(BLUE)Formatting code...$(NC)"
	@go fmt ./...
	@echo "$(GREEN)✓ Code formatted$(NC)"

lint:
	@echo "$(BLUE)Running linter...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
		echo "$(GREEN)✓ Linting complete$(NC)"; \
	else \
		echo "$(YELLOW)⚠ golangci-lint not installed. Install: https://golangci-lint.run/$(NC)"; \
	fi

clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html
	@rm -f audit-package*.json
	@rm -rf test_data_*
	@rm -rf data
	@rm -f cli
	@echo "$(GREEN)✓ Clean complete$(NC)"
