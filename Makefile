.DEFAULT_GOAL := help

# The module path as it currently stands. `make rename` rewrites it.
MODULE := $(shell go list -m)

# How to invoke Compose. Override it if you use Podman, which is a drop-in
# replacement here:
#
#   make up COMPOSE="podman compose"
#
# Note that a `docker` shell alias pointing at podman will NOT work: make runs
# its recipes in /bin/sh, which does not see your shell's aliases.
COMPOSE ?= docker compose

# DSN for the throwaway test database defined in docker-compose.yml.
TEST_DSN := postgres://app:app@localhost:5433/app?sslmode=disable

# Pinned so `make lint` and CI agree, and so the config in .golangci.yml matches
# the tool. golangci-lint is run via `go run` rather than installed: it needs no
# separate setup and never pollutes this module's go.mod with its own dependencies.
GOLANGCI_VERSION := v2.12.2

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup

.PHONY: env
env: ## Create .env from .env.example (never overwrites an existing .env)
	@if [ -f .env ]; then \
		echo ".env already exists; leaving it alone."; \
	else \
		cp .env.example .env && echo "Wrote .env -- edit it before running in anger."; \
	fi

.PHONY: rename
rename: ## Point the template at your project: make rename m=github.com/you/your-project
	@test -n "$(m)" || { echo "usage: make rename m=github.com/you/your-project"; exit 1; }
	@echo "Rewriting module path: $(MODULE) -> $(m)"
	@go mod edit -module "$(m)"
	@grep -rl --include='*.go' -F "$(MODULE)" . | xargs -r sed -i "s|$(MODULE)|$(m)|g"
	@go mod tidy
	@go build ./... && echo "Done -- module is now $(m) and it still builds."

# ---------------------------------------------------------------- develop

.PHONY: run
run: ## Run the server locally (needs Postgres: `make up-db`)
	go run ./cmd/server

.PHONY: build
build: ## Build the server binary into ./bin
	go build -o bin/server ./cmd/server

.PHONY: fmt
fmt: ## Format the code
	gofmt -w .

.PHONY: vet
vet: ## Static analysis
	go vet ./...

.PHONY: tidy
tidy: ## Resolve and pin dependencies
	go mod tidy

.PHONY: lint
lint: ## Run golangci-lint (bug-catching linters; config in .golangci.yml)
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./...

.PHONY: vulncheck
vulncheck: ## Scan dependencies for known vulnerabilities in code you actually call
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# ---------------------------------------------------------------- test

.PHONY: test
test: ## Run unit tests (integration tests skip without a database)
	go test ./...

.PHONY: test-integration
test-integration: ## Run every test, including integration, against a throwaway Postgres
	$(COMPOSE) --profile test up -d postgres-test
	@echo "Waiting for the test database..."
	@until $(COMPOSE) exec -T postgres-test pg_isready -U app -d app >/dev/null 2>&1; do sleep 1; done
	TEST_POSTGRES_DSN="$(TEST_DSN)" go test ./... -count=1
	$(COMPOSE) --profile test down

.PHONY: test-e2e
test-e2e: ## Drive the running stack over real HTTP (needs `make up` first)
	@command -v jq >/dev/null || { echo "test-e2e needs jq"; exit 1; }
	@for f in scripts/e2e/*.sh; do \
		echo "--- $$f"; \
		bash "$$f" || exit 1; \
	done

.PHONY: cover
cover: ## Run every test with coverage and open the HTML report
	$(COMPOSE) --profile test up -d postgres-test
	@until $(COMPOSE) exec -T postgres-test pg_isready -U app -d app >/dev/null 2>&1; do sleep 1; done
	TEST_POSTGRES_DSN="$(TEST_DSN)" go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	$(COMPOSE) --profile test down
	@echo "Wrote coverage.html"

# ---------------------------------------------------------------- stack

.PHONY: up
up: ## Start the full stack (Postgres + migrations + app)
	$(COMPOSE) up --build

.PHONY: up-db
up-db: ## Start only Postgres, for running the app with `make run`
	$(COMPOSE) up -d postgres

.PHONY: down
down: ## Stop the stack and delete its data volume
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail the app logs
	$(COMPOSE) logs -f app

# ---------------------------------------------------------------- migrations

.PHONY: migrate
migrate: ## Apply all pending migrations
	go run ./cmd/server migrate up

.PHONY: migrate-status
migrate-status: ## Show which migrations have been applied
	go run ./cmd/server migrate status

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	go run ./cmd/server migrate down

.PHONY: migrate-reset
migrate-reset: ## Roll back every migration (destroys all data)
	go run ./cmd/server migrate reset
