SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help build test lint vet tidy up up-linux down logs sensor smoke clean certs helm-lint helm-package helm-template

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'

build: ## Build all Go binaries locally (sensor uses the non-Linux stub off Linux)
	go build ./...

vet: ## Run go vet
	go vet ./...

lint: vet ## Alias for vet (add golangci-lint here if desired)

test: ## Run unit tests
	go test ./...

tidy: ## Tidy go.mod/go.sum
	go mod tidy

helm-lint: ## Lint the Helm chart
	helm lint deploy/helm/core-payment-solution

helm-package: ## Package the Helm chart to dist/
	@chmod +x scripts/package-helm.sh
	./scripts/package-helm.sh dist

helm-template: ## Render Helm templates (requires webhook + token placeholders)
	helm template honeypot deploy/helm/core-payment-solution \
		--set notifications.slack.webhookUrl='https://hooks.slack.com/services/example' \
		--set secrets.dashboardToken='dev-token'

up: ## Build images and start the deception stack (bridge networking)
	$(COMPOSE) up -d --build

up-linux: ## Start with host networking for real client-IP attribution (Linux only)
	$(COMPOSE) -f docker-compose.yml -f docker-compose.linux.yml up -d --build

tier2: ## Start the Tier-2 emulators (AJP/Ghostcat, kubelet exec, etcd)
	$(COMPOSE) --profile tier2 up -d --build

sensor: ## Start the Tier-2 packet sensor (Linux + host networking only)
	$(COMPOSE) --profile sensor up -d --build sensor

down: ## Stop and remove the stack
	$(COMPOSE) down

logs: ## Tail collector logs
	$(COMPOSE) logs -f collector

smoke: ## Run the end-to-end smoke test against a running stack
	./scripts/smoke-test.sh

clean: ## Remove build artifacts and local state
	rm -rf bin certs *.db
