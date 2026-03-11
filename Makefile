.PHONY: help build build-all web net wifi mobile ad total \
       up down shell test clean

COMPOSE := docker compose

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ---- Build targets ----

build: total ## Build the total (all-in-one) image

build-all: ## Build every image variant
	$(COMPOSE) build

web: ## Build & start web container
	$(COMPOSE) up -d --build web

net: ## Build & start network container
	$(COMPOSE) up -d --build net

wifi: ## Build & start wifi container
	$(COMPOSE) up -d --build wifi

mobile: ## Build & start mobile container
	$(COMPOSE) up -d --build mobile

ad: ## Build & start AD container
	$(COMPOSE) up -d --build ad

total: ## Build & start total container
	$(COMPOSE) up -d --build total

# ---- Runtime ----

up: ## Start all containers
	$(COMPOSE) up -d

down: ## Stop & remove all containers
	$(COMPOSE) down

shell: ## Shell into the total container
	$(COMPOSE) exec total bash

shell-%: ## Shell into a specific container (e.g. make shell-web)
	$(COMPOSE) exec $* bash

# ---- Testing ----

test: ## Run smoke tests against total image
	$(COMPOSE) run --rm total smoke-test total

test-%: ## Run smoke tests for a variant (e.g. make test-web)
	$(COMPOSE) run --rm $* smoke-test $*

# ---- Cleanup ----

clean: ## Remove containers, networks, volumes
	$(COMPOSE) down -v --remove-orphans
	docker image prune -f
