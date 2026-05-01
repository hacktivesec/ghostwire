.PHONY: help base build build-all web net wifi mobile ad pivot \
        up down shell test test-all clean prune \
        push pull verify sbom

COMPOSE      := docker compose
COMPOSE_BUILD:= GHOSTWIRE_IMAGE_TAG=local GHOSTWIRE_IMAGE_PREFIX=ghostwire $(COMPOSE)
REGISTRY     := ghcr.io
IMAGE_OWNER  := wnoelll
TAG          := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ---- Build targets ----
base: ## Build the shared base image (run first, locally)
	docker build -f Dockerfile.base -t ghostwire-base:dev .

build: web ## Build the web image (default)

build-all: base ## Build base + every variant locally
	@for v in web net ad mobile wifi pivot; do \
	  echo "==> building $$v"; \
	  docker build -f Dockerfile.$$v --build-arg GHOSTWIRE_BASE=ghostwire-base:dev \
	    -t ghostwire-$$v:dev . || exit 1; \
	done

web net wifi mobile ad pivot: base ## Build & start a single variant (locally)
	docker build -f Dockerfile.$@ --build-arg GHOSTWIRE_BASE=ghostwire-base:dev \
	  -t ghostwire-$@:dev .
	$(COMPOSE_BUILD) up -d $@

# ---- Runtime ----
up: ## Start all containers (pulls from GHCR by default)
	$(COMPOSE) up -d

down: ## Stop & remove all containers
	$(COMPOSE) down

shell: ## Shell into the web container
	$(COMPOSE) exec web bash

shell-%: ## Shell into a specific container (e.g. make shell-ad)
	$(COMPOSE) exec $* bash

# ---- Testing ----
test: ## Run smoke tests against web image
	docker run --rm ghostwire-web:dev smoke-test web

test-all: ## Smoke-test every variant locally
	@for v in base web net ad mobile wifi pivot; do \
	  echo "==> smoke $$v"; \
	  docker run --rm ghostwire-$$v:dev smoke-test $$v || exit 1; \
	done

test-%: ## Smoke-test a single variant (e.g. make test-ad)
	docker run --rm ghostwire-$*:dev smoke-test $*

# ---- Registry ----
pull: ## Pull all variants from GHCR at TAG (default: latest)
	@for v in base web net ad mobile wifi pivot; do \
	  docker pull $(REGISTRY)/$(IMAGE_OWNER)/ghostwire-$$v:$${T:-latest}; \
	done

push: ## Tag local dev images and push to GHCR (use for one-offs; prefer CI)
	@for v in base web net ad mobile wifi pivot; do \
	  docker tag ghostwire-$$v:dev $(REGISTRY)/$(IMAGE_OWNER)/ghostwire-$$v:$(TAG); \
	  docker push    $(REGISTRY)/$(IMAGE_OWNER)/ghostwire-$$v:$(TAG); \
	done

verify: ## Verify cosign signature on a tag (V=variant T=tag)
	cosign verify \
	  --certificate-identity-regexp 'https://github.com/$(IMAGE_OWNER)/ghostwire/.*' \
	  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
	  $(REGISTRY)/$(IMAGE_OWNER)/ghostwire-$${V:-web}:$${T:-latest}

sbom: ## Generate SBOM for a local image (V=variant)
	syft ghostwire-$${V:-web}:dev -o spdx-json > sbom-$${V:-web}.spdx.json
	@echo "wrote sbom-$${V:-web}.spdx.json"

# ---- Cleanup ----
clean: ## Remove containers, networks, volumes
	$(COMPOSE) down -v --remove-orphans
	docker image prune -f

prune: clean ## Aggressive: remove all ghostwire images + buildx cache
	-docker images --filter=reference='ghostwire-*' -q | xargs -r docker rmi -f
	-docker images --filter=reference='ghcr.io/$(IMAGE_OWNER)/ghostwire-*' -q | xargs -r docker rmi -f
	docker buildx prune -af
	docker system prune -f
