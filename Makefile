# Makefile — convenience wrappers around docker compose + composer.
# These are *optional*. Everything works with raw docker/composer commands too.
#
# Common targets:
#   make build       — build the dev image
#   make up          — start the container
#   make sh          — interactive shell inside the container
#   make install     — composer install
#   make test        — run the full test suite
#   make qa          — fast quality gate (CS + PHPStan + tests)
#   make qa-full     — full quality gate including mutation testing
#   make down        — stop and remove the container
#
# Pass extra args with ARGS="...":
#   make test ARGS="--filter=ParserTest"

.DEFAULT_GOAL := help

DC      := docker compose
EXEC    := $(DC) exec -T php

.PHONY: help build up down sh install update test test-coverage qa qa-full \
        phpstan cs cs-fix clean

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Available targets:\n\n"} \
	     /^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the dev image
	$(DC) build

up: ## Start the container in the background
	$(DC) up -d

down: ## Stop and remove the container
	$(DC) down

sh: ## Interactive shell inside the container
	$(DC) exec php sh

install: ## composer install
	$(EXEC) composer install

update: ## composer update
	$(EXEC) composer update

test: ## Run the full test suite (ARGS="..." for extra phpunit args)
	$(EXEC) vendor/bin/phpunit $(ARGS)

test-coverage: ## Run tests with HTML coverage (uses Xdebug)
	$(DC) exec -T -e XDEBUG_MODE=coverage php vendor/bin/phpunit --coverage-html=var/coverage --coverage-text

phpstan: ## Run PHPStan
	$(EXEC) composer phpstan

cs: ## Check code style (no changes)
	$(EXEC) composer cs:check

cs-fix: ## Apply code-style fixes
	$(EXEC) composer cs:fix

qa: ## Fast quality gate (CS + PHPStan + tests)
	$(EXEC) composer qa

qa-full: ## Full quality gate (CS + PHPStan + coverage + mutation)
	$(EXEC) composer qa:full

clean: ## Remove generated artefacts
	rm -rf var vendor composer.lock
