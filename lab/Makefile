SCRIPTS := scripts
COMPOSE := compose
AUTH_DIR := /opt/auth-lab

GCP_PROJECT ?= $(shell grep GCP_PROJECT .env 2>/dev/null | cut -d= -f2)
GCP_ZONE ?= $(shell grep GCP_ZONE .env 2>/dev/null | cut -d= -f2)
DOMAIN ?= $(shell grep DOMAIN .env 2>/dev/null | cut -d= -f2)

export GCP_PROJECT GCP_ZONE DOMAIN

.PHONY: help up down ssh ip sync deploy teardown smoke smoke-local test logs caddy-image dns-update bcrypt

help: ## Show this help
	@grep -E '^[a-zA-Z_%-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'

# --- GCP VM ---

up: ## Create GCP VM (e2-medium, ~$$0.03/hr, auto-deletes in 2hr)
	$(SCRIPTS)/gcp.sh up

down: ## Destroy GCP VM
	$(SCRIPTS)/gcp.sh down

ssh: ## SSH to VM
	$(SCRIPTS)/gcp.sh ssh

ip: ## Print VM external IP
	@$(SCRIPTS)/gcp.sh ip

# --- Caddy image (build locally, push to registry, or load on VM) ---

caddy-image: ## Build the custom Caddy image (cloudflare DNS-01 plugin)
	$(MAKE) -C ../caddy build

# --- Deployment ---

sync: ## Sync compose, blueprints, scripts to VM (single tarball)
	@echo "Packing files..."
	@tar czf /tmp/auth-lab-sync.tar.gz \
		compose/ scripts/ \
		-C .. authentik/blueprints \
		$$([ -f .env ] && echo .env) \
		$$([ -f .env.example ] && echo .env.example)
	@echo "Uploading tarball (1 scp)..."
	$(SCRIPTS)/gcp.sh scp /tmp/auth-lab-sync.tar.gz /tmp/auth-lab-sync.tar.gz
	@echo "Unpacking on VM (1 ssh)..."
	$(SCRIPTS)/gcp.sh ssh "sudo mkdir -p $(AUTH_DIR) && sudo tar xzf /tmp/auth-lab-sync.tar.gz -C $(AUTH_DIR) && sudo chmod +x $(AUTH_DIR)/scripts/*.sh && rm -f /tmp/auth-lab-sync.tar.gz"
	@rm -f /tmp/auth-lab-sync.tar.gz
	@echo "Files synced to VM (2 connections total)"

deploy: ## Wait for auto-deploy to complete (started by setup-vm.sh)
	@echo "Waiting for Authentik to become healthy (auto-deploy runs on VM startup)..."
	@IP=$$($(SCRIPTS)/gcp.sh ip); \
	for i in $$(seq 1 60); do \
		if curl -sf "http://$$IP:9000/-/health/live/" >/dev/null 2>&1; then \
			echo "Authentik healthy after $$((i * 10))s at $$IP:9000"; \
			echo "Waiting 90s for blueprints + token generation..."; \
			sleep 90; \
			echo "=== Deploy complete ==="; \
			break; \
		fi; \
		if [ $$((i % 6)) -eq 0 ]; then echo "  waiting... ($$((i * 10))s)"; fi; \
		sleep 10; \
		if [ $$i -eq 60 ]; then \
			echo "ERROR: Authentik not healthy after 600s"; \
			echo "  SSH: make ssh"; \
			echo "  Logs: make logs"; \
			exit 1; \
		fi; \
	done

teardown: ## Tear down compose stack on VM
	$(SCRIPTS)/gcp.sh ssh "cd $(AUTH_DIR)/compose && sudo podman-compose down -v"

# --- DNS ---

dns-update: ## Print instructions to update Cloudflare DNS
	@echo "Set *.test.dunn.dev A record to: $$($(SCRIPTS)/gcp.sh ip)"
	@echo "  Cloudflare → DNS → Add Record → Type: A, Name: *.test, Content: $$($(SCRIPTS)/gcp.sh ip), Proxy: OFF (gray cloud)"

# --- Testing ---

smoke: sync ## Run smoke tests against VM
	$(SCRIPTS)/gcp.sh ssh "sudo bash $(AUTH_DIR)/scripts/smoke.sh"

smoke-local: ## Run smoke tests locally on VM (single SSH)
	$(SCRIPTS)/gcp.sh ssh "cd $(AUTH_DIR) && source .env 2>/dev/null; sudo bash scripts/smoke-local.sh"

test: ## Run Playwright tests from local machine
	cd tests && npx playwright test

# --- Utility ---

logs: ## Tail compose logs on VM
	$(SCRIPTS)/gcp.sh ssh "cd $(AUTH_DIR)/compose && sudo podman-compose logs -f --tail=50"

bcrypt: ## Generate a bcrypt hash for ADMIN_BCRYPT_HASH (prompt for password)
	@echo "Enter the admin password (will not echo):"
	@read -s PW && echo "" && podman run --rm caddy:2-alpine caddy hash-password --plaintext "$$PW"
