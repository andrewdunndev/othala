.PHONY: help lab-up lab-sync lab-deploy lab-ssh lab-ip lab-dns-up lab-dns-down lab-down lab-secrets

LAB_DIR := lab
COMPOSE_DIR := $(LAB_DIR)/compose

help:
	@echo "dunn.dev/othala — SSO substrate (Ory Kratos + Hydra + glauth-kratos + Astro UI)"
	@echo ""
	@echo "Phase 1 lab spike:"
	@echo "  lab-secrets   generate fresh secrets to lab/compose/.env (runs once)"
	@echo "  lab-up        provision GCP lab VM (requires GCP_PROJECT)"
	@echo "  lab-dns-up    create auth-lab + keep-lab DNS A records (Cloudflare)"
	@echo "  lab-sync      rsync repo to VM"
	@echo "  lab-deploy    deploy compose stack on VM (auto-fires after sync)"
	@echo "  lab-ssh       SSH to lab VM"
	@echo "  lab-ip        print lab VM public IP"
	@echo "  lab-dns-down  remove auth-lab + keep-lab DNS A records"
	@echo "  lab-down      tear down lab VM"
	@echo ""
	@echo "Required env (in shell or .envrc):"
	@echo "  GCP_PROJECT   GCP project for lab VMs"
	@echo "  CF_API_TOKEN  Cloudflare API token (Zone:DNS:Edit on dunn.dev)"
	@echo "  CF_ZONE_ID    Cloudflare zone ID for dunn.dev"
	@echo ""
	@echo "Status:"
	@echo "  See docs/STATUS.md for current direction and lab progress."

lab-secrets:
	@if [ -f $(COMPOSE_DIR)/.env ]; then \
		echo "ERROR: $(COMPOSE_DIR)/.env already exists. Delete it first to regenerate." >&2; \
		exit 1; \
	fi
	bash $(LAB_DIR)/scripts/gen-secrets.sh > $(COMPOSE_DIR)/.env
	@echo "Generated $(COMPOSE_DIR)/.env"

lab-up:
	bash $(LAB_DIR)/scripts/gcp.sh up

lab-dns-up:
	bash $(LAB_DIR)/scripts/cloudflare-dns.sh up

lab-sync:
	bash $(LAB_DIR)/scripts/sync.sh

lab-deploy:
	bash $(LAB_DIR)/scripts/gcp.sh ssh -- "sudo bash /opt/auth-lab/lab/scripts/deploy.sh"

lab-ssh:
	bash $(LAB_DIR)/scripts/gcp.sh ssh

lab-ip:
	@bash $(LAB_DIR)/scripts/gcp.sh ip

lab-dns-down:
	bash $(LAB_DIR)/scripts/cloudflare-dns.sh down

lab-down:
	bash $(LAB_DIR)/scripts/gcp.sh down
