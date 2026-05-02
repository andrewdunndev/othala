IMAGE ?= dunn.dev/caddy-estate
TAG ?= lab
RUNTIME ?= podman

# Pinned module versions.
CADDY_VERSION ?= v2.8.4
CADDY_DNS_CLOUDFLARE_VERSION ?= v0.2.1

.PHONY: help build verify push

help:
	@echo "caddy-estate image (built directly from upstream Caddy + cloudflare DNS plugin)"
	@echo ""
	@echo "Targets:"
	@echo "  build    Build the image (uses $(RUNTIME))"
	@echo "  verify   Run the image and dump caddy list-modules"
	@echo "  push     Push to registry (set IMAGE=<full-registry-path>)"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE                          = $(IMAGE)"
	@echo "  TAG                            = $(TAG)"
	@echo "  RUNTIME                        = $(RUNTIME) (podman or docker)"
	@echo "  CADDY_VERSION                  = $(CADDY_VERSION)"
	@echo "  CADDY_DNS_CLOUDFLARE_VERSION   = $(CADDY_DNS_CLOUDFLARE_VERSION)"

build:
	$(RUNTIME) build \
		--build-arg CADDY_VERSION=$(CADDY_VERSION) \
		--build-arg CADDY_DNS_CLOUDFLARE_VERSION=$(CADDY_DNS_CLOUDFLARE_VERSION) \
		-t $(IMAGE):$(TAG) -f Containerfile .

verify:
	$(RUNTIME) run --rm $(IMAGE):$(TAG) caddy list-modules | grep 'dns.providers.cloudflare'

push:
	$(RUNTIME) push $(IMAGE):$(TAG)
