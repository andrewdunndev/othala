IMAGE ?= dunn.dev/caddy-estate
TAG ?= lab
RUNTIME ?= podman

# Build args — pinned versions of the modules we link in.
CADDY_VERSION ?= v2.8.4
CADDY_DNS_CLOUDFLARE_VERSION ?= v0.2.1
CADDY_SECURITY_VERSION ?= v1.1.62

.PHONY: help build verify push

help:
	@echo "caddy-estate image (built directly from upstream Caddy + plugin modules)"
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
	@echo "  CADDY_SECURITY_VERSION         = $(CADDY_SECURITY_VERSION)"

build:
	$(RUNTIME) build \
		--build-arg CADDY_VERSION=$(CADDY_VERSION) \
		--build-arg CADDY_DNS_CLOUDFLARE_VERSION=$(CADDY_DNS_CLOUDFLARE_VERSION) \
		--build-arg CADDY_SECURITY_VERSION=$(CADDY_SECURITY_VERSION) \
		-t $(IMAGE):$(TAG) -f Containerfile .

verify:
	$(RUNTIME) run --rm $(IMAGE):$(TAG) caddy list-modules | grep -E '(dns.providers.cloudflare|security)'

push:
	$(RUNTIME) push $(IMAGE):$(TAG)
