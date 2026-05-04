IMAGE ?= dunn.dev/consent
TAG ?= lab
RUNTIME ?= podman

# Default fuzz duration; override with `make fuzz-jwk FUZZ_TIME=2m`.
FUZZ_TIME ?= 30s

.PHONY: help build verify push test fuzz-jwk fuzz-manifest

help:
	@echo "consent service — Hydra login/consent challenge handler"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the image"
	@echo "  verify         Run the image and check /healthz"
	@echo "  test           Run go tests"
	@echo "  fuzz-jwk       Fuzz jwkToSigningKey for FUZZ_TIME ($(FUZZ_TIME))"
	@echo "  fuzz-manifest  Fuzz loadClientManifest for FUZZ_TIME ($(FUZZ_TIME))"
	@echo "  push           Push to registry"

build:
	$(RUNTIME) build -t $(IMAGE):$(TAG) -f Containerfile .

verify:
	$(RUNTIME) run --rm -d --name consent-verify -p 4477:4477 $(IMAGE):$(TAG)
	sleep 2
	curl -sf http://localhost:4477/healthz && echo " OK"
	$(RUNTIME) stop consent-verify

test:
	go test ./...

fuzz-jwk:
	go test -run=^$$ -fuzz=FuzzJwkToSigningKey -fuzztime=$(FUZZ_TIME) .

fuzz-manifest:
	go test -run=^$$ -fuzz=FuzzLoadClientManifest -fuzztime=$(FUZZ_TIME) .

push:
	$(RUNTIME) push $(IMAGE):$(TAG)
