IMAGE ?= dunn.dev/consent
TAG ?= lab
RUNTIME ?= podman

.PHONY: help build verify push test

help:
	@echo "consent service — Hydra login/consent challenge handler"
	@echo ""
	@echo "Targets:"
	@echo "  build    Build the image"
	@echo "  verify   Run the image and check /healthz"
	@echo "  test     Run go tests"
	@echo "  push     Push to registry"

build:
	$(RUNTIME) build -t $(IMAGE):$(TAG) -f Containerfile .

verify:
	$(RUNTIME) run --rm -d --name consent-verify -p 4477:4477 $(IMAGE):$(TAG)
	sleep 2
	curl -sf http://localhost:4477/healthz && echo " OK"
	$(RUNTIME) stop consent-verify

test:
	go test ./...

push:
	$(RUNTIME) push $(IMAGE):$(TAG)
