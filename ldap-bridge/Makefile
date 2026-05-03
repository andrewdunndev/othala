IMAGE ?= dunn.dev/glauth-kratos
TAG ?= lab
RUNTIME ?= podman

GLAUTH_VERSION ?= v2.5.0

.PHONY: help build verify push clean test

help:
	@echo "glauth-kratos: custom glauth binary with Kratos backend embedded"
	@echo ""
	@echo "Targets:"
	@echo "  build    Build the image (uses $(RUNTIME))"
	@echo "  verify   Run the image with --help to confirm the binary is healthy"
	@echo "  test     Run go tests on the kratos package"
	@echo "  push     Push to registry (set IMAGE=<full-registry-path>)"
	@echo "  clean    Remove the image"

build:
	$(RUNTIME) build \
		--build-arg GLAUTH_VERSION=$(GLAUTH_VERSION) \
		-t $(IMAGE):$(TAG) -f Containerfile .

verify:
	$(RUNTIME) run --rm $(IMAGE):$(TAG) --help

test:
	go test ./kratos/...

push:
	$(RUNTIME) push $(IMAGE):$(TAG)

clean:
	$(RUNTIME) rmi $(IMAGE):$(TAG) || true
