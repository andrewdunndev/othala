IMAGE   ?= glauth-kratos
TAG     ?= lab
RUNTIME ?= podman

GO ?= go

# Default fuzz duration; override with `make fuzz-dn FUZZ_TIME=2m`.
FUZZ_TIME ?= 30s

.PHONY: help build test image verify push clean tidy run-local fuzz-dn

help:
	@echo "glauth-kratos: LDAP-to-Kratos bridge"
	@echo ""
	@echo "Targets:"
	@echo "  build      go build the binary into ./glauth-kratos"
	@echo "  test       go test ./..."
	@echo "  tidy       go mod tidy"
	@echo "  image      $(RUNTIME) build the container image"
	@echo "  verify     run the image with --help to confirm the binary is healthy"
	@echo "  run-local  run the binary against a local Kratos (set KRATOS_BRIDGE_ADMIN_TOKEN)"
	@echo "  fuzz-dn    fuzz parseUsernameFromDN for FUZZ_TIME ($(FUZZ_TIME))"
	@echo "  push       push the image to a registry (set IMAGE=<full-registry-path>)"
	@echo "  clean      remove the local binary and image"

build:
	$(GO) build -trimpath -o glauth-kratos .

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

image:
	$(RUNTIME) build -t $(IMAGE):$(TAG) -f Containerfile .

verify:
	$(RUNTIME) run --rm $(IMAGE):$(TAG) --help

run-local: build
	./glauth-kratos --config glauth.cfg

push:
	$(RUNTIME) push $(IMAGE):$(TAG)

fuzz-dn:
	$(GO) test -run=^$$ -fuzz=FuzzParseUsernameFromDN -fuzztime=$(FUZZ_TIME) ./kratos/...

clean:
	rm -f glauth-kratos
	$(RUNTIME) rmi $(IMAGE):$(TAG) || true
