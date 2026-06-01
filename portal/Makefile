.PHONY: help install dev build check test image start clean

REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null || echo $(CURDIR)/..)
IMAGE     := dunn.dev/auth-portal
TAG       := lab

help:
	@echo "dunn.dev/auth-portal — Astro Node SSR portal"
	@echo ""
	@echo "Targets:"
	@echo "  install    npm install (lockfile-respecting via npm ci)"
	@echo "  dev        run astro dev on :4321 (point KRATOS_PUBLIC_URL at lab)"
	@echo "  build      astro build (dist/server + dist/client)"
	@echo "  check      astro check (type-check)"
	@echo "  test       node --test on scripts/*.test.mjs (CSRF, webfinger)"
	@echo "  image      podman build -t $(IMAGE):$(TAG)"
	@echo "  start      node ./dist/server/listen.mjs (D-listener; after build)"
	@echo "  clean      rm dist/ + .astro/"

install:
	npm ci

dev:
	npm run dev

build:
	npm run build

check:
	npm run check

test:
	npm test

image:
	cd $(REPO_ROOT) && podman build -t $(IMAGE):$(TAG) -f portal/Containerfile .

start:
	npm run start

clean:
	rm -rf dist .astro
