# caddy

Custom Caddy image build manifest. Produces `dunn.dev/caddy-estate`, the universal Caddy sidecar for the dunn.dev estate.

xcaddy plugins:
- `caddy-dns/cloudflare` — DNS-01 ACME for `*.dunn.dev` subdomains
- forward-auth plugin (selected in lab — see `docs/contribution-strategy.md`)

Replaces the prior `dunn.dev/caddy-cloudflare` once forward-auth plugin selection is finalized.

Status: empty placeholder. The Phase 1 lab builds the image with selected plugins. Production migration of the registry image happens post-lab.
