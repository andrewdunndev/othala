# portal

Astro home portal at `home.dunn.dev`. Three-state design: pre-auth (login), post-auth (tile launcher filtered by groups claim), infra-down (status panel).

Deployed to Cloudflare Pages. Health-check via Cloudflare Worker that polls kanidm and stores status in Workers KV.

Status: empty placeholder. The Phase 1 lab builds the prototype against the lab kanidm. Production version is built post-lab.
