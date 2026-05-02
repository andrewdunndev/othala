# kanidm

Production kanidm configuration scripts (CLI-driven, idempotent). Source of truth for OAuth2 clients, group definitions, scope mappings, LDAPS bind accounts, and access policies.

Pyinfra references these scripts during carmine deploy. Secrets are sourced from Bitwarden out-of-band, not from this repo.

Status: empty placeholder. The Phase 1 lab produces the initial `kanidm-config.sh`. Production version is hardened and reviewed post-lab.
