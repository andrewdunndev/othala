---
name: Tailscale
description: Private mesh VPN. Reach the estate from anywhere via SSO-authenticated tailnet.
url: https://login.tailscale.com/admin
icon: TS
access_group: access-tailscale
auth_kind: oidc
order: 130
---

<!-- TODO: Andrew authors education content. Suggested topics:
- Tailscale custom OIDC against Hydra; WebFinger at the dunn.dev apex
- Install Tailscale on phone / laptop, sign in with the dunn.dev OIDC option
- Once joined, every *.dunn.dev hostname resolves via MagicDNS
- Role / owner assignments happen INSIDE the Tailscale admin console,
  not in this portal — Tailscale ignores OIDC group claims per upstream
- See docs/apex-webfinger-followup.md for the setup flow
-->
