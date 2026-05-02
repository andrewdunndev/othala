# portal

Astro home portal at `home.dunn.dev`. Three-state design driven by Authentik reachability:

1. **Pre-auth** (no session): dunn.dev brand + "Sign in" button → bounces to `auth.dunn.dev` for OIDC redirect
2. **Post-auth** (valid session): tile grid filtered by ID-token `groups` claim, each tile deep-links into the corresponding app
3. **Infra-down** (Authentik unreachable): friendly status panel ("Dunn family services are temporarily offline. Last checked: HH:MM. Retrying automatically.")

## Health-check pattern

A Cloudflare Worker polls Authentik's `/-/health/live/` on a 30s cron and stores `{status, last_seen}` in Workers KV. The Astro page reads from KV at load time, not from carmine directly. Edge-fast for visitors; doesn't hammer carmine when family refreshes during an outage.

The Worker is deployed alongside the Pages site (CF Pages supports Functions and Workers integrations natively).

## Deployment

Cloudflare Pages, deployed via `wrangler` or `astro` build. DNS for `home.dunn.dev` resolves to Cloudflare directly (gray cloud not needed since Pages is on Cloudflare's network).

## Status

Empty placeholder. Lab-phase prototype is built against the lab Authentik (`auth.test.dunn.dev`); production version follows lab validation.

## Family UX flow

1. iPad / iPhone opens `home.dunn.dev` (PWA on home screen, recommended)
2. Page renders dunn.dev brand → Sign-In button visible
3. Tap Sign In → redirect to `auth.dunn.dev` (briefly visible URL change)
4. Authentik login UI (custom-CSS branded to dunn.dev) → conditional UI passkey autofill → Face ID / Touch ID
5. Redirect back to home.dunn.dev → tile grid renders based on group membership
6. Tap tile → app-side OIDC redirect → already authenticated → app loads

Steps 3-5 happen in ~1-2 seconds. Brief auth.dunn.dev URL shift is the standard SSO bounce pattern, not friction.
