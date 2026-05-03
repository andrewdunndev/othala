# portal

The Astro UI for the dunn.dev auth substrate. Runs on Cloudflare Workers (Astro 6 dropped the Pages target). Hosts the family-facing home portal AND the admin UI.

## Status

Skeleton (Phase 0). Real implementation in Phase 3 of the build.

## Layout

```
portal/
├── package.json
├── astro.config.mjs        # output: hybrid; adapter: cloudflare
├── wrangler.toml           # Workers deploy config
├── src/
│   ├── lib/
│   │   ├── kratos.ts       # public Kratos API client (browser-safe)
│   │   └── admin.ts        # admin Kratos+Hydra wrappers (server-only) + AAL2 guard
│   └── pages/
│       ├── index.astro     # three-state landing/launcher
│       ├── auth/
│       │   ├── login.astro       # Kratos login flow
│       │   ├── recovery.astro    # Kratos recovery (code strategy)
│       │   ├── settings.astro    # Kratos settings (passkeys, password, profile)
│       │   ├── verification.astro
│       │   └── consent.astro     # Hydra consent (forwards to consent service on carmine)
│       └── admin/
│           ├── index.astro
│           ├── users.astro
│           ├── users/
│           │   ├── [id].astro
│           │   └── new.astro
│           ├── groups.astro
│           ├── oauth2.astro
│           └── activity.astro
└── public/
    └── .well-known/
        └── webfinger       # static JSON for Tailscale custom-OIDC
```

## prerender flag is mandatory per page

Astro 6 hybrid mode does not inherit `prerender`. Every page MUST explicitly set:

```astro
---
export const prerender = false;  // SSR
// or
export const prerender = true;   // static
---
```

All current pages are SSR (`prerender = false`) because they read session cookies or call admin APIs server-side.

## AAL2 admin guard

`src/lib/admin.ts` exports `requireAdminSession(Astro)` which is the server-side guard for `/admin/*` routes. It:

1. Reads the Kratos session via whoami
2. Returns redirect to `/auth/login` if no session
3. Returns redirect to `/auth/error?reason=not-admin` if not in admin group
4. Returns redirect to Kratos refresh-login with `?aal=aal2` if session is below aal2
5. Returns the validated session otherwise

Per adversarial review: AAL is enforced at this layer, NOT at Caddy. Caddy `forward_auth` only verifies "any session present"; the per-route AAL2 check is here.

## Deployment

```bash
npm install
npm run build       # Astro builds to dist/
wrangler deploy     # ships to Cloudflare Workers
```

The Workers deploy reads:

- KV namespace `AUTH_HEALTH` (cron Worker writes Kratos /health status; index reads)
- Secrets via `wrangler secret put`: any sensitive tokens (admin URL is internal-only and not reached from Workers — admin pages call carmine via `auth.dunn.dev/consent` for consent, and `auth.dunn.dev/admin-api/...` if we expose a thin admin proxy)

## Design rules

- Match dunn.dev/design: paper palette (`#faf6ed` ground, `#2c2417` ink, `#6b5d4f` secondary, `#c4b99a` rules), monospace for headings, sharp corners, dense rather than editorial
- No em-dashes in copy
- One auth feel: family sees only Kratos-driven flows, no Cloudflare challenges, no consent screens (auto-accept for trusted clients)

## Endpoint usage map

| Page | Kratos API | Hydra/consent | Other |
|---|---|---|---|
| `/` | `GET /sessions/whoami` | — | `GET /api/health` (KV via Worker) |
| `/auth/login` | `POST /self-service/login/api`, `POST /self-service/login?flow=...` | — | WebAuthn ceremonies in client JS |
| `/auth/recovery` | `POST /self-service/recovery/api`, `POST /self-service/recovery?flow=...` | — | — |
| `/auth/settings` | `GET /self-service/settings/api`, `POST /self-service/settings?flow=...` | — | — |
| `/auth/verification` | `POST /self-service/verification?flow=...` | — | — |
| `/auth/consent` | `GET /sessions/whoami` | redirect to `auth.dunn.dev/consent` (consent service) | — |
| `/admin/*` | `GET /sessions/whoami`, admin API via `requireAdminSession` | `GET /admin/clients` (read-only) | — |
