# consent

Small Go HTTP service that handles Hydra OAuth2 login/consent challenges. Runs alongside Hydra on carmine. **Never publicly exposed** — only reachable via Hydra's redirect (which the user's browser follows back to this service via Caddy on auth.dunn.dev).

## Why this exists

Hydra needs a "login app" and a "consent app" to handle login_challenge and consent_challenge redirects. The standard pattern would be: Hydra redirects the browser to our Astro UI, which calls Hydra admin API to accept/reject.

That doesn't work for us because:

- Astro UI runs on Cloudflare Workers (edge)
- Hydra admin port (4445) is internal to the carmine pod network
- We don't want to expose the admin port publicly OR allowlist Cloudflare's egress IPs

Solution: a tiny Go service co-located with Hydra. The Astro UI redirects users to this service via `auth.dunn.dev/consent` and `auth.dunn.dev/login`; this service validates the Kratos session over the pod network, calls Hydra admin internally, redirects the browser onward.

The user sees: a brief redirect through `auth.dunn.dev` (which they already see for the login flow), no exposure of admin internals.

## Endpoints

| Path | Purpose |
|---|---|
| `GET /login?login_challenge=<id>` | Hydra login challenge handler. If user has Kratos session: auto-accept. If not: redirect to home portal login with return_to. |
| `GET /consent?consent_challenge=<id>` | Hydra consent challenge handler. Auto-accept for trusted clients (skip_consent: true). Inject email, email_verified, name, groups into id_token session. |
| `GET /healthz` | Liveness check |

## Status

Skeleton (Phase 0). Real implementation in Phase 3. The endpoints currently return 501 Not Implemented.

## ID token claim injection

Hydra does NOT auto-populate `email`, `email_verified`, `name` even when scopes `openid email profile` are requested. This service does it during consent acceptance:

```go
session := AcceptConsentRequest{
    GrantScope: challenge.RequestedScope,
    Session: ConsentRequestSession{
        IDToken: map[string]interface{}{
            "email":          identity.Traits.Email,
            "email_verified": identity.VerifiableAddresses[0].Verified,
            "name":           identity.Traits.DisplayName,
            "groups":         identity.MetadataAdmin.Groups,
        },
    },
}
```

The `groups` claim is what apps use for per-app authz (e.g., Mealie's `OIDC_ADMIN_GROUP=admin`).

## Deployment

Production (carmine): runs in a quadlet alongside the Hydra pod. Caddy in front of `auth.dunn.dev` routes `/login` and `/consent` paths to this service; everything else to Hydra.

Lab (GCP): runs as a container in the compose stack on the same network as Hydra and Kratos.

## Future

If we ever want a consent UI for untrusted clients (third-party OAuth2 apps not in our 16-app whitelist), this service grows a "render consent screen" path that returns HTML instead of redirecting. Out of scope for v1.
