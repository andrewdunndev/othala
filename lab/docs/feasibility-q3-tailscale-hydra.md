# Q3: Tailscale custom OIDC against Hydra

## Verdict

**GREEN.** Tailscale's custom OIDC profile is plain-vanilla OIDC discovery
+ authorization-code with a confidential client. Hydra (self-hosted) emits
a discovery document that satisfies every Tailscale requirement out of the
box: `subject_types_supported: ["public"]`, `id_token_signing_alg_values_supported: ["RS256"]`,
`scopes_supported` containing `openid`, `client_secret_basic` and
`client_secret_post` both available, PKCE off by default for confidential
clients. The two pieces of work are operator side, not provider side:

1. Serve a static WebFinger JRD ourselves at `<email-domain>/.well-known/webfinger`
   (Hydra does not emit WebFinger; nobody does).
2. Implement the consent app so it sets `session.id_token.email`,
   `email_verified`, and `name` from the Kratos identity. Self-hosted
   Hydra does not auto-populate these; only Ory Network's hosted product
   does.

The single load-bearing risk is GitHub issue
[tailscale/tailscale#16155](https://github.com/tailscale/tailscale/issues/16155):
Tailscale's WebFinger fetch is fussy about JSON shape and response handling.
Mitigated by serving a known-good static JSON with the right
Content-Type — the Authelia, Authentik, kanidm, and Pocket-ID communities
have all gotten this past Tailscale.

## Tailscale's requirements

- **WebFinger:** must answer at `https://<email-domain>/.well-known/webfinger`,
  responding to `?resource=acct:user@<email-domain>` (URL-encoded as
  `acct%3Auser%40<email-domain>`). Response must be a JRD with
  `subject: "acct:<email>"` and a `links` entry whose `rel` is
  `http://openid.net/specs/connect/1.0/issuer` and whose `href` is the
  exact issuer string Hydra returns from its discovery document. Per
  Tailscale docs: WebFinger is consulted only at "initial setup" of the
  tailnet (the admin-domain proof step), not on every login.
- **OIDC discovery:** must be reachable at `<issuer>/.well-known/openid-configuration`
  and the `issuer` field in that document must byte-match the WebFinger
  `href`.
- **Required claims:** `sub` (any stable string), `email`, `email_verified`,
  and `name`. Tailscale uses `email` as the user identifier in the UI and
  expects `email_verified: true` for trusted-domain sign-up. `picture`
  is consumed if present but optional. `sub` must be stable per user
  across sessions: Hydra's default `public` subject identifier algorithm
  satisfies this.
- **PKCE:** "Tailscale doesn't support Proof Key for Code Exchange (PKCE).
  If the provider enables PKCE by default, it must be disabled to avoid
  installation errors." Per Tailscale's KB-1240.
- **Token endpoint:** Tailscale tries `client_secret_basic` first, then
  falls back to `client_secret_post`. Either is acceptable as long as
  the client is registered with one of those methods. Confidential client
  with a client_secret. Authorization-code grant. Response type `code`.
  Redirect URI exactly `https://login.tailscale.com/a/oauth_response`.
- **Signing:** ES256 or RSA, RSA minimum 2048 bits. Hydra default RS256
  matches.
- **JWE:** id_token must not be encrypted; signed only.

## Hydra's emission

Self-hosted Ory Hydra `/.well-known/openid-configuration` returns
(values from Ory's docs and the upstream config schema):

```json
{
  "issuer": "https://hydra.dunn.dev",
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "userinfo_signing_alg_values_supported": ["none", "RS256"],
  "scopes_supported": ["offline_access", "offline", "openid"],
  "claims_supported": ["sub"],
  "code_challenge_methods_supported": ["plain", "S256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
    "none"
  ],
  "response_types_supported": [
    "code", "code id_token", "id_token", "token id_token",
    "token", "token id_token code"
  ],
  "grant_types_supported": [
    "authorization_code", "implicit", "client_credentials",
    "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"
  ]
}
```

- **Subject types:** `public` is the default and the only enabled algorithm
  unless `oidc.subject_identifiers.supported_types` is widened. Public
  gives every client the same `sub` per user, which is what Tailscale
  expects for stable identity.
- **Signing algorithms:** RS256 only for id_tokens. Matches Tailscale's
  ES256/RS256 requirement.
- **Claims:** Hydra advertises only `sub` in `claims_supported`. Tailscale
  does not validate `claims_supported` (it just consumes whatever is in
  the issued id_token), so this thin advertisement is harmless. The
  actual claims emitted in the id_token come from whatever the consent
  app puts on `session.id_token`.
- **PKCE:** Hydra advertises `S256` and `plain` as available, but PKCE
  is off by default. Two switches govern enforcement, both global:
  `oauth2.pkce.enforced` (off by default) and
  `oauth2.pkce.enforced_for_public_clients` (off by default). For a
  confidential client (which Tailscale registers as), Hydra does not
  require a `code_challenge` unless the global flag is true. Leave both
  off and Tailscale's no-PKCE flow proceeds normally.
- **Token endpoint auth:** Hydra default is `client_secret_basic`, with
  `client_secret_post` available as an alternate per-client setting.
  Tailscale's two-method fallback (basic, then post) means either choice
  works — `client_secret_basic` is the path of least resistance.

## Match analysis

- **Discovery: match.** Issuer-string identity between WebFinger `href`
  and the `issuer` Hydra emits is the only tricky part — both must include
  or both must omit the trailing slash. Hydra's default emission has no
  trailing slash; mirror that in WebFinger.
- **Claims: partial mismatch, fixable in consent app.** Hydra by itself
  does not emit `email`, `email_verified`, or `name` even when a client
  requests `openid email profile` scopes. The auto-mapping behavior
  documented at ory.com/docs/oauth2-oidc/openid-connect-claims-scope-custom
  applies to Ory Network (their hosted Hydra-plus-Kratos managed product),
  not to self-hosted Hydra-plus-our-own-consent-app. The consent app
  must read the Kratos identity and set:

  ```
  session.id_token.email = identity.traits.email
  session.id_token.email_verified = (verifiable_addresses[0].verified === true)
  session.id_token.name = identity.traits.name  // or {given_name, family_name}
  ```

  This is roughly ten lines of glue in the consent service.
- **PKCE: match.** Tailscale refuses PKCE; Hydra defaults to PKCE-off for
  confidential clients. No configuration drift required as long as we
  don't toggle `oauth2.pkce.enforced` true at the Hydra level.

## WebFinger we serve ourselves

RFC 7033 compliant response shape (this is the byte-exact JRD Tailscale
expects, drawn from the FoxIDs and Codeberg integration docs and confirmed
by RFC 7033 §4.4):

```json
{
  "subject": "acct:andrew@dunn.dev",
  "links": [
    {
      "rel": "http://openid.net/specs/connect/1.0/issuer",
      "href": "https://hydra.dunn.dev"
    }
  ]
}
```

Required HTTP behavior:

- Path: `/.well-known/webfinger` at the **email domain root** (so
  `https://dunn.dev/.well-known/webfinger`, not the Hydra subdomain).
- Method: GET. Must accept `?resource=acct:<anything>@dunn.dev` (with
  the `:` and `@` percent-encoded).
- `Content-Type: application/jrd+json` (RFC 7033 §10.2).
- `Access-Control-Allow-Origin: *` (RFC 7033 §5).
- Response is identical regardless of which `acct:` resource is asked for
  (Tailscale only uses this once during tailnet setup; we don't need to
  vary by user).

Hosting options:

- **Cloudflare Pages function** (the path of least resistance): a single
  `functions/.well-known/webfinger.ts` (or `.js`) that returns the JSON
  with the right headers. Cloudflare's own Wildebeest project has a
  reference implementation at
  `cloudflare/wildebeest/functions/.well-known/webfinger.ts`. The
  `home` repo (Astro on CF Pages) is the natural host since it already
  owns `dunn.dev`'s root.
- **Caddy** in carmine could serve a static JSON with `respond` and the
  right Content-Type, but only if `dunn.dev` apex traffic is routed
  through carmine, which it isn't today.

CF Pages function is the recommendation. Cloudflare Worker is also fine
but adds an account-billing dimension that Pages functions avoid for
this trivial workload.

## ID token claims

`email_verified` mapping: Kratos models email verification as
`identity.verifiable_addresses[i].verified` (boolean) on the identity
record. The consent app's job is to map `verifiable_addresses[0].verified`
into `session.id_token.email_verified`. If we want stricter behavior —
refusing to issue an id_token at all when the email is unverified —
that's also a one-line guard in the consent app.

Custom claim configuration in Hydra: nothing to configure on Hydra's
side. Hydra accepts whatever the consent app sets on `session.id_token`
and copies it through. If we later want to add audit-only claims (e.g.
`tailscale_role`), the same path: consent app reads from Kratos identity
metadata, sets `session.id_token.tailscale_role`, and Hydra emits it.

The `oauth2.token_hook` webhook is an alternative mechanism — Hydra
calls our HTTPS endpoint with the session and we return a JSON patch.
Useful for refresh-token claim freshness (issue
[ory/hydra#3879](https://github.com/ory/hydra/issues/3879) shows the
email claim disappearing on refresh in some setups), but not needed for
the initial Tailscale flow.

## Prior art

- **Hydra + Tailscale:** no public write-up of the exact pairing exists
  (searched github.com, community.ory.sh, blog ecosystems). What does
  exist is the structural-equivalent: Authelia + Tailscale, where Authelia
  plays the same OIDC-IDP-as-a-service role Hydra plays for us. The
  Authelia integration (links below) confirms every requirement we'd hit
  with Hydra.
- **Authelia + Tailscale (closest reference):** documented at
  authelia.com/integration/openid-connect/clients/tailscale/. Their
  client config is the template:

  ```yaml
  - client_id: 'tailscale'
    public: false
    require_pkce: false
    pkce_challenge_method: ''
    redirect_uris:
      - 'https://login.tailscale.com/a/oauth_response'
    scopes: ['openid', 'email', 'profile']
    response_types: ['code']
    grant_types: ['authorization_code']
    token_endpoint_auth_method: 'client_secret_basic'
  ```

  Map straight onto Hydra's `hydra create oauth2-client` flags:
  `--token-endpoint-auth-method client_secret_basic`,
  `--grant-type authorization_code`,
  `--response-type code`,
  `--scope openid,email,profile`,
  `--redirect-uri https://login.tailscale.com/a/oauth_response`.
  Do not pass any PKCE-forcing flag.
- **Authentik + Tailscale:** working in the wild (blog.antsu.net write-up).
  Confirms the Authentik-app-slug-must-equal-`tailscale` quirk is
  Authentik-specific, not a Tailscale requirement; Hydra sidesteps it
  entirely.
- **Codeberg + Tailscale, FoxIDs + Tailscale:** also working examples
  in the wild. Both confirm the WebFinger JRD shape we plan to use.
- **Known Tailscale OIDC sign-up wart:**
  [tailscale/tailscale#16155](https://github.com/tailscale/tailscale/issues/16155).
  Tailscale's WebFinger fetcher reports "invalid JSON" against Okta's
  response under some conditions. Working around it: serve our static
  JRD with the documented Content-Type and trailing-newline-free body.
  The Authelia/Authentik communities don't hit this because they serve
  exactly the minimal JRD, which is what we'll do.

## Sources

- [Tailscale custom OIDC providers (KB-1240)](https://tailscale.com/kb/1240/sso-custom-oidc)
- [Tailscale custom OIDC docs portal](https://tailscale.com/docs/integrations/identity/custom-oidc)
- [Tailscale enterprise custom OIDC blog post](https://tailscale.com/blog/custom-oidc-enterprise)
- [Tailscale issue #16155 — OIDC sign-up broken for some IDPs](https://github.com/tailscale/tailscale/issues/16155)
- [Authelia + Tailscale OIDC client integration](https://www.authelia.com/integration/openid-connect/clients/tailscale/)
- [Authelia source for Tailscale integration doc](https://github.com/authelia/authelia/blob/master/docs/content//integration/openid-connect/clients/tailscale/index.md)
- [Authelia discussion #7288: token_endpoint_auth_method with Tailscale](https://github.com/authelia/authelia/discussions/7288)
- [Authentik + Tailscale via WebFinger (antsu.net)](https://blog.antsu.net/custom-tailscale-oidc-provider-with-authentik/)
- [Codeberg + Tailscale OIDC walkthrough](https://kennyqin.com/posts/codeberg-as-an-oidc-provider-for-tailscale/)
- [FoxIDs + Tailscale OIDC walkthrough](https://www.foxids.com/docs/app-reg-howto-oidc-tailscale)
- [Ory Hydra OIDC discovery doc shape](https://www.ory.com/docs/oauth2-oidc/wellknown-endpoint-discovery)
- [Ory Hydra config schema (PKCE flags, subject identifiers)](https://github.com/ory/hydra/blob/master/.schema/config.schema.json)
- [Ory Hydra token_endpoint_auth_method behavior](https://www.ory.com/docs/hydra/debug/token-endpoint-auth-method)
- [Ory Hydra OAuth2 webhooks for claim customization](https://www.ory.com/docs/hydra/guides/claims-at-refresh)
- [Ory subject anonymization (public vs pairwise)](https://www.ory.com/docs/hydra/guides/openid)
- [Ory custom OIDC scopes/claims](https://www.ory.com/docs/oauth2-oidc/openid-connect-claims-scope-custom)
- [Ory issue #3879 — email claim missing on refresh](https://github.com/ory/hydra/issues/3879)
- [Ory issue #1106 — consent claims handling history](https://github.com/ory/hydra/issues/1106)
- [Ory discussion #2326 — PKCE and client_secret](https://github.com/ory/hydra/discussions/2326)
- [Ory discussion #2993 — PKCE enforcement scope](https://github.com/ory/hydra/discussions/2993)
- [RFC 7033 — WebFinger](https://datatracker.ietf.org/doc/html/rfc7033)
- [Cloudflare Wildebeest WebFinger function (reference impl)](https://github.com/cloudflare/wildebeest/blob/main/functions/.well-known/webfinger.ts)
