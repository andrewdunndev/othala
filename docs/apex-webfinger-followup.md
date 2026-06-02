# Follow-up: WebFinger on the dunn.dev apex

Status: BLOCKED on first Tailscale tenant setup. WebFinger is not
load-bearing until then.

## Background

Tailscale custom OIDC requires WebFinger at the email-domain root —
`https://${email-domain}/.well-known/webfinger`. For dunn.dev family
emails this resolves to `https://dunn.dev/.well-known/webfinger`. NOT
on the IdP subdomain (dag.dunn.dev) and NOT on any other subdomain.

Per Tailscale KB-1240, this endpoint is consulted **exactly once**
during initial tailnet setup (admin-domain proof). After that the
configured issuer URL is used for every login.

## Implementation

Add to the dunn.dev apex repo at `functions/.well-known/webfinger.ts`:

```typescript
// Cloudflare Pages function. Tailscale custom-OIDC tenant setup
// fetches this exactly once to prove domain ownership and discover
// the IdP issuer. After tenant creation the issuer is locked into
// Tailscale's control plane and this endpoint is never re-read.
//
// Issuer must byte-match Hydra's urls.self.issuer in
// dunn.dev/othala/hydra/hydra.yml (currently `https://dag.dunn.dev/`).
// Any byte difference (trailing slash, case) breaks Tailscale.

export const onRequest: PagesFunction = () =>
  new Response(JSON.stringify({
    subject: "acct:user@dunn.dev",
    links: [
      {
        rel: "http://openid.net/specs/connect/1.0/issuer",
        href: "https://dag.dunn.dev/",
      },
    ],
  }), {
    headers: {
      "Content-Type": "application/jrd+json",
      "Access-Control-Allow-Origin": "*",
    },
  });
```

## Verification

Before pointing Tailscale at it:

```sh
curl -sH 'Accept: application/jrd+json' \
  'https://dunn.dev/.well-known/webfinger?resource=acct:andrew@dunn.dev'
```

Expect:
- Status 200
- `Content-Type: application/jrd+json`
- `Access-Control-Allow-Origin: *`
- Body has `links[0].rel == "http://openid.net/specs/connect/1.0/issuer"`
- Body has `links[0].href == "https://dag.dunn.dev/"` byte-exact

Then run the same check through `https://webfinger.net/lookup` as an
external second opinion.

## Locking risk

Tailscale "locks in" the issuer at tenant creation. Changing it later
requires contacting Tailscale support per their KB. Test the WebFinger
response in lab against a test Tailscale tenant (free tier) before
pointing the family tailnet at it. Cost of getting this wrong once:
contact-support cycle to migrate; the family is offline from Tailscale
until that resolves.

## Why not on dag.dunn.dev or home.dunn.dev

The previous shape of this repo had an Astro handler at
`portal/src/pages/.well-known/webfinger.ts`. That handler was correct
in shape but lived on the wrong host — Tailscale would query
`dunn.dev/.well-known/webfinger`, not the portal subdomain, and never
find it. Handler deleted in v0.2.0 alongside this follow-up.

## Related

- Tailscale KB-1240: https://tailscale.com/kb/1240/sso-custom-oidc
- RFC 7033 (WebFinger): https://datatracker.ietf.org/doc/html/rfc7033
- `lab/docs/feasibility-q3-tailscale-hydra.md` — original feasibility doc
- `docs/decision.md` — Tailscale WebFinger row
- `hydra/clients/tailscale.yaml` — client manifest with header pointing here
