# dunn.dev apex — WebFinger bundle

Drop-in package for the Cloudflare Pages function that serves
`dunn.dev/.well-known/webfinger`. Tailscale custom OIDC requires
WebFinger at the email-domain root (per Tailscale KB-1240), NOT on
the IdP subdomain. The auth project itself is on `auth.dunn.dev`;
WebFinger has to live at the apex.

## Files

```
apex/
├── functions/.well-known/webfinger.ts   ← Pages function (single source)
├── scripts/verify-webfinger.sh           ← local + remote verification
└── README.md (this file)
```

## When you wire Tailscale

1. Drop the `apex/functions/` and (optionally) `apex/scripts/` into
   whichever repo serves `dunn.dev` on Cloudflare Pages.

   Likely candidates from your estate:
   - `~/gitlab.com/dunn.dev/home/` (currently empty git init —
     bootstrap it as the apex repo)
   - A new `dunn.dev/landing` or similar

2. Push. CF Pages deploys.

3. Verify before pointing Tailscale at it:
   ```sh
   bash apex/scripts/verify-webfinger.sh dunn.dev
   ```
   Expect: status 200, Content-Type `application/jrd+json`,
   issuer `href` byte-equals `https://auth.dunn.dev/`.

4. Cross-check via [WebFinger Lookup](https://webfinger.net/lookup)
   as an external second opinion.

5. Configure Tailscale: admin console → SSO → Custom OIDC →
   email-domain = `dunn.dev`. Tailscale fetches the WebFinger once,
   locks in the issuer, never re-reads.

## Why this is a one-time setup

Per Tailscale KB-1240: "Tailscale uses the issuer value from your
WebFinger endpoint **only** during the initial setup." After tenant
creation, the issuer is locked in Tailscale's control plane.
Changing it requires contacting Tailscale support.

This is why pre-deploy verification matters more than the eventual
deploy: WebFinger gets read once; you can't fix a typo by
re-deploying.

## Reference

- Tailscale KB-1240: https://tailscale.com/kb/1240/sso-custom-oidc
- RFC 7033 (WebFinger): https://datatracker.ietf.org/doc/html/rfc7033
- `dunn.dev/auth/docs/apex-webfinger-followup.md` — extended notes
- `dunn.dev/auth/hydra/hydra.yml` — `urls.self.issuer` must
  byte-match this WebFinger response's `links[0].href`
