// Cloudflare Pages function — Tailscale custom-OIDC tenant setup.
//
// Path: dunn.dev/.well-known/webfinger
//
// Tailscale's KB-1240 specifies:
//   - This endpoint is consulted EXACTLY ONCE during tenant setup
//     (admin-domain proof).
//   - The `links[0].href` byte-equals Hydra's `urls.self.issuer`.
//   - Content-Type MUST be `application/jrd+json` (NOT plain JSON).
//   - The `resource` query parameter (acct:user@dunn.dev) is read by
//     Tailscale but the spec lets the response be the same regardless;
//     `subject` is informational per the contract.
//
// Locking:
//   The issuer URL is locked into Tailscale's control plane after
//   tenant creation. Changing it requires contacting Tailscale support.
//   Verify the response shape BEFORE pointing Tailscale at it.
//
// Source of truth for the issuer:
//   dunn.dev/othala/hydra/hydra.yml `urls.self.issuer` — currently
//   `https://dag.dunn.dev/` (with trailing slash).
//
// MEDIUM-7 (security review): `subject` is hardcoded to a fixed value
// rather than reflecting the `resource` query parameter. Reflecting
// unbounded untrusted input into a CDN-cached, CORS-* response is a
// cache-poisoning surface. The Tailscale contract treats `subject` as
// informational, so a fixed value is correct.

export const onRequest: PagesFunction = (ctx) => {
  // resource query (acct:user@dunn.dev) is intentionally ignored
  // per MEDIUM-7. Tailscale only validates links[0].href.

  const body = {
    subject: "acct:user@dunn.dev",
    links: [
      {
        rel: "http://openid.net/specs/connect/1.0/issuer",
        href: "https://dag.dunn.dev/",
      },
    ],
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      // RFC 7033 §10.2 — WebFinger uses application/jrd+json, not
      // plain application/json. Tailscale's parser will reject a
      // mis-typed response.
      "Content-Type": "application/jrd+json",
      // RFC 7033 §5 — WebFinger responses are publicly cacheable.
      // The 5 min TTL matches the Astro portal's prior handler.
      "Cache-Control": "public, max-age=300",
      "Access-Control-Allow-Origin": "*",
    },
  });
};
