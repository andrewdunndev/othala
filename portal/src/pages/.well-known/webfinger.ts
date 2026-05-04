// WebFinger endpoint (RFC 7033) for Tailscale custom-OIDC discovery.
//
// Tailscale's `--login-server=` issues a WebFinger query of the form
//   GET /.well-known/webfinger?resource=acct:user@dunn.dev
// and reads the `links` array for `rel = http://openid.net/specs/connect/1.0/issuer`.
// The href there must byte-match Hydra's `urls.self.issuer` and the
// `issuer` field in `/.well-known/openid-configuration` exactly. A
// single byte of difference (trailing slash, scheme case, etc.) causes
// Tailscale to reject the discovery.
//
// Production Hydra (`hydra/hydra.yml`) sets:
//   urls.self.issuer: https://auth.dunn.dev/
// Lab Hydra sets a different issuer (auth-lab.<sslip>/). The handler
// reads HYDRA_ISSUER_URL at request time so each instance returns its
// own issuer; the production fallback ships the production issuer.
//
// Headers:
//   Content-Type: application/jrd+json   (per RFC 7033 §10.2; not JSON)
//   Access-Control-Allow-Origin: *       (Tailscale OIDC discovery is
//                                          a server-to-server fetch but
//                                          the spec recommends `*` and
//                                          some clients fetch via XHR)

import type { APIRoute } from 'astro';

export const prerender = false;

const DEFAULT_ISSUER = 'https://auth.dunn.dev/';

function resolveIssuer(): string {
  // Read at request time (not module load) so SSR pods inherit a
  // refreshed env without a code change. Trailing slash is part of
  // the byte-match contract; pad it on if the operator's value forgot.
  const v = process.env.HYDRA_ISSUER_URL ?? process.env.HYDRA_ISSUER ?? DEFAULT_ISSUER;
  return v.endsWith('/') ? v : `${v}/`;
}

// SAFE_SUBJECT is the fixed value emitted in `subject`, regardless of
// the inbound `resource` query (MEDIUM-7). The Tailscale custom-OIDC
// contract treats `subject` as informational; only the issuer href in
// `links[]` is load-bearing for discovery. Reflecting `?resource=`
// verbatim into a 5-min CDN-cached, CORS-* response is a cache-pollution
// surface; hardcoding the field closes it.
const SAFE_SUBJECT = 'acct:user@dunn.dev';

export const GET: APIRoute = (_ctx) => {
  // resource is intentionally ignored: see SAFE_SUBJECT comment above.

  const body = {
    subject: SAFE_SUBJECT,
    links: [
      {
        rel: 'http://openid.net/specs/connect/1.0/issuer',
        href: resolveIssuer(),
      },
    ],
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'Content-Type': 'application/jrd+json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=300',
    },
  });
};
