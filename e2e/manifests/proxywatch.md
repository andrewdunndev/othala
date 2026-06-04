Proxywatch is a generic stand-in for an internal tool that has no built-in
authentication of its own. Rather than teach the app to speak OIDC, the reverse
proxy in front of it (Caddy or Traefik, via their `forward_auth` directive)
enforces sign-in: before forwarding a request upstream, the proxy makes a
subrequest to the auth provider; a 2xx lets the request through, anything else
redirects the browser to log in.

This is the pragmatic pattern for the long tail of self-hosted dashboards and
admin panels that ship with weak or no auth. Because the gate lives entirely at
the proxy, the manifest is presentation-only — it appears as a tile in the
portal but registers no OAuth client.
