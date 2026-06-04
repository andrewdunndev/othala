Audiobookshelf is a self-hosted server for audiobooks and podcasts, with
per-user collections and playback-progress sync across devices. It speaks plain
OpenID Connect: the user is redirected to the identity provider, returns with
an authorization code at `/auth/openid/callback`, and the server exchanges it
for tokens.

This fixture is the minimal, well-behaved OIDC relying party — no JMESPath
expressions, no nested `resource_access` structure, just a `groups` claim. A
single group-to-role map decides whether the signed-in identity is an admin or
a regular user; everything finer-grained (which libraries, which folders) is
managed inside Audiobookshelf itself. It is the counterpoint to the Grafana
example: same protocol, far simpler claim shape.
