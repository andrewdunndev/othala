## What it's for

Proxywatch is a stand-in for an internal tool with no sign-in of its own. The reverse proxy in front of it enforces
single sign-on, so the manifest is presentation-only: it appears as a tile and registers no OAuth client.

## First time

1. Switch Tailscale on, since the tool is reachable only from the private network.
2. Open the tile. The proxy checks your session and lets you through.

## Good to know

- Signing out of the portal ends access here too.
- The proxy asks the auth provider about every request; anything other than a 2xx sends the browser to sign in.

## Getting help

If the page does not load, check that Tailscale is on, then ask the administrator.
