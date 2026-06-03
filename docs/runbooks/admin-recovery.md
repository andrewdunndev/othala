# Admin recovery runbook

Email recovery is disabled for identities in the `admin` group (H1 /
D3). Admins recover via console / shell only. This runbook covers the
procedures and the recommended posture so it never has to run.

## Posture (do this first, not last)

Every admin enrolls multiple WebAuthn authenticators:

- One platform authenticator on the laptop (Touch ID / Windows Hello)
- One platform authenticator on the phone (Face ID / fingerprint)
- One YubiKey if available (off-site copy in a sealed envelope)

With three authenticators across two physical devices, "lost all
admin authenticators" requires losing both the laptop AND the phone
AND the YubiKey simultaneously. At family scale this is the asteroid
case, not the routine case. Optimize for "lost one device", which is
trivially survivable: log in from any other authenticator and remove
the lost device's credential from the settings flow.

## Why email recovery is off for admins

A compromised Fastmail account would otherwise self-recover the admin.
Email recovery for admins == admin Fastmail is part of the trust
boundary, which we explicitly don't want.

The recovery-gate webhook (handled in `portal/src/server/listen.mjs` via
`portal/src/lib/access.ts`, configured at
`kratos.yml: selfservice.flows.recovery.after.code.hooks`) intercepts
the recovery flow before the privileged session is issued and replies
HTTP 403 if the identity carries the `admin` group. Non-admin family
members continue to recover via email as normal.

## Self-service recovery for non-admin family

Same as before: home portal "Recover account" link, email a code, type
it back, set a new password / register a passkey.

## Console recovery for an admin (break-glass)

Prereq: SSH access to the SSO host with sudo.

### Path A: another admin still has working auth

NOT AVAILABLE for admin-to-admin recovery via the portal UI (HIGH-3).

The "Issue enrollment URL" button on `/admin/users/<id>` refuses to
operate when the target identity is in the `admin` group. The check
fires server-side before calling Kratos `getRecoveryLink`, with a
user-facing notice pointing back here. This closes the gap where one
admin (or an attacker who CSRF'd one admin's session) could issue a
recovery URL for the other admin and take over their account,
bypassing the recovery-gate webhook entirely.

For non-admin family recovery, Path A still applies as before: log in,
navigate to `/admin/users/<id>`, click "Issue enrollment URL", text
the link via Signal/iMessage.

For admin-to-admin recovery, only Path B (console) is supported.

### Path B: every admin authenticator is lost

The asteroid case. Recovery is by Kratos admin CLI on the SSO host.

1. SSH to the SSO host.

2. Open a Kratos admin shell against the running pod:

   ```sh
   sudo podman exec -it auth-kratos sh
   ```

3. Find the identity's ID:

   ```sh
   kratos --endpoint http://localhost:4434 identities list \
     --format json | jq '.[] | select(.traits.username == "<your-username>")'
   ```

4. Issue a recovery URL via the Kratos admin API:

   ```sh
   curl -fsS -X POST \
     -H 'Content-Type: application/json' \
     -d '{"identity_id": "<UUID>", "expires_in": "1h"}' \
     http://localhost:4434/admin/recovery/link
   ```

   Response includes a `recovery_link` value. Note: the admin-issued
   recovery link bypasses the recovery-gate webhook because the gate
   only fires for the public `/self-service/recovery/code` flow, not
   the admin-issued link.

5. Open the link in a clean browser session. Set a new password and
   register at least two authenticators before closing the tab.

6. Log the event in the recent-activity audit (`/admin/activity`) by
   noting "console recovery: <reason>".

### Path C: Kratos itself is unreachable

If the Kratos pod is down hard enough that even `podman exec` fails,
the recovery is at the Postgres layer. This is a database-edit
procedure, not a CLI:

1. Restore the auth pod (priority 0).
2. Once Kratos is back up, run Path B above.

There is NO documented "edit the password hash directly in
postgres.identity_credentials" procedure. Argon2id verification is
deterministic; an attacker with database write access could mint a
working session. Don't normalize that path.

## Verification

After any recovery, confirm:

- Two or more authenticators registered (`/admin/users/<id>` Effective
  Access view shows the credential count).
- Old session cookies invalidated by reusing `revoke_active_sessions`
  (already wired in `kratos.yml` `selfservice.flows.settings.after`).
- Audit log entry exists for the recovery event.

## Webhook authentication (MEDIUM-2)

The recovery-gate webhook accepts only requests carrying the shared
secret in the `X-Webhook-Auth` header. The secret lives in the
`RECOVERY_GATE_SECRET` env var on both Kratos (sent via
`web_hook.config.auth: api_key`) and the consent service
(constant-time compared on receive). Empty env on either side fails
closed.

Rotate by updating Bitwarden, restarting both services, and verifying
a non-admin recovery completes end-to-end.

## Related

- `portal/src/server/listen.mjs` + `portal/src/lib/access.ts`: the gate implementation (in-app, post-convergence).
- `kratos/hooks/recovery-gate.jsonnet`: the request body Kratos sends.
- `kratos/kratos.yml`: the `selfservice.flows.recovery.after.code.hooks`
  block that wires the gate in (with `auth: api_key` for MEDIUM-2).
- `docs/runbooks/cookie-rotation.md`: rotate cookies after a console
  recovery.
- `docs/runbooks/secrets-rotation.md`: A2 break-glass rotation of
  `secrets.system`.
