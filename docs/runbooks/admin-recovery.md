# Admin account recovery and AAL operations

This runbook is the source of truth for admin account recovery at family
scale — one or two admins (operator + spouse). It is written so a
non-deeply-technical spouse can follow the break-glass steps without needing
the operator present.

---

## 1. Prevention: what every admin should have enrolled

Do this once at initial setup. Recovering from a locked state is much harder
than spending ten minutes now.

### Passkeys (AAL1 — primary login)

Enroll a passkey on at least two physical devices:

- Your laptop (Touch ID / Windows Hello)
- Your phone (Face ID / fingerprint)

With two passkeys across two devices, losing one device is a non-event: log
in from the other and remove the lost device's credential from Settings.

A hardware key (YubiKey) as a third device is a good bonus. Store it
somewhere you would remember under stress — a home safe is fine.

### TOTP (AAL2 — required for admin actions)

Admin pages require AAL2 (two-factor). TOTP is the primary second factor.

1. Open Settings → Two-factor authentication → Add authenticator app.
2. Scan the QR code with your authenticator app (Bitwarden, 1Password, Authy,
   Google Authenticator — any TOTP client works).
3. Confirm with a code.

AAL2 works like this: you sign in with your passkey (AAL1), then any admin
page automatically asks for a TOTP code before letting you in. The step-up is
seamless from the browser.

### Backup codes (recovery insurance)

After enrolling TOTP, download or print the backup codes (lookup_secret in
Kratos terms). These are single-use codes that can replace a TOTP code if you
lose your authenticator app.

Store them in your password manager or somewhere safe. They are the AAL2
fallback.

**Summary: what "fully enrolled" looks like**

- 2+ passkeys on different devices
- TOTP enrolled in an authenticator app
- Backup codes saved in Bitwarden / password manager

---

## 2. How admin authority works

Admin status is controlled by the `metadata_admin.admin` flag on a Kratos
identity — a boolean set only via the Kratos admin API (never settable through
self-service flows, OIDC claims, or LDAP attributes). The portal reads this flag
on every request via `GET /admin/identities/:id` on the internal admin endpoint.

This is intentional: an attacker who gains access to the portal UI or a
family member's self-service flow cannot elevate themselves to admin by editing
their own identity (email, groups, traits). The only write path for
`metadata_admin` is the network-gated admin API, which is not reachable from
the internet. (See docs/adr/08-admin-authority-model.md for the full rationale.)

For dual-admin setup (recommended), both identities get `metadata_admin.admin=true`
via the admin UI (Admin → Users → Edit → toggle admin marker) or:

```sh
# From inside the Kratos container
curl -fsS -X PATCH \
  -H 'Content-Type: application/json' \
  -d '{"metadata_admin":{"admin":true,"groups":["family","admin"]}}' \
  http://localhost:4434/admin/identities/<UUID>
```

---

## 3. Why admin email-recovery is intentionally blocked

For regular family members, "Forgot account?" sends a code to their email
and lets them back in. This is convenient and safe for family accounts.

For admins, this path is deliberately blocked. The reason: if someone
compromised your Fastmail account, they could use the email-recovery flow to
take over the admin account. That would give them full access to every family
account on the system.

Technically, the recovery-gate webhook (`kratos/hooks/recovery-gate.jsonnet`
+ `fetchAdminMarker` in `portal/src/server/listen.mjs`) intercepts every
recovery attempt after code verification. Kratos posts the identity id and
traits to the gate; the gate calls the Kratos admin API to read the
authoritative `metadata_admin.admin` flag. If the flag is `true`, the gate
returns HTTP 403 and Kratos (`can_interrupt: true`) aborts the flow — no
privileged session is issued. This fires even if someone requests a recovery
code and types it in correctly; the gate blocks the session promotion step.

Note: the jsonnet body template (`recovery-gate.jsonnet`) also computes an
`is_admin` field from `ctx.identity.metadata_admin.admin`, but Kratos v26.2.0
omits `metadata_admin` from the after-hook template context. The gate ignores
the jsonnet `is_admin` field and does its own admin-API lookup using the
`identity_id` field instead. This workaround is transparent to operators.

Non-admin family members are unaffected. They recover via email as normal.

---

## 4. Admin recovery ladder

Work from top to bottom. Each step is less convenient and more drastic than
the one above it.

---

### Step A: You have another enrolled device

If you still have a working passkey on any device (laptop, phone, or hardware
key), this is not a lockout situation. Sign in from that device. Then:

- To recover from a lost device: remove the lost device's credential in
  Settings → Security → Passkeys.
- To recover from a lost TOTP app: use a backup code (step B below) to
  complete the AAL2 step-up once, then immediately enroll a new TOTP app.

---

### Step B: You lost your TOTP app but have a backup code

1. Sign in with your passkey (AAL1).
2. When the admin page asks for a TOTP code, click "Use backup code" (or
   equivalent — the flow offers this option when TOTP is unavailable).
3. Enter one of your saved backup codes.
4. You are in at AAL2. Immediately enroll a new TOTP app before the session
   expires.

Backup codes are single-use. After using one, the remaining codes are still
valid. Generate a fresh set from Settings → Two-factor authentication after
re-enrolling.

---

### Step C: The other admin recovers you (dual-admin — the primary break-glass)

This is the recommended path when the dual-admin model is active (both
operator and spouse carrying the `metadata_admin.admin` marker).

**Who does this:** the admin who still has working auth.

**Why it works:** the portal UI blocks issuing a recovery link for admin
targets through the normal "Issue enrollment URL" button — it checks the
`metadata_admin.admin` flag and refuses if the target is an admin.

The console path (Step D) bypasses this restriction because it calls the
Kratos admin API directly, not the portal. The portal guard exists to prevent
a compromised admin browser session from issuing a recovery URL for the other
admin — it is a defense-in-depth measure, not the only lock.

**For the operator:** do this from your workstation.

1. SSH to your host.
2. Exec into the Kratos container:

   ```sh
   sudo -u dag XDG_RUNTIME_DIR=/run/user/<service-uid> \
     podman exec -it dag-kratos sh
   ```

   (The `dag` user and `<service-uid>` are the quadlet service account on your
   host. Adjust UID to match your deployment.)

3. Find the identity ID for the locked-out admin:

   ```sh
   kratos --endpoint http://localhost:4434 identities list \
     --format json | jq '.[] | select(.traits.email == "spouse@example.com")'
   ```

4. Issue a recovery URL:

   ```sh
   curl -fsS -X POST \
     -H 'Content-Type: application/json' \
     -d '{"identity_id": "<UUID-from-step-3>", "expires_in": "1h"}' \
     http://localhost:4434/admin/recovery/link
   ```

   The response contains a `recovery_link`. Copy it.

5. Send the link via Signal or iMessage to the locked-out admin. Set a 1h
   time limit on the conversation: "use this within an hour."

6. The locked-out admin opens the link in a clean browser window. It lands
   them in the settings flow with a privileged session. They re-enroll their
   passkeys and TOTP before closing the tab.

Note: the recovery link issued from the admin API bypasses the recovery-gate
webhook. The gate only fires on the public self-service recovery flow
(`/self-service/recovery/code`), not on admin-API-issued links. This is why
Step C works when email recovery does not.

---

### Step C (co-admin version)

If one admin is locked out and you need to help:

1. You are signed in to the home portal as yourself (admin).
2. Go to Admin → Users → find the locked-out admin's account.
3. The "Issue enrollment URL" button will say "Admin recovery is console-only.
   See docs/runbooks/admin-recovery.md." — the portal intentionally blocks
   this to prevent browser-based admin-to-admin takeover.
4. You cannot do Step C from the browser. You need SSH access to the host
   server and the console steps above.

If you have SSH access to the host, use the console steps above. If you do not,
go to Step E.

---

### Step D: Console break-glass (SSH — no working admin session)

Use this when neither admin has a working browser session but SSH to the host
still works.

1. From your workstation (or any machine with your SSH key):

   ```sh
   ssh <operator-user>@<your-host>
   ```

2. Exec into the Kratos container:

   ```sh
   sudo -u dag XDG_RUNTIME_DIR=/run/user/<service-uid> \
     podman exec -it dag-kratos sh
   ```

3. Find your identity ID by email:

   ```sh
   kratos --endpoint http://localhost:4434 identities list \
     --format json | jq '.[] | select(.traits.email == "your@email.com")'
   ```

4. Issue a self-recovery URL:

   ```sh
   curl -fsS -X POST \
     -H 'Content-Type: application/json' \
     -d '{"identity_id": "<UUID>", "expires_in": "1h"}' \
     http://localhost:4434/admin/recovery/link
   ```

5. Copy the `recovery_link` from the response.

6. Open the link in your browser. You will land in the settings flow with a
   privileged session. Re-enroll passkeys and TOTP before closing the tab.

7. Record the event in the operator log: note the date and reason in
   `journalctl` on the host or your ops notes.

**After recovery, verify:**

- Two or more passkeys registered (visible in Settings → Security).
- TOTP re-enrolled and backup codes saved.
- Old session cookies invalidated — the settings flow's `revoke_active_sessions`
  hook fires automatically on passkey/password change and handles this.

---

### Step E: Asteroid (no devices, no SSH — physical access only)

This is the last resort. It requires physical access to your host.

1. Sit down at the host (keyboard + monitor directly, or BMC serial-over-LAN
   if your hardware supports it).
2. Log in as `<operator-user>` at the console.
3. Follow Step D above from the local terminal. The Kratos admin API is
   available on localhost inside the container regardless of network state.

The ZFS data pool is encrypted. If the host rebooted without TPM2-sealed
auto-unlock, you will need to enter the ZFS passphrase first. That passphrase
lives in your sops-encrypted secrets file under `<host>.zfs_passphrase`. If
you do not have the sops age key, you need the passphrase from your password
manager before the host will mount the data pool and start Kratos.

There is no "edit the password hash in Postgres directly" procedure.
That path is not documented because normalizing it would create a class of
break-glass that can also be abused. Get Kratos running and use Step D.

---

## 5. The dual-admin model (recommended)

The safest single-family configuration is two admins: the operator and the
spouse. Both identities carry the `metadata_admin.admin` marker.

What this gives you:

- Either admin can recover the other via Step C (console) without needing an
  Asteroid event.
- Either admin can manage family accounts (onboard a child, reset a family
  member's access) without waiting for the other.
- No single point of human failure.

To add the spouse as an admin:

1. Create an Othala identity for the spouse (Admin → Users → New, or use the
   enrollment URL flow).
2. In the admin UI, open the spouse's profile and toggle the admin marker on.
   (Or via the Kratos admin API: `PATCH /admin/identities/<UUID>` with
   `{"metadata_admin":{"admin":true,"groups":["family","admin"]}}`.)
3. Have the co-admin sign in and verify they reach the admin dashboard.
4. Have the co-admin enroll a second passkey and TOTP per Section 1 above.

No restart required — the admin marker takes effect immediately on the next
request (the portal reads it from the Kratos admin API on each check).

Both admins should have SSH keys registered on the host so either can reach
Step D independently.

---

## 6. If you're the co-admin and the primary admin is unavailable

This section is written for non-technical co-admins.

**You still have your own account working:**
Sign in to the portal with your passkey. Go to Admin → Users. If another
account needs anything a member needs (reset a password, issue an
enrollment link), you can do that from the admin UI.

**The primary admin's account is locked and you need to unlock it:**
The web UI will tell you "Admin recovery is console-only." That is correct.
You cannot do admin-to-admin recovery from the browser. You need to either:
- Use SSH to the host server and follow the console steps in
  Section 4, Step C/D above, OR
- Wait for the primary admin to have physical or SSH access to the host.

**Nobody can get into the admin panel at all:**
This is the Asteroid case (Section 4, Step E). You need physical access to
the host. The steps require the ZFS passphrase and the admin API commands
above. If you're not comfortable with that, write down "Kratos admin API
recovery" and find someone who is — the procedure is straightforward once
you're at a terminal on the host.

**What you should have in your password manager before you ever need this:**
- Your own Othala passkey (enrolled on phone + laptop)
- Your own TOTP backup codes
- The ZFS passphrase for the host (in your shared password manager vault)
- SSH key access to the host

---

## 7. Webhook authentication note

The recovery-gate webhook requires the `RECOVERY_GATE_SECRET` to match on
both Kratos (sends it as `Authorization: Bearer <secret>`) and the portal
(compares it constant-time on receive). Empty or mismatched secret fails
closed — recovery is denied, not allowed. Rotate by updating the sops secret,
re-provisioning, and restarting both services. Verify with a non-admin
recovery to confirm the gate still allows it.

---

## Related runbooks and source files

- `docs/runbooks/lost-device.md` — **lost/stolen device eviction procedure**:
  audit credentials, remove affected types, force re-login, issue enrollment URL.
  Read this first when responding to a lost device — force re-login alone is
  insufficient if a credential was enrolled on the device.
- `docs/runbooks/email-recovery.md` — deliverability ops for non-admin
  family recovery.
- `docs/runbooks/cookie-rotation.md` — rotate session cookies after a
  console recovery.
- `docs/runbooks/secrets-rotation.md` — break-glass rotation of `secrets.system`.
- `kratos/kratos.yml` — `selfservice.flows.recovery.after.hooks` (the
  gate wire-up and `can_interrupt: true`).
- `kratos/hooks/recovery-gate.jsonnet` — webhook body template; note the
  `is_admin` field is always false in Kratos v26.2.0 (metadata_admin absent
  from after-hook ctx.identity); the gate does its own admin-API lookup.
- `portal/src/server/listen.mjs` (`fetchAdminMarker`, `handleRecoveryGate`) —
  the gate handler; reads `metadata_admin.admin` via the Kratos admin API.
- `portal/src/lib/admin.ts` (`requireAdminSession`) — AAL2 step-up at the
  SSR layer.
