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
via the admin UI (Admin → Users → Edit → toggle admin marker) or from the
console:

```sh
# From inside the Kratos container. This endpoint takes a JSON Patch ARRAY,
# not a merge object — a bare {"metadata_admin": …} body is rejected.
curl -fsS -X PATCH \
  -H 'Content-Type: application/json' \
  -d '[{"op":"add","path":"/metadata_admin/admin","value":true}]' \
  http://localhost:4434/admin/identities/<UUID>
```

(That is the same two-op shape the portal itself uses — see `setAdminMarker`
in `portal/src/lib/admin-api.ts`. If `metadata_admin` is absent entirely, add
it first: `[{"op":"add","path":"/metadata_admin","value":{"admin":true}}]`.)

Patch the marker and nothing else. Never send a whole `metadata_admin` object
here: it replaces `groups` as well, and silently stripping an admin's groups
leaves them able to sign in while every app denies them.

**Groups are separate, and nothing is derived from the marker.** Entry to an
app comes from holding that app's `<svc>-access` group — for everyone, admins
included. `<svc>-admin` grants the elevated role *inside* the app and admits
nobody on its own. So an admin who uses a service holds both, explicitly:
`["keep-access", "keep-admin"]`. Read the identity before you write it:

```sh
curl -fsS http://localhost:4434/admin/identities/<UUID> | jq '.metadata_admin'
```

The full model, and what enforces each half, is in `docs/access-model.md`.

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

The gate re-reads that flag from the admin API on **every** attempt
(`fetchAdminMarker` in `portal/src/server/listen.mjs`). It holds no cached
copy and no allow-list. That is what makes the console procedure in Section 4
work: an operator at the Kratos admin API can clear the marker, recover, and
put it back.

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

> **Read before you need it.** Steps A and B are ordinary product paths and
> are exercised by the e2e suite. Steps C, D and E are console procedures
> assembled from the Kratos admin API; they have **not** been rehearsed
> end-to-end against a live stack. Drill them in the QEMU lab before you are
> relying on them at 2am. Two things they must be drilled against are called
> out in place below: the recovery **link** strategy is disabled on this
> instance, and the recovery-gate's admin-403 is wired at the flow level, so
> the ladder deliberately does not depend on any claim that an admin-issued
> code "bypasses" it.

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

**Why the browser cannot do this:** the portal UI refuses to issue a recovery
URL for an admin target through the "Issue enrollment URL" button — it reads
the `metadata_admin.admin` flag and stops (`shouldRefuseRecovery` in
`portal/src/lib/access.ts`). That guard exists so a compromised admin browser
session cannot issue a recovery URL for the other admin. It is why admin
recovery is console-only.

**For the operator:** do this from your workstation. It is Step D run against
someone else's identity, so the mechanics live there — this step is only about
who runs it and how the result is handed over.

1. Follow **Step D**, steps 1 to 6, using the locked-out admin's identity id
   at step 3.
2. Send the `recovery_link` **and** the `recovery_code` to the locked-out
   admin over a channel you both already trust (Signal, iMessage). Both are
   needed: the link opens the recovery page, the code is what it asks for.
3. Say "use this in the next few minutes" — the code's lifetime is short (see
   the note in Step D, step 5).
4. They open the link in a clean browser window, enter the code, and land in
   the settings flow with a privileged session. They re-enroll passkeys and
   TOTP before closing the tab.
5. **You then restore their admin marker** (Step D, step 8). Until you do,
   they are a normal member. Do not walk away from the console between these
   two steps.

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

3. Find the identity ID by email:

   ```sh
   kratos --endpoint http://localhost:4434 identities list \
     --format json | jq '.[] | select(.traits.email == "your@email.com")'
   ```

4. **Save the current `metadata_admin`, then clear the admin marker.** You are
   about to run a recovery flow, and the recovery-gate refuses recovery for
   any identity carrying that marker (Section 3). The gate re-reads the marker
   live, so clearing it first is what makes the next step land:

   ```sh
   curl -fsS http://localhost:4434/admin/identities/<UUID> \
     | jq '.metadata_admin'          # write this down — you restore it at step 8

   curl -fsS -X PATCH \
     -H 'Content-Type: application/json' \
     -d '[{"op":"remove","path":"/metadata_admin/admin"}]' \
     http://localhost:4434/admin/identities/<UUID>
   ```

   Leave `groups` alone. This patch touches the marker only. (`remove` fails if
   the key is not there. If the `jq` above shows no `admin` key, there is
   nothing to clear — skip to step 5, and skip step 8 as well.)

5. Issue a recovery **code**:

   ```sh
   curl -fsS -X POST \
     -H 'Content-Type: application/json' \
     -d '{"identity_id": "<UUID>", "expires_in": "15m"}' \
     http://localhost:4434/admin/recovery/code
   ```

   The response carries a `recovery_link` **and** a `recovery_code`. You need
   both. Nothing is emailed — this is the admin API handing you the code
   directly.

   > It is `/admin/recovery/code`, not `/admin/recovery/link`. The link
   > (magic-link) strategy is disabled on this instance —
   > `selfservice.methods.link.enabled: false` in `kratos/kratos.yml` — so the
   > link endpoint is not a working path here. The code method is the one
   > that is enabled, and `selfservice.flows.recovery.use: code` is what the
   > flow runs. Note also that the code's own lifetime is bounded by
   > `selfservice.methods.code.config.lifespan` in the same file regardless of
   > the `expires_in` you ask for: treat the window as minutes. If the code is
   > rejected as expired, issue a fresh one.

6. Open the `recovery_link` in your browser and enter the `recovery_code`. You
   land in the settings flow with a privileged session.

7. Re-enroll **in that session**, before the tab closes: at least two passkeys
   across two devices, a fresh TOTP, and new backup codes saved.

8. **Restore the admin marker.** Back at the console:

   ```sh
   curl -fsS -X PATCH \
     -H 'Content-Type: application/json' \
     -d '[{"op":"add","path":"/metadata_admin/admin","value":true}]' \
     http://localhost:4434/admin/identities/<UUID>
   ```

   Then re-read `metadata_admin` and compare it against what you saved at
   step 4. It takes effect on the next request; no restart.

9. Record the event in the operator log: note the date and reason in
   `journalctl` on the host or your ops notes. The window in which the marker
   was off belongs in that note.

**After recovery, verify:**

- Two or more passkeys registered (visible in Settings → Security).
- TOTP re-enrolled and backup codes saved.
- The admin marker is back, and `groups` is exactly what step 4 recorded.
- You can reach `/admin` again (that is the marker actually working, not the
  patch merely returning 200).
- Old session cookies invalidated — the settings flow's `revoke_active_sessions`
  hook fires automatically on passkey/password change and handles this.

**Why the marker comes off and goes back on.** The recovery-gate webhook is
wired at the flow level — `selfservice.flows.recovery.after.hooks` in
`kratos/kratos.yml`, `can_interrupt: true` — with no exemption for a flow the
admin API created. An earlier version of this runbook asserted that admin-API
recovery bypasses the gate; nothing in the config scopes it that way, and it
has never been drilled. Clearing the marker for the length of the recovery
makes the procedure work whether the hook fires or not, which is the property
worth having in a break-glass. It costs nothing: anyone who can call the
Kratos admin API can already do far more than flip that boolean.

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
   (Or via the Kratos admin API, using the marker-only JSON Patch from
   Section 2 — never a whole `metadata_admin` object, which would replace
   their groups.)
3. Give them the groups they need, in the admin UI or in the same patch style.
   A portal admin is not automatically admitted anywhere: they need each
   app's `<svc>-access` group to get in, plus `<svc>-admin` wherever they
   should hold the elevated role.
4. Have the co-admin sign in and verify they reach the admin dashboard.
5. Have the co-admin enroll a second passkey and TOTP per Section 1 above.

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
