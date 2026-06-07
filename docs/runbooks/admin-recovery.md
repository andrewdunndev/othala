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

Admin status is controlled by the `OTHALA_ADMIN_SUBJECTS` environment
variable — a comma-separated list of email addresses. This list lives in sops
outside Kratos. To be an admin, your email must be in that list.

This is intentional: an attacker who gains access to the Kratos database or
the portal cannot elevate themselves to admin by editing their own identity.
The list is the only source of truth.

For dual-admin setup (recommended), both emails go in the list:

```
OTHALA_ADMIN_SUBJECTS=operator@example.com,spouse@example.com
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
+ the gate handler in the portal) intercepts every recovery attempt before
Kratos issues a privileged session. If the identity's email is on the
`OTHALA_ADMIN_SUBJECTS` list, the gate returns HTTP 403 and the recovery
stops. This fires even if someone requests a recovery code and types it in
correctly — the gate blocks the session promotion step regardless.

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
operator and spouse on `OTHALA_ADMIN_SUBJECTS`).

**Who does this:** the admin who still has working auth.

**Why it works:** the HIGH-3 guard in the portal UI blocks issuing a recovery
link for admin targets through the normal "Issue enrollment URL" button. That
button checks `shouldRefuseRecovery` (in `portal/src/lib/access.ts`), which
calls `isAdminSubject`. If the target is an admin, it refuses.

The console path (Step D) bypasses this restriction because it calls the
Kratos admin API directly, not the portal. The portal guard exists to prevent
a compromised admin browser session from issuing a recovery URL for the other
admin — it is a defense-in-depth measure, not the only lock.

**For the operator:** do this from your workstation.

1. SSH to carmine.
2. Exec into the Kratos container:

   ```sh
   sudo -u dag XDG_RUNTIME_DIR=/run/user/2002 \
     podman exec -it dag-kratos sh
   ```

   (The `dag` user and UID 2002 are the quadlet service account on carmine.
   Adjust if your deployment differs. [VERIFY ON CARMINE])

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

### Step C (spouse-friendly version)

If Andrew is the one locked out and you need to help:

1. You are signed in to the home portal at dag.dunn.dev as yourself (admin).
2. Go to Admin → Users → find Andrew's account.
3. The "Issue enrollment URL" button will say "Admin recovery is console-only.
   See docs/runbooks/admin-recovery.md." — the portal intentionally blocks
   this to prevent browser-based admin-to-admin takeover.
4. You cannot do Step C from the browser. You need SSH access to carmine (the
   home server) and the console steps above.

If you have SSH access to carmine, use the console steps above. If you do not,
go to Step E.

---

### Step D: Console break-glass (SSH — no working admin session)

Use this when neither admin has a working browser session but SSH to carmine
still works.

1. From the operator Mac (or any machine with your SSH key):

   ```sh
   ssh agd@carmine.dunn.dev
   ```

2. Exec into the Kratos container:

   ```sh
   sudo -u dag XDG_RUNTIME_DIR=/run/user/2002 \
     podman exec -it dag-kratos sh
   ```

   [VERIFY ON CARMINE: confirm the dag service account UID is 2002]

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
   `journalctl` on carmine or your ops notes.

**After recovery, verify:**

- Two or more passkeys registered (visible in Settings → Security).
- TOTP re-enrolled and backup codes saved.
- Old session cookies invalidated — the settings flow's `revoke_active_sessions`
  hook fires automatically on passkey/password change and handles this.

---

### Step E: Asteroid (no devices, no SSH — physical access only)

This is the last resort. It requires physical access to carmine.

1. Sit down at carmine (keyboard + monitor on the machine directly, or BMC
   serial-over-LAN — see `carmine.md` § "SoL access via BMC").
2. Log in as `agd` at the console.
3. Follow Step D above from the local terminal. The Kratos admin API is
   available on localhost inside the container regardless of network state.

The ZFS data pool (`safe`) is encrypted. If carmine rebooted without
TPM2-sealed auto-unlock, you will need to enter the ZFS passphrase first.
That passphrase lives in `pyinfra/secrets.enc.yaml` under
`carmine.zfs_passphrase` (sops-encrypted). If you do not have the sops age
key, you need the passphrase from Bitwarden before carmine will mount the
data pool and start Kratos.

There is no "edit the password hash in Postgres directly" procedure.
That path is not documented because normalizing it would create a class of
break-glass that can also be abused. Get Kratos running and use Step D.

---

## 5. The dual-admin model (recommended)

The safest single-family configuration is two admins: the operator and the
spouse. Both emails on `OTHALA_ADMIN_SUBJECTS`.

What this gives you:

- Either admin can recover the other via Step C (console) without needing an
  Asteroid event.
- Either admin can manage family accounts (onboard a child, reset a family
  member's access) without waiting for the other.
- No single point of human failure.

To add the spouse as an admin:

1. Create an Othala identity for the spouse (Admin → Users → New, or use the
   enrollment URL flow).
2. Edit `pyinfra/secrets.enc.yaml` and add the spouse's email to the
   `OTHALA_ADMIN_SUBJECTS` value.
3. Re-provision and restart the portal: `make dag-secrets HOST=carmine &&
   make dag-deploy HOST=carmine`.
4. Have the spouse sign in and verify they reach the admin dashboard.
5. Have the spouse enroll a second passkey and TOTP per Section 1 above.

Both admins should have SSH keys registered on carmine so either can reach
Step D independently.

---

## 6. If you're the spouse and Andrew is unavailable

This section is written for you, not for a technical audience.

**You still have your own account working:**
Sign in at dag.dunn.dev with your passkey. Go to Admin → Users. If Andrew's
account needs anything a family member needs (reset a password, issue an
enrollment link), you can do that from the admin UI.

**Andrew's account is locked and you need to unlock it:**
The web UI will tell you "Admin recovery is console-only." That is correct.
You cannot do admin-to-admin recovery from the browser. You need to either:
- Use SSH to the home server (carmine) and follow the console steps in
  Section 4, Step C/D above, OR
- Wait for Andrew to have physical or SSH access to carmine.

**Nobody can get into the admin panel at all:**
This is the Asteroid case (Section 4, Step E). You need physical access to
the home server. The steps require the ZFS passphrase and the admin API
commands above. If you're not comfortable with that, write down "Kratos admin
API recovery" and find someone who is — the procedure is straightforward once
you're at a terminal on carmine.

**What you should have in your password manager before you ever need this:**
- Your own Othala passkey (enrolled on phone + laptop)
- Your own TOTP backup codes
- The ZFS passphrase for carmine (`carmine.zfs_passphrase` in the shared
  Bitwarden vault)
- SSH key access to carmine (ask Andrew to add `~/.ssh/authorized_keys` on
  carmine for your key)

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
- `kratos/hooks/recovery-gate.jsonnet` — what the gate sends to the portal.
- `portal/src/lib/admin-auth.ts` (`isAdminSubject`) — the admin-allowlist
  predicate.
- `portal/src/lib/access.ts` (`shouldRefuseRecovery`) — HIGH-3 guard that
  blocks portal-UI admin-to-admin recovery.
- `portal/src/lib/admin.ts` (`requireAdminSession`) — AAL2 step-up at the
  SSR layer.
