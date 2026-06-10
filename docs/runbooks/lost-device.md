# Lost or stolen device — eviction procedure

This runbook covers the correct response when a family member's device is lost,
stolen, or accessed without their knowledge. Follow it in full: skipping steps
leaves a window where an attacker can regain access even after you believe the
account is secure.

See also `docs/security-review-2026-06-07.md` (HIGH-C) and
`docs/hardening.md` §7 for the threat context.

---

## Why `revokeSubject` (force re-login) alone is insufficient

The **Force re-login** action in the admin UI calls `revokeSubject`, which
deletes the identity's active Kratos sessions and invalidates Hydra login/consent
grants. This cuts the attacker's current session — they are logged out
immediately.

**It does not delete enrolled credentials.**

A passkey (or TOTP seed, or WebAuthn key) is stored in Kratos as a credential
on the identity record, separate from any session. If a thief got a brief
authenticated session — or if the legitimate user was already signed in on the
device — the attacker can enrol *their own* passkey while that session is
live. That credential persists after `revokeSubject` runs. With it, the attacker
can authenticate afresh: the session is gone, but they hold a valid login key.

The same applies to TOTP: if the attacker saw or copied the TOTP QR code, they
have an indefinitely valid second factor even after a force re-login.

**Eviction requires removing the enrolled credentials, not just the sessions.**

---

## The correct eviction sequence

Perform these steps in order. Do not skip to "force re-login" first — that
burns the session before you can audit what credentials need removing.

### Step 1 — Open the user in the admin UI

Navigate to **/admin/users/\<id\>** for the affected identity.

You must have an active admin session at AAL2. If you are prompted for your
second factor (TOTP), complete it before continuing. The admin guard now also
enforces a freshness window (default 8 hours, `OTHALA_ADMIN_FRESHNESS_HOURS`):
if your AAL2 session is stale, you will be re-prompted automatically.

### Step 2 — Audit enrolled credentials

In the **Profile** section, the **credentials** row shows every enrolled method
with a chip:

| Chip | Meaning |
|------|---------|
| `passkey ✓` | One or more FIDO2 passkeys registered |
| `webauthn ✓` | Legacy WebAuthn keys registered |
| `totp ✓` | TOTP authenticator app enrolled |
| `backup codes ✓` | Single-use recovery codes generated |
| `password ✓` | Password set (Jellyfin/LDAP path) |
| `— ` (muted) | Not enrolled |

Ask the user which devices or credential types they had on the lost/stolen
device. Any type that was enrolled and accessible on that device should be
treated as compromised.

If you cannot reach the user (emergency eviction), remove all evictable types
as a conservative response. The user re-enrolls from scratch via the recovery
URL in Step 5.

### Step 2b — Check the identity's recovery email address

While you have the Profile section open, look at the **recoveryEmail** row.

A `recoveryEmail` trait accepts an unverified email address. If the attacker had
a brief authenticated session — even just AAL1 — they could have opened the
settings flow and planted their own address. That address is not removed by
`revokeSubject` or credential eviction, so it survives the rest of this
procedure and stays usable for future account recovery.

**What to check:** the `recoveryEmail` value shown in the Profile section. Ask
the family member whether they recognise it. If they don't, or if it looks like
an address they do not own, clear it:

1. Click **Edit** (top of the Profile section).
2. Clear the **Recovery email** field (leave it blank, or replace it with an
   address the family member controls).
3. Click **Save**.

The legitimate user can set a recovery email of their choice after they
re-enroll in Step 5.

### Step 3 — Remove the affected credential type(s)

Next to each enrolled evictable credential chip, there is a **Remove** button.
Click it for each affected type.

**What Remove does:** it calls the Kratos admin API
`DELETE /admin/identities/{id}/credentials/{type}` and removes **all**
credentials of that type from the identity record. For passkeys, this means
every registered passkey — Kratos does not expose per-instance removal on the
admin API. The legitimate user re-enrolls with new keys after recovery.

**Evictable types (Remove button present):**
- `passkey` — all FIDO2 passkeys
- `webauthn` — all legacy WebAuthn keys
- `totp` — the TOTP shared secret (the authenticator app binding)
- `lookup_secret` (backup codes) — the set of backup codes

**Not evictable from this UI:**
- `password` — Kratos rejects admin deletion of the password credential.
  If a password-authenticated path (Jellyfin LDAP) is in use, change the
  password via the Jellyfin/LDAP admin path instead.

Each Remove action is CSRF-protected and requires an active AAL2 admin session.
The confirmation banner after each removal tells you which type was removed.

### Step 4 — Force re-login (revoke sessions)

After removing the attacker's credentials, click **Force re-login** in the
Actions panel. This:

- Deletes all active Kratos sessions for the identity.
- Invalidates the Hydra login window and consent grants.
- Emits OIDC back-channel logout to every app that supports it.

At this point the attacker has no sessions and no enrolled credentials. They
cannot log in.

### Step 5 — Issue a recovery/enrollment URL

Click **Issue enrollment URL** to generate a one-shot Kratos recovery URL.
Share it with the legitimate user out-of-band (Signal, iMessage, or another
trusted channel — not the compromised email account if that was the attack
vector).

The URL lands the user in the settings flow with a privileged session. They
re-enroll:
1. A new passkey on a trusted device.
2. TOTP on a fresh authenticator app.
3. A new set of backup codes.

The enrollment URL expires (default 24 h). If the user misses it, issue a
new one.

### Step 6 — Optionally rotate the password (if password auth is in use)

If the identity has a `password ✓` chip and the user uses the Jellyfin or
LDAP path, the password may also be compromised (if the attacker had access
to the device's saved credentials). Rotate it via the Jellyfin/LDAP admin
console.

The portal does not expose a password-reset path for the admin-on-behalf-of-user
case by design (Kratos does not allow admin-set passwords without the user's
current password or a privileged recovery session).

---

## Summary checklist

```
[ ] 1. Open /admin/users/<id>  (confirm AAL2 + freshness gate passed)
[ ] 2. Audit the credential chips — note which types were on the lost device
[ ] 2b. Check the recoveryEmail trait — clear any address the user doesn't recognise
[ ] 3. Remove each affected evictable type (passkey / webauthn / totp / backup codes)
[ ] 4. Force re-login  (revoke sessions)
[ ] 5. Issue enrollment URL  — share via Signal/iMessage
[ ] 6. If password in use: rotate via Jellyfin/LDAP admin
[ ] 7. Follow up with the user once they confirm re-enrollment
```

---

## Security gates protecting this surface

- **AAL2 requirement** — the admin user-detail page requires a Kratos session
  at authenticator assurance level 2 (passkey + TOTP). An attacker with only
  the admin's password cannot reach it.

- **AAL2 freshness** — `requireAdminSession` additionally checks that the
  AAL2 elevation happened within `OTHALA_ADMIN_FRESHNESS_HOURS` (default 8 h).
  A stolen admin browser with a stale AAL2 session is redirected to the TOTP
  step-up before any admin action is possible. See `portal/src/lib/admin.ts`.

- **CSRF protection** — every Remove action carries a per-render, per-type,
  per-admin-identity CSRF token (30-min TTL, single-use). A cross-site form
  submission cannot trigger eviction.

- **Console break-glass** — the admin's own account cannot be evicted via
  this UI (the `shouldRefuseRecovery` guard blocks portal-UI admin-to-admin
  recovery). Operator self-recovery uses the console path in
  `docs/runbooks/admin-recovery.md`.

---

## Related runbooks and source files

- `docs/runbooks/admin-recovery.md` — admin self-recovery (locked out, lost
  device, break-glass ladder).
- `docs/security-review-2026-06-07.md` HIGH-C — eviction threat analysis.
- `docs/hardening.md` §7 — sessions & lost-device hardening rationale.
- `portal/src/lib/admin-api.ts` (`deleteCredential`, `EVICTABLE_CREDENTIAL_TYPES`) —
  the Kratos admin API call.
- `portal/src/lib/admin.ts` (`requireAdminSession`) — AAL2 + freshness gate.
- `portal/src/pages/admin/users/[id].astro` — Remove action handler and UI.
