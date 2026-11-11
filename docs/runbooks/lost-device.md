# Lost or stolen device — eviction procedure

The response when a member's device is lost, stolen, or accessed without their
knowledge. Follow it in full: skipped steps leave a window for the attacker to
regain access.

Signing out everywhere (`revokeSubject`) ends sessions and Hydra grants but does not delete enrolled
credentials. An attacker with a brief session can enrol their own passkey, or hold a copied TOTP seed, and
authenticate afresh. Eviction removes the credentials, not just the sessions.

---

## The correct eviction sequence

Perform these steps in order. Do not force re-login first; audit the credentials first.

### Step 1 — Open the user in the admin UI

Navigate to **/admin/users/\<id\>** for the affected identity.

This requires an active admin session at AAL2.

### Step 2 — Audit enrolled credentials

In the **Profile** section, the **credentials** row shows every enrolled method
with a chip:

| Chip | Meaning |
|------|---------|
| `passkey ✓` | One or more FIDO2 passkeys registered |
| `webauthn ✓` | Security keys registered |
| `totp ✓` | TOTP authenticator app enrolled |
| `backup codes ✓` | Single-use recovery codes generated |
| `password ✓` | Password set (directory-backed / password-auth path) |
| `— ` (muted) | Not enrolled |

Ask the user which credential types were on the device; treat each as
compromised. If you cannot reach them, remove all evictable types; they
re-enroll via the Step 4 URL.

If a member reports an authenticator app they did not add, remove it from their account page, then use Also sign out everywhere on the same page.

### Step 2b — Check the identity's recovery email address

The `recoveryEmail` trait accepts an unverified address. An attacker with even
an AAL1 session could have planted their own in the settings flow, and neither
`revokeSubject` nor credential eviction removes it. Ask the member whether they
recognise the value in the Profile section; if not, clear it:

1. Click **Edit profile and picture**.
2. Clear the **Recovery email** field (leave it blank, or replace it with an
   address the member controls).
3. Click **Save**.

The user can set their own after re-enrolling in Step 4.

### Step 3 — Remove the affected credential type(s)

Next to each enrolled evictable credential chip, there is a **Remove** button.
Click it for each affected type.

Remove calls the Kratos admin API
`DELETE /admin/identities/{id}/credentials/{type}`, deleting **all**
credentials of that type, then signs the user out everywhere (Kratos sessions,
Hydra login and consent).

**Evictable types (Remove button present):**
- `webauthn` — all security keys
- `totp` — the TOTP shared secret (the authenticator app binding)
- `lookup_secret` (backup codes) — the set of backup codes

**Not evictable from this UI:**
- `password` — Kratos rejects admin deletion of the password credential.
  Where a directory-backed app authenticates by password, rotate it in that
  app's own admin console instead.
- `passkey` — Kratos's admin API cannot delete a passkey credential at all,
  even the whole type (upstream limitation, not a missing UI feature); no
  Remove button is shown. See Step 3b.

### Step 3b — Passkey: self-service removal

Kratos exposes per-credential passkey removal only through the user's own
`/auth/settings`, where each key is listed with its label; the user removes the
one matching the lost device. If they are locked out, issue the Step 4 URL
first: it lands them in a privileged settings session. Removing a passkey signs
no one out, so then click **Sign out everywhere** in the Actions panel.

If the user cannot be reached and full lockout is urgent, the last resort is
**Delete** on this identity (Actions panel): it revokes sessions and app grants
first, and the user re-registers.

### Step 4 — Issue a recovery/enrollment URL

Click **Get setup link** to generate a one-shot Kratos recovery URL.
Share it out-of-band over a trusted channel, not a possibly compromised
mailbox. It lands the user in the settings flow with a privileged session to
re-enroll:
1. A new passkey on a trusted device.
2. TOTP on a fresh authenticator app.
3. A new set of backup codes.

The URL expires (default 24 h); issue a new one if missed.

### Step 5 — Optionally rotate the password (if password auth is in use)

If the identity has a `password ✓` chip and reaches a directory-backed app by
password, the device may have had it saved. Rotate it in that app's own admin
console; the portal has no admin-set password path by design.

## Related

`docs/runbooks/admin-recovery.md` covers an admin's own account.
