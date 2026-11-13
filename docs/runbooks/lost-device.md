# Lost or stolen device

Use this when a member's device is lost, stolen or used without their knowledge. Signing out everywhere ends sessions
and Hydra grants but leaves enrolled credentials, so someone holding a brief session can enrol their own passkey, or
keep a copied TOTP seed, and sign in afresh. Eviction removes the credentials first and the sessions with them. Do not
force a re-login before the credentials are audited.

You need an admin session at AAL2, on the member's page in the admin area.

## Eviction

1. **Audit.** The member's credentials row lists each enrolled method. Ask which were on the device and treat each as
   compromised; if you cannot reach them, take every removable type.
2. **Check the recovery email.** The trait accepts an unverified address, and neither sign-out nor credential removal
   clears one a thief planted. If the member does not recognise it, blank it or replace it with an address they
   control.
3. **Remove** each affected type: `webauthn` (security keys), `totp`, `lookup_secret` (backup codes). Each removal
   deletes every credential of that type and signs the member out everywhere. A `password` credential cannot be
   removed here; rotate it in the app with its own password store.
4. **Passkeys** the admin API cannot delete, even as a type. The member removes the lost one from their own settings
   after step 5, then you use sign out everywhere, since removing a passkey ends no sessions. If they cannot be
   reached and the lockout is urgent, delete the identity; it revokes sessions and app grants first and the member
   enrols again through the setup link.
5. **Issue a setup link** and send it over a channel that is not the member's possibly compromised mailbox. It opens
   a privileged settings session in which they enrol a new passkey, an authenticator app and new backup codes. It
   expires after 24 hours; issue another if it lapses.

## A member who holds an elevated role

The portal refuses to remove the last authenticator app or security key from someone who holds an elevated role, so
step 3 is refused. Lower first, remove, then raise again:

1. Lower every elevated role to the app's entry level.
2. Do steps 1 to 3 above, including `totp`, and `lookup_secret` unless the member still holds the codes, and
   `webauthn` if a key was on the device.
3. Issue the setup link. The member enrols a second factor and removes the lost passkey from settings within the five
   minutes the setup session stays privileged.
4. Raise the roles again; the portal allows it once a second factor exists.

## An admin

With a second admin present, revoke the target's admin access first (the portal blocks only revoking the last admin),
then follow the sequence above for an elevated member, then grant admin access back once they hold a second factor.
A sole admin has no one to run this; follow Step D of `docs/runbooks/admin-recovery.md`.

## Related

- `docs/runbooks/admin-recovery.md`: an admin's own account.
- Pinned by `e2e/playwright/tests/p-eviction.spec.ts` (passkeys) and `e2e/playwright/tests/zv-eviction-elevated.spec.ts` (an elevated role) and `e2e/playwright/tests/zx-eviction-admin.spec.ts` (an admin).
