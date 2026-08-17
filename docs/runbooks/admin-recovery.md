# Admin account recovery and AAL operations

Admin accounts cannot use the ordinary email-recovery path (Section 3 explains
why), so losing access needs a different ladder. This is that ladder: what to
enroll so you rarely need it, how admin authority itself works, and the
break-glass steps in order of decreasing convenience. Deploy-specific
transcripts (SSH, container exec, host storage) belong to your own deploy
plane's runbook — this file is the pattern any Othala instance follows.

---

## 1. Prevention: what every admin should have enrolled

Do this once at initial setup. Recovering from a locked state is much harder
than spending ten minutes now.

### Passkeys (AAL1 — primary login)

Enroll a passkey on at least two physical devices (laptop + phone). With two
passkeys across two devices, losing one device is a non-event: log in from the
other and remove the lost device's credential from Settings. A hardware key
(YubiKey) as a third device, stored somewhere you'd remember under stress, is
a good bonus.

### TOTP (AAL2 — required for admin actions)

Admin pages require AAL2. Enroll TOTP from Settings → Two-factor
authentication → Add authenticator app; any TOTP client works. Once enrolled,
signing in with a passkey (AAL1) plus a TOTP step-up (AAL2) is seamless from
the browser — any admin page prompts for it automatically.

### Backup codes (recovery insurance)

After enrolling TOTP, download the backup codes (`lookup_secret` in Kratos
terms) and store them in a password manager. They are the AAL2 fallback when
the authenticator app is unavailable.

**Fully enrolled** means: 2+ passkeys on different devices, TOTP in an
authenticator app, and backup codes saved.

---

## 2. How admin authority works

Admin status is the `metadata_admin.admin` flag on a Kratos identity — a
boolean set only via the Kratos admin API, never through self-service flows,
OIDC claims, or LDAP attributes. The portal reads this flag fresh on every
request via `GET /admin/identities/:id`.

This is deliberate: an attacker who gains access to the portal UI or a family
member's self-service flow cannot elevate themselves to admin by editing their
own identity. The only write path is the network-gated admin API, unreachable
from the internet.

The admin API's identity-update endpoint takes a JSON Patch **array**, not a
merge object — a bare `{"metadata_admin": …}` body is rejected:

```sh
curl -fsS -X PATCH -H 'Content-Type: application/json' \
  -d '[{"op":"add","path":"/metadata_admin/admin","value":true}]' \
  http://localhost:4434/admin/identities/<UUID>
```

That is the same two-op shape the portal itself uses (`setAdminMarker` in
`portal/src/lib/admin-api.ts`). Patch the marker and nothing else — sending a
whole `metadata_admin` object replaces `groups` too, silently stripping an
admin's app access while they can still sign in.

**Groups are separate, and nothing is derived from the marker.** Entry to an
app comes from holding that app's `<svc>-access` group, admins included;
`<svc>-admin` grants the elevated role *inside* an app and admits nobody on
its own. An admin who also uses a service holds both, explicitly. The full
model is `portal/src/lib/gate.ts` and `portal/src/lib/admin-auth.ts`.

---

## 3. Why admin email-recovery is intentionally blocked

For regular family members, "Forgot account?" sends a code to their email and
lets them back in — convenient and safe. For admins, this path is blocked: if
someone compromised an admin's email account, the recovery flow would hand
them full admin access to every account on the system.

The recovery-gate webhook (`kratos/hooks/recovery-gate.jsonnet` +
`fetchAdminMarker` in `portal/src/server/listen.mjs`) intercepts every
recovery attempt after code verification. Kratos posts the identity id; the
gate calls the admin API to read the authoritative `metadata_admin.admin`
flag, and if it is `true`, returns HTTP 403 and Kratos (`can_interrupt: true`)
aborts the flow — no privileged session is issued, even if the recovery code
was entered correctly.

The gate re-reads the flag on **every** attempt, live, with no cache and no
allow-list — that is what makes the console procedure in Section 4 work: an
operator at the admin API can clear the marker, recover, and put it back.

(The jsonnet template also computes an `is_admin` field from
`ctx.identity.metadata_admin.admin`, but Kratos v26.2.0 omits
`metadata_admin` from the after-hook context. The gate ignores that field and
does its own admin-API lookup by `identity_id` instead — transparent to
operators.)

Non-admin family members are unaffected; they recover via email as normal.

---

## 4. Admin recovery ladder

Work from top to bottom. Each step is less convenient and more drastic than
the one above it.

> **Read before you need it.** Steps A and B are ordinary product paths,
> exercised by the e2e suite. Steps C, D and E are console procedures built
> on the Kratos admin API — rehearse them against a throwaway stack before
> you are relying on them at 2am. The ladder does not depend on any claim
> that an admin-issued recovery code "bypasses" the gate; it does not, which
> is why Step D clears the marker first.

### Step A: You have another enrolled device

If you still have a working passkey anywhere, this is not a lockout. Sign in
from that device, then: remove the lost device's credential in Settings →
Security → Passkeys, or (for a lost TOTP app) use a backup code — Step B — to
step up once and immediately enroll a fresh TOTP app.

### Step B: You lost your TOTP app but have a backup code

Sign in with your passkey (AAL1). When prompted for TOTP, choose "Use backup
code" and enter one. You're in at AAL2 — immediately enroll a new TOTP app
before the session expires. Backup codes are single-use; the rest stay valid.
Generate a fresh set after re-enrolling.

### Step C: The other admin recovers you (dual-admin)

The recommended path when a second admin exists. The portal UI refuses to
issue a recovery URL for an admin target (`shouldRefuseRecovery` in
`portal/src/lib/access.ts`, which reads the `metadata_admin.admin` flag and
stops) — so a compromised admin browser session can never mint a recovery URL
for the other admin. Admin-to-admin recovery is console-only by design: the
working admin runs Step D against the locked-out admin's identity, then hands
the resulting `recovery_link` **and** `recovery_code` over an out-of-band
channel you both already trust. Both are needed — the link opens the
recovery page, the code is what it asks for — and the code's lifetime is
short (see Step D), so say "use this in the next few minutes." Restoring the
locked-out admin's marker (the last step of D) is not optional: until it
happens, they're a normal member.

### Step D: Console break-glass (no working admin session)

Use this when neither admin has a working browser session but you can still
reach the Kratos admin API — over SSH to the host, `kubectl exec`, or however
your deploy plane exposes it. The admin API itself is never published to the
network; every deploy plane must reach it some other way. This instance's
exact transcript lives in the deploy plane's own runbook.

The shape:

1. **Save, then clear the admin marker.** The recovery-gate refuses recovery
   for any identity carrying it (Section 3), and it re-reads the marker live
   — clearing it first is what makes the next step land. Record the
   `metadata_admin` value before clearing it; you restore it at step 4.
   Removing the `admin` key only (never a whole-object replace) leaves
   `groups` untouched.
2. **Issue a recovery code**, not a link: `POST /admin/recovery/code`. Some
   instances disable the magic-link strategy entirely
   (`selfservice.methods.link.enabled: false` in `kratos.yml`), in which case
   `/admin/recovery/link` is not a working path — the code method is what
   `selfservice.flows.recovery.use` actually runs. The response carries both
   a `recovery_link` and a `recovery_code`; nothing is emailed. The code's
   lifetime is bounded by `selfservice.methods.code.config.lifespan`
   regardless of the `expires_in` requested — treat the window as minutes,
   and issue a fresh one if it expires.
3. **Open the link, enter the code**, and re-enroll in that session before
   the tab closes: two passkeys across two devices, fresh TOTP, new backup
   codes.
4. **Restore the admin marker**, re-add-only, and compare the result against
   what step 1 recorded. It takes effect on the next request — no restart.
5. **Verify:** two-plus passkeys visible, TOTP + backup codes present, the
   marker back with `groups` unchanged, `/admin` reachable again (proof the
   marker actually works, not just that the patch returned 200), and old
   session cookies invalidated (`revoke_active_sessions` fires automatically
   on credential change). Record the event — date, reason, and the window the
   marker was off — in your ops log.

**Why the marker comes off and goes back on.** The recovery-gate webhook is
wired at the flow level (`selfservice.flows.recovery.after.hooks`,
`can_interrupt: true`) with no exemption for a flow the admin API itself
created. Clearing the marker for the length of the recovery makes the
procedure work whether the hook fires for admin-API-issued codes or not,
which is the property worth having in a break-glass — and it costs nothing:
anyone who can call the admin API can already do far more than flip that
boolean.

### Step E: No devices, no admin-API access — physical access only

The last resort. Get physical (or BMC/serial) access to the host, unlock
whatever encrypts its data volume (your deploy plane's own runbook has the
specifics — a passphrase or key file, however it's stored), start Kratos, and
follow Step D from the local console.

There is no "edit the password hash in Postgres directly" procedure. That
path is undocumented on purpose — normalizing it would create a class of
break-glass that is also trivially abusable. Get Kratos running and use
Step D.

---

## 5. The dual-admin model (recommended)

Two admins — carrying the `metadata_admin.admin` marker on separate
identities — removes the single point of human failure: either can recover
the other via Step C without an Asteroid-grade event, and either can manage
family accounts without waiting on the other. The co-admin runs Step D
against themself the same way an operator would; the portal UI blocks
browser-based admin-to-admin recovery for both of them equally, so console
access is the only path either has.

To add a co-admin: create their identity, toggle the admin marker on (admin
UI, or the marker-only JSON Patch from Section 2 — never a whole
`metadata_admin` object), grant the groups they need (each app's
`<svc>-access`, plus `<svc>-admin` wherever they hold the elevated role), and
have them enroll a second passkey and TOTP per Section 1. Takes effect
immediately, no restart. Both admins should be able to reach the console
independently (SSH key, `kubectl` access — whatever your deploy plane uses).

---

## 6. Webhook authentication note

The recovery-gate webhook requires `RECOVERY_GATE_SECRET` to match on both
Kratos (`Authorization: Bearer <secret>`) and the portal (constant-time
comparison on receive). Empty or mismatched secret fails closed — recovery is
denied, not allowed. Rotate by updating the secret and restarting both
services; verify with a non-admin recovery that the gate still allows it.

---

## Related runbooks and source files

- `docs/runbooks/lost-device.md` — lost/stolen device eviction procedure.
  Read this first when responding to a lost device — force re-login alone is
  insufficient if a credential was enrolled on the device.
- `docs/runbooks/cookie-rotation.md` — rotate session cookies after a console
  recovery.
- `docs/runbooks/secrets-rotation.md` — break-glass rotation of
  `secrets.system`.
- `kratos/kratos.yml` — `selfservice.flows.recovery.after.hooks` (the gate
  wire-up and `can_interrupt: true`).
- `kratos/hooks/recovery-gate.jsonnet` — webhook body template.
- `portal/src/server/listen.mjs` (`fetchAdminMarker`, `handleRecoveryGate`) —
  the gate handler.
- `portal/src/lib/admin.ts` (`requireAdminSession`) — AAL2 step-up at the SSR
  layer.
