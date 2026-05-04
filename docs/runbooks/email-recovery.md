# Email recovery: deliverability and operations

Recovery codes go out via Fastmail SMTP from `noreply@dunn.dev`. This
runbook captures the deliverability watch-outs and the verification
loop after the first lab recovery test.

## Pre-rollout checks

After the first end-to-end recovery flow in lab (or production), open
a code-recovery email at:

- Gmail (most family addresses)
- Apple Mail / iCloud
- a corporate inbox if any family member uses one (Outlook 365, Google
  Workspace)

Check:

1. Subject and from-address rendered correctly. Fastmail signs
   outbound, so SPF/DKIM should pass.
2. The email landed in Inbox, not Spam. "noreply@" prefixes can flag
   stricter receivers; if any provider quarantines it, the family member
   can't recover.
3. The code is rendered in monospace and is selectable as a single
   token (some receivers strip whitespace; verify the digit string is
   intact).
4. Click-through links (if any) preserve the flow ID query parameter.

## If deliverability is bad at any provider

Options in order of preference:

1. Switch the from-address to a personalized prefix
   (`recovery@dunn.dev` instead of `noreply@dunn.dev`). Fastmail
   accepts arbitrary local parts on the catch-all. Update
   `kratos/kratos.yml: courier.smtp.from_address`.
2. Add a SPF record explicitly listing Fastmail's outbound IPs. Fastmail
   provides the include directive; one DNS update.
3. Add a DKIM key (Fastmail's setup wizard generates it; one DNS
   update).
4. As a last resort, switch to a transactional provider (Postmark,
   Mailgun) for the recovery flow only. Bigger change; reach for it
   only if the cheaper interventions fail.

## Lab verification commands

In the lab compose stack:

```sh
# Trigger a recovery flow for a known identity
curl -fsS -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email": "test@example.com"}' \
  https://auth-lab.example.com/self-service/recovery/api

# Watch Kratos logs for the courier hand-off
podman logs -f auth-kratos | grep courier
```

Confirm the courier reports `delivered: true` for the message ID.

## Production verification

First family recovery flow gets a manual receipt:

1. Operator triggers a recovery for their own non-admin alias (we
   maintain a non-admin family-test identity for this).
2. Receipt is logged in `/admin/activity` and the receiving inbox.
3. If the receipt doesn't arrive within 60s, escalate per the
   "deliverability bad" path above.

## Related

- `kratos/kratos.yml: courier.smtp.from_address`: the source of truth
  for the from address.
- `docs/runbooks/admin-recovery.md`: admin recovery is shell-only;
  email recovery is rejected for admins via the recovery-gate webhook.
