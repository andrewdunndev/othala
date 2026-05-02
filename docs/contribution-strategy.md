# Contribution strategy

How dunn.dev/auth relates to upstream Authentik (and to the projects we evaluated and rejected during the substrate selection).

## Posture: consumer

dunn.dev/auth is a consumer of Authentik. We run upstream releases unmodified and treat Authentik as a stable substrate. The estate's existing contribution arc (bootc, composefs, rpm-ostree) doesn't extend here for a few reasons:

1. **Authentik is mature.** The free OSS tier already includes everything our 16-service estate uses. The gaps we identified during evaluation (Django substrate concern, commercial trajectory of paywalled features) aren't things we'd contribute fixes for; they're substrate-level concerns we manage via the hardening package, not feature gaps we plug.
2. **No structural blockers in our use.** Forward-auth, LDAP outpost, OIDC with custom branding, blueprint-based IaC, MFA flows, passkey support — all work out of the box.
3. **Limited code-contribution leverage.** The Authentik codebase is large (Python/Django + JS frontend); meaningful contributions require sustained context. Better leverage from running a well-configured deployment and reporting deployment-derived bugs than dropping into Authentik core development.

What we do contribute, when applicable:

- **Bug reports backed by deployment evidence.** Logs, repro steps, observed behavior. Hand-written, no AI-assisted text.
- **Documentation issues.** When something we encountered isn't documented or is wrong.
- **Real-world deployment notes** that may help other operators (blog posts, gists, etc., not necessarily upstream PRs).

## Why this is different from bootc

The bootc contribution arc (3 PRs merged) made sense because:
- bootc is small enough to read end-to-end
- Active development with clear extension points
- Architectural flexibility welcomed by maintainer (cgwalters)
- Our deployments surface real issues that benefit the broader user base

Authentik is shaped differently. Its maintainership is more product-team-driven (BeryJu the company, B-Corp), with a clearer roadmap and less invitation for outside architectural changes. That's not a criticism — it's a healthy stable project. It just doesn't have the same shape as a contribution target.

## Why this is different from kanidm

Kanidm has an explicit AI/LLM ban (AGENTS.md, includes Anthropic-specific refusal trigger) plus closed contribution doors on the things we'd want (forward-auth, BYO-UI). For us, kanidm-as-consumer means accepting the substrate without contributing back. Authentik is also consumer-only, but for different reasons (mature, shaped product). The outcomes look similar; the reasoning is different.

## Watch-outs

What would change the posture toward Authentik:

- **Free-tier features moving to enterprise.** If LDAP outpost, proxy outpost, custom branding, blueprints, or other currently-free features get paywalled, revisit substrate selection. The eval evidence in `substrate-comparison.md` is the playbook.
- **Maintainer governance shifts.** B-Corp / company-driven model is currently healthy. If governance changes (acquisition, license shift, project pivot), revisit.
- **Specific high-severity issue in our deployment** that requires upstream fix and the upstream is unresponsive. Then contribution becomes the path even at higher cost.

None of these are likely in the next 12-24 months based on current trajectory. Default posture: ship deployments, monitor advisories, file bugs as encountered.

## Per-project notes from the eval

For reference (full evaluations under `../lab/docs/eval-*.md`):

- **kanidm:** evaluated; AI ban + closed contribution doors push it to fallback-only status. We're not contributing.
- **Authelia:** evaluated; doesn't fit shape (no LDAP server). We're not deploying or contributing.
- **Hanko:** evaluated; not an IDP. Not deploying.
- **voidauth:** evaluated; too immature for a 5-year bet. Not deploying.
- **Pocket-ID:** evaluated; consumes external LDAP, doesn't serve LDAP. Not deploying.
- **Zitadel:** evaluated; multi-container architecture mismatch. Not deploying.

The estate runs Authentik. The repo records the evaluation history.
