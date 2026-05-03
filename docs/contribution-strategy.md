# Contribution strategy

The dunn.dev/auth project as both consumer and contributor. We use Ory Kratos + Hydra without modification (no fork, no patch series). The novel piece — `glauth-kratos`, our LDAP bridge — has standalone upstream value beyond our deployment.

## Posture: consumer of Ory; contributor to glauth (potentially)

### Ory Kratos and Hydra: consumer

We run upstream Ory Kratos and Hydra release images. No patches, no fork. The architecture decision is to use these projects as-shipped because:

- Ory ships fast (release cadence ~monthly); a patch series ages out fast
- The composable architecture means we can route around limitations rather than patch them
- Operational gaps (consent app, login app, LDAP bridge) are documented BYO-extension points, not bugs

Possible future contributions to Ory, if a deployment-derived issue surfaces:

- Bug reports backed by logs and repro steps
- Documentation issues (e.g., the AAL semantics gap that the adversarial review caught is poorly documented)
- A Kratos admin-API webhook event for identity CRUD — would benefit our LDAP bridge cache and any other admin-facing consumer; small contribution, general value

These are speculative. Default posture: ship deployment, monitor advisories, file bugs as encountered.

### glauth: contribution candidate

`glauth-kratos` (the bridge in `ldap-bridge/`) is built as a glauth embedded plugin: a Handler implementation that satisfies glauth's Bind/Search interface against Kratos. Once it proves out in production, the natural contribution path is:

1. Extract `ldap-bridge/kratos/` plus the surrounding Containerfile/Makefile to its own repo: `gitlab.com/dunn.dev/glauth-kratos` (with GitHub mirror)
2. Open a PR against glauth itself proposing the kratos backend as an upstream embedded plugin
3. Maintain the standalone repo as the authoritative source; the upstream contribution is a pointer

The bridge's standalone value: anyone running Kratos who needs LDAP. The community of homelabbers + small-org Kratos deployments has the same gap; we're not the first to hit it (just the first to assemble the pieces).

## What we do NOT contribute

- **Patches to Authentik or kanidm.** Authentik is mature; kanidm has explicit AI/LLM bans. Both stacks are out of scope.
- **A fork of Ory.** If Ory itself fails us, we revisit substrate, not patch-and-maintain.
- **A standalone "Ory homelab kit" project.** The `dunn.dev/auth` repo IS the kit, but extracted only as components (the bridge first; the Astro UI is more opinionated and possibly less generally useful). We don't pre-publish the entire kit because:
  - Maintenance treadmill killed every prior Ory homelab kit (see `lab/docs/ory-homelab-research.md`)
  - We dogfood on carmine; that's the structural difference vs prior solo maintainers
  - If the bridge proves valuable as a standalone, that's where the leverage is — focus there

## Posture if asked

If someone asks "can I use your kit?" the answer is: the bridge is open-source, the Astro UI is a reference, the rest is dunn.dev-specific config. Take what's useful. Patches welcome on the bridge specifically.

## Watch-outs

- Ory Network commercial trajectory tightens free-tier OSS — currently no signs, but if SCIM, advanced AAL flows, or other features migrate to Network-only, revisit
- glauth governance health — single-maintainer concern; if the project goes quiet for >6 months, our bridge becomes a maintenance burden we own alone
- Kratos breaking changes — fast release cadence is the published strength and the latent risk; we pin major versions, test against new versions in lab before bumping carmine

## Voice for upstream

Apply estate voice rules to any external text (PR descriptions, issue replies, blog posts):
- No em-dashes (use colons, parentheses, semicolons)
- Direct phrasing, no filler ("comprehensive", "robust", "leverage", "straightforward")
- State uncertainty plainly; don't hedge
- No trailing summaries

DCO sign-off where projects require it. No AI-Assisted trailers. Drafts to file first; human review before posting.
