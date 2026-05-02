# upstream

Historical research notes from the substrate evaluation. We are consumer-only across all evaluated projects (Authentik chosen as substrate; kanidm, Authelia, Hanko, voidauth, Pocket-ID, Zitadel evaluated and rejected). No active upstream code contributions are planned.

## Layout

| Path | Contents |
|---|---|
| `firstyear-walk/findings.md` | Maintainer-stance walk on William Brown (kanidm). Captures the AI/LLM ban, the architectural rejection of forward-auth contributions (issues #2407, #2774), and the closure of browser BYO-UI work (PR #2980). Reason kanidm is fallback-only, not a contribution target. |

## Why this directory exists in a consumer-only repo

The walks documented here informed the substrate decision. They are durable evidence that explains the journey: why kanidm felt like fighting the framework, why we returned to Authentik, what the bar is for re-evaluation in the future. Future operators reading this repo cold should be able to reconstruct the reasoning.

## If we ever revisit upstream contribution

The bar (per `../docs/contribution-strategy.md`):
- A specific deployment-derived issue with no upstream-fix path
- Hand-written, no AI-assisted text in posted content
- Apply estate voice conventions to any external text (no em-dashes, direct phrasing, no filler words)
- DCO sign-off where required by the project

Bug reports backed by deployment evidence (logs, repro steps) are the appropriate kind of upstream contribution from us.
