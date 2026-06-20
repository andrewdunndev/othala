// Manifest lint — the guardrail the flat-string access model otherwise lacks
// (access-model §11, R3). With no enforced naming convention, a typo'd group
// (`access: [memmories]`) silently locks everyone out (fail-closed, no error)
// and a brand-new user sees a blank dashboard with no explanation. The lint
// cross-checks every group a manifest references against the known-group set
// and flags structural problems, so those footguns surface as findings instead
// of silent denials.
//
// Severity matrix (§11), exactly:
//
//   BLOCK (reload-blocking; joins validateClients' hard-fails):
//     - accessGroups empty AND not skipAccessCheck (definitionally
//       unreachable — the app can never be entered).
//     - a group listed twice within one manifest's access binding.
//     - a group_role_map key that maps to a role NOT declared in roles[].
//   WARN (never blocks — adopters may already run nonstandard names):
//     - a group named in access:/group_role_map that is not in the known set
//       (typo → silent lockout).
//     - access_group present alongside access: (the shim is ignored).
//     - a group name that misses the safe charset.
//
// Phase 2 scope (work order): the FUNCTION + its tests are the must-have. The
// three §11 surfaces (a `just lint` CI job, an `othala lint` CLI, and a yellow
// callout in /admin/oauth2) are deliberately NOT built out here — see the TODO
// at the bottom. The LOAD-TIME BLOCK path IS wired: validateClients
// (manifests.ts) now runs every BLOCK-class check from this matrix (empty
// access binding, duplicate group, undeclared group_role_map role), so a bare
// or contradictory manifest is rejected at reload (R3 feedback loop). This
// function additionally surfaces the WARN dimensions (known-group typos, shim
// shadowing, charset misses) for the not-yet-built advisory surfaces.

import type { ClientManifest } from './manifests';
import { ACCESS_GROUP_NAME_RE } from './access-groups';

export type LintSeverity = 'block' | 'warn';

export interface LintFinding {
  /** The manifest the finding is about (sourcePath, falling back to clientId). */
  source: string;
  severity: LintSeverity;
  message: string;
}

/**
 * Lint a manifest set against a known-group set.
 *
 * `knownGroups` is the set of group names the operator considers legitimate —
 * typically the registry's identity groups plus every group any manifest binds
 * (i.e. knownGroupNames(registry)). A reference to a group OUTSIDE this set is
 * the typo/lockout WARN. (When callers pass the registry's own key set, only
 * genuinely orphaned references — e.g. a charset-rejected name that never made
 * it into accessGroups — can be flagged; callers wanting strict env-only
 * checking pass just the identity-group set.)
 */
export function lintManifests(
  set: ClientManifest[],
  knownGroups: Iterable<string>,
): LintFinding[] {
  const known = new Set(knownGroups);
  const findings: LintFinding[] = [];

  for (const m of set) {
    const source = m.sourcePath || m.clientId;
    const block = (message: string) => findings.push({ source, severity: 'block', message });
    const warn = (message: string) => findings.push({ source, severity: 'warn', message });

    // BLOCK: empty access binding with no skip — the app is unreachable.
    if (m.accessGroups.length === 0 && !m.skipAccessCheck) {
      block(
        'accessGroups is empty and skip_access_check is not set: no group can ' +
          'satisfy the gate, so this app is unreachable. Declare presentation.access: ' +
          'or set consent.skip_access_check.',
      );
    }

    // BLOCK: duplicate group within this manifest's access binding.
    const seen = new Set<string>();
    for (const g of m.accessGroups) {
      if (seen.has(g)) {
        block(`presentation.access lists ${JSON.stringify(g)} more than once`);
      }
      seen.add(g);
    }

    // BLOCK: group_role_map key mapping to an undeclared role.
    for (const [groupName, roleName] of Object.entries(m.groupRoleMap)) {
      if (!m.roles.some((r) => r.name === roleName)) {
        block(
          `consent.group_role_map[${JSON.stringify(groupName)}] points at role ` +
            `${JSON.stringify(roleName)} which is not declared in consent.roles`,
        );
      }
    }

    // WARN: charset miss on any access-binding name.
    for (const g of m.accessGroups) {
      if (!ACCESS_GROUP_NAME_RE.test(g)) {
        warn(
          `access group ${JSON.stringify(g)} does not match the safe charset ` +
            `${ACCESS_GROUP_NAME_RE.source}`,
        );
      }
    }

    // WARN: a referenced group is not in the known set (typo → silent lockout).
    const referenced = new Set<string>([
      ...m.accessGroups,
      ...Object.keys(m.groupRoleMap),
    ]);
    for (const g of referenced) {
      if (!known.has(g)) {
        warn(
          `group ${JSON.stringify(g)} is referenced but not in the known group ` +
            `set — a typo here silently locks everyone out (fail-closed). Add it ` +
            `to OTHALA_IDENTITY_GROUPS or fix the name.`,
        );
      }
    }
  }

  return findings;
}

/** The BLOCK-severity findings only — the subset that should fail a reload. */
export function lintBlockers(set: ClientManifest[], knownGroups: Iterable<string>): LintFinding[] {
  return lintManifests(set, knownGroups).filter((f) => f.severity === 'block');
}

// TODO(access-model §11 — Phase 2 follow-up): wire lintManifests into the three
// surfaces the spec calls for, none of which exist yet in this repo:
//   1. A CI `lint-manifests` job (`just lint`) that fails on BLOCK findings.
//   2. An `othala lint` CLI subcommand over MANIFEST_DIR.
//   3. A non-blocking yellow callout (.notice-warn) on /admin/oauth2 surfacing
//      WARN findings for the live manifest set.
// The function + its unit tests are the Phase-2 must-have; the surfaces are
// intentionally deferred so this change stays atomic and reviewable.
