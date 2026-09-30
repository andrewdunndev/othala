// Manifest lint: cross-checks every group a manifest references against the
// known-group set so a typo'd group surfaces as a finding, not a silent lockout.
// BLOCK (also enforced by validateClients at load): empty accessGroups without
// skipAccessCheck, a duplicated group, an undeclared group_role_map role.
// WARN: a group missing from the known set, or missing the canonical form.

import type { ClientManifest } from './manifests';
import { GROUP_RE } from './access-groups';

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

    // WARN: charset miss on ANY group name this manifest declares — both the
    // access binding and the `group_role_map` keys. A key that misses the
    // canonical form (access-groups.ts GROUP_RE) can never match a stored
    // group, so the role it maps is dead: no identity can ever receive it.
    for (const g of [...m.accessGroups, ...Object.keys(m.groupRoleMap)]) {
      if (!GROUP_RE.test(g)) {
        warn(
          `group ${JSON.stringify(g)} does not match the safe charset ` +
            `${GROUP_RE.source}`,
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

// TODO: wire lintManifests into the three surfaces below, none of which exist
// yet in this repo:
//   1. A CI `lint-manifests` job (`just lint`) that fails on BLOCK findings.
//   2. An `othala lint` CLI subcommand over MANIFEST_DIR.
//   3. A non-blocking yellow callout (.notice-warn) on /admin/oauth2 surfacing
//      WARN findings for the live manifest set.
// The function + its unit tests are the Phase-2 must-have; the surfaces are
// intentionally deferred so this change stays atomic and reviewable.
