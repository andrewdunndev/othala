// Tests for the content.config.ts access_group↔filename superRefine
// (CU2 item 4). The cross-cut predicate lives in src/lib/app-slug.ts so it
// is testable without the `astro:content` virtual module; content.config.ts
// wires the SAME predicate into a zod superRefine that runs at `astro
// build` / `astro check`. This suite proves:
//
//   1. The predicate accepts a matching access_group and rejects a
//      mismatched one (and fails closed on a missing slug).
//   2. A zod schema using the predicate via superRefine — exactly how
//      content.config.ts wires it — rejects a mismatched access_group at
//      parse time (the build-time behaviour), not only in npm test.
//
// Run with: tsx --test scripts/content-config-superrefine.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'astro/zod';
import {
  slugFromEntry,
  expectedAccessGroup,
  accessGroupMismatch,
} from '../src/lib/app-slug.ts';

// ── predicate ──────────────────────────────────────────────────────────────

test('slugFromEntry strips directory + extension', () => {
  assert.equal(slugFromEntry('keep.md'), 'keep');
  assert.equal(slugFromEntry('sub/dir/keep.md'), 'keep');
  assert.equal(slugFromEntry('tailscale.md'), 'tailscale');
});

test('expectedAccessGroup is access-<slug>', () => {
  assert.equal(expectedAccessGroup('keep'), 'access-keep');
});

test('accessGroupMismatch: matching returns null', () => {
  assert.equal(accessGroupMismatch('keep', 'access-keep'), null);
});

test('accessGroupMismatch: mismatch returns an error message', () => {
  const msg = accessGroupMismatch('keep', 'access-vault');
  assert.ok(msg && msg.includes('does not match the filename slug "keep"'));
  assert.ok(msg.includes('expected "access-keep"'));
});

test('accessGroupMismatch: missing slug fails closed', () => {
  assert.ok(accessGroupMismatch(undefined, 'access-keep'));
  assert.ok(accessGroupMismatch('', 'access-keep'));
});

// ── zod superRefine wiring (mirrors content.config.ts) ─────────────────────

// Rebuild the same schema shape + superRefine content.config.ts uses, so
// the test proves the predicate rejects through zod (the build path), not
// just as a bare function.
const appsSchema = z
  .object({
    _slug: z.string().optional(),
    name: z.string().min(1),
    description: z.string().min(1),
    url: z.string().url(),
    icon: z.string().min(1).max(3),
    access_group: z.string().regex(/^access-[a-z][a-z0-9-]*$/),
    auth_kind: z.enum(['oidc', 'forward_auth', 'ldap', 'oidc+ldap']).default('oidc'),
    disabled: z.boolean().default(false),
    order: z.number().int().default(100),
  })
  .superRefine((data, ctx) => {
    const problem = accessGroupMismatch(data._slug, data.access_group);
    if (problem) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['access_group'], message: problem });
    }
  });

function frontmatter(overrides = {}) {
  return {
    _slug: 'keep',
    name: 'Vaultwarden',
    description: 'Password manager',
    url: 'https://keep.dunn.dev',
    icon: 'KP',
    access_group: 'access-keep',
    ...overrides,
  };
}

test('zod superRefine ACCEPTS a matching access_group', () => {
  const res = appsSchema.safeParse(frontmatter());
  assert.equal(res.success, true, JSON.stringify(res.error?.issues));
});

test('zod superRefine REJECTS a mismatched access_group (build-time failure)', () => {
  const res = appsSchema.safeParse(frontmatter({ access_group: 'access-vault' }));
  assert.equal(res.success, false);
  const issue = res.error.issues.find((i) => i.path.includes('access_group'));
  assert.ok(issue, 'expected an access_group issue');
  assert.ok(issue.message.includes('does not match the filename slug "keep"'));
});

test('zod superRefine REJECTS when the loader did not inject a slug (fail-closed)', () => {
  const fm = frontmatter();
  delete fm._slug;
  const res = appsSchema.safeParse(fm);
  assert.equal(res.success, false);
});
