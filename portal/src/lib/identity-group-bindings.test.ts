// Invariant: identity groups never ride in an app's access or role bindings, and 'admin' is an ordinary group name.

import { describe, expect, it } from 'vitest';
import { parseManifest, validateClients } from './manifests';
import { planGroupSave } from './gate';
import type { Identity } from './types';

function manifest(access: string, roleMapGroup = 'app-admin'): string {
  return `
oidc:
  client_id: app
  redirect_uris: ["https://app.othala.test/cb"]
  audience: ["https://app.othala.test"]
presentation:
  access: [${access}]
consent:
  roles:
    - name: admin
      description: Everything
      claim_emit:
        role: [admin]
  group_role_map:
    ${roleMapGroup}: admin
`;
}

describe('identity groups in manifests', () => {
  it('accepts app groups', () => {
    expect(validateClients([parseManifest(manifest('app-access'), 'app.yaml')])).toEqual([]);
  });

  it('rejects everyone in presentation.access', () => {
    const errs = validateClients([parseManifest(manifest('app-access, everyone'), 'app.yaml')]);
    expect(errs.some((e) => e.includes('"everyone"') && e.includes('identity group'))).toBe(true);
  });

  it('rejects everyone in group_role_map', () => {
    const errs = validateClients([parseManifest(manifest('app-access', 'everyone'), 'app.yaml')]);
    expect(errs.some((e) => e.includes('"everyone"') && e.includes('identity group'))).toBe(true);
  });
});

describe('the admin group name', () => {
  it('binds like any app group', () => {
    expect(validateClients([parseManifest(manifest('admin', 'admin'), 'app.yaml')])).toEqual([]);
  });

  it('is stored by a group save', () => {
    const stored = { metadata_admin: { groups: ['everyone'] } } as unknown as Identity;
    expect(planGroupSave(stored, ['admin', 'everyone'], []).groups).toEqual(['admin', 'everyone']);
  });
});
