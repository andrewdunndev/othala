// Invariant: identity groups never ride in an app's access or role bindings, and a group save never stores `admin`.

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

  it.each(['admin', 'everyone'])('rejects %s in presentation.access', (g) => {
    const errs = validateClients([parseManifest(manifest(`app-access, ${g}`), 'app.yaml')]);
    expect(errs.some((e) => e.includes(`"${g}"`) && e.includes('identity group'))).toBe(true);
  });

  it.each(['admin', 'everyone'])('rejects %s in group_role_map', (g) => {
    const errs = validateClients([parseManifest(manifest('app-access', g), 'app.yaml')]);
    expect(errs.some((e) => e.includes(`"${g}"`) && e.includes('identity group'))).toBe(true);
  });
});

describe('planGroupSave and the legacy admin group', () => {
  it('drops admin from the submitted groups', () => {
    const stored = { metadata_admin: { groups: ['admin', 'everyone'] } } as unknown as Identity;
    expect(planGroupSave(stored, ['admin', 'everyone', 'app-access'], []).groups).toEqual(['everyone', 'app-access']);
  });
});
