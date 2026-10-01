// Invariant: an unreadable Hydra is "unknown", never "synced"; holders show a level only above the base level.

import { describe, expect, it } from 'vitest';
import { adminsOf, holdersOf, hydraClientIds } from './admin-apps';
import { joinApps } from './admin-view';
import type { ClientManifest } from './manifests';
import { identity } from './test-builders';

const role = (name: string) => ({ name, description: '', claimEmit: {} });
const grafana = {
  clientId: 'grafana', clientName: 'Grafana', sourcePath: 'grafana.yaml', accessGroups: ['grafana-access'],
  roles: [role('admin'), role('editor'), role('viewer')], groupRoleMap: { 'grafana-admin': 'admin' }, skipAccessCheck: false,
} as unknown as ClientManifest;
const [app] = joinApps([grafana], []);
const people = [
  { identity: identity({ id: 'a', metadataAdmin: { groups: ['grafana-access', 'grafana-admin'] } }), name: 'Amy' },
  { identity: identity({ id: 'b', metadataAdmin: { groups: ['grafana-access'], roles: { grafana: 'editor' } } }), name: 'Ben' },
  { identity: identity({ id: 'c', metadataAdmin: { groups: ['grafana-access'] } }), name: 'Cleo' },
  { identity: identity({ id: 'd', metadataAdmin: { groups: [] } }), name: 'Dev' },
];

describe('hydraClientIds', () => {
  const reply = (status: number, body: unknown) => (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

  it('collects client ids', async () => {
    expect(await hydraClientIds(reply(200, [{ client_id: 'grafana' }, { client_id: 'wiki' }, {}]))).toEqual(new Set(['grafana', 'wiki']));
  });

  it('is null, not empty, when Hydra errors, answers oddly or is unreachable', async () => {
    expect(await hydraClientIds(reply(500, []))).toBeNull();
    expect(await hydraClientIds(reply(200, { nope: 1 }))).toBeNull();
    expect(await hydraClientIds((async () => { throw new Error('down'); }) as unknown as typeof fetch)).toBeNull();
  });
});

describe('who can use an app', () => {
  it('lists holders and labels only the levels above the base level', () => {
    expect(holdersOf(app, people).map((h) => [h.name, h.level])).toEqual([['Amy', 'Admin'], ['Ben', 'Editor'], ['Cleo', '']]);
  });

  it('lists admins as those at the top level', () => {
    expect(adminsOf(app, people).map((h) => h.name)).toEqual(['Amy']);
  });
});
