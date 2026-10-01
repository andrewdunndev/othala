// Prerequisites and guides: the requires schema, the requirements/ loader, the guide outline, per-person readiness,
// and the lint warning. Properties over a temp MANIFEST_DIR, not snapshots.

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadTiles,
  loadRequirements,
  parseRequirement,
  parseRequires,
  splitGuide,
  holdsTopRole,
  tileReadiness,
  type AppTile,
} from './tiles';
import { validateMetadataAdmin, MetadataAdminError } from './metadata-admin';
import { parseManifest } from './manifests';
import { lintManifests } from './manifest-lint';

const dirs: string[] = [];
const savedDir = process.env.MANIFEST_DIR;
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  if (savedDir === undefined) delete process.env.MANIFEST_DIR;
  else process.env.MANIFEST_DIR = savedDir;
});

function manifestDirWith(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), 'othala-prereq-'));
  dirs.push(d);
  for (const [name, body] of Object.entries(files)) {
    const p = join(d, name);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, body);
  }
  process.env.MANIFEST_DIR = d;
  return d;
}

const TILE = (extra = '') => `presentation:
  name: Vault
  description: Passwords
  url: https://vault.example.test
  access: [everyone]
${extra}`;

describe('presentation.requires', () => {
  it('normalizes: lowercases, dedupes, drops malformed and non-string entries', () => {
    expect(parseRequires(['Tailscale', 'tailscale', '../x', 3, 'vpn-2', ''])).toEqual(['tailscale', 'vpn-2']);
    expect(parseRequires('tailscale')).toEqual([]);
    expect(parseRequires(undefined)).toEqual([]);
  });

  it('loads onto the tile, and a tile without it requires nothing', () => {
    manifestDirWith({
      'a.yaml': TILE('  requires: [tailscale]\n'),
      'b.yaml': TILE(),
    });
    const tiles = loadTiles();
    expect(tiles.find((t) => t.slug === 'a')?.requires).toEqual(['tailscale']);
    expect(tiles.find((t) => t.slug === 'b')?.requires).toEqual([]);
  });
});

describe('requirements/<name>.md', () => {
  it('reads title and why from front matter and sanitizes the body', () => {
    const r = parseRequirement(
      'tailscale',
      '---\ntitle: Tailscale\nwhy: Reaches home apps from anywhere.\n---\n## Set up\n\n1. Install it.\n<script>alert(1)</script>\n',
    );
    expect(r.title).toBe('Tailscale');
    expect(r.why).toBe('Reaches home apps from anywhere.');
    expect(r.html).toContain('<h2');
    expect(r.html).not.toContain('<script');
  });

  it('falls back to a title-cased name when the front matter is absent or malformed', () => {
    expect(parseRequirement('tailscale', 'Just text.').title).toBe('Tailscale');
    expect(parseRequirement('tailscale', '---\ntitle: [oops\n---\nBody').title).toBe('Tailscale');
  });

  it('loads every well-named file and skips a bad filename', () => {
    manifestDirWith({
      'requirements/tailscale.md': '---\ntitle: Tailscale\n---\nBody',
      'requirements/Bad Name.md': 'x',
      'requirements/notes.txt': 'x',
    });
    expect([...loadRequirements().keys()]).toEqual(['tailscale']);
  });

  it('is empty when the directory is absent', () => {
    manifestDirWith({ 'a.yaml': TILE() });
    expect(loadRequirements().size).toBe(0);
  });
});

describe('splitGuide: the fixed outline', () => {
  const html =
    '<p>Intro</p><h2>Getting help</h2><p>Ask.</p><h2>Good to know</h2><p>Note.</p>' +
    "<h2>What it's for</h2><p>Why.</p><h2>First time</h2><ol><li>One</li></ol><h2>Bonus</h2><p>More.</p>";

  it('orders sections by the outline and keeps the lead', () => {
    const g = splitGuide(html);
    expect(g.lead).toBe('<p>Intro</p>');
    expect(g.sections.map((s) => s.id)).toEqual(['purpose', 'first-time', 'good-to-know', 'help', 'extra']);
    expect(g.sections[0]?.title).toBe("What it's for");
    expect(g.sections[4]?.title).toBe('Bonus');
    expect(g.sections[1]?.html).toContain('<ol>');
  });

  it('puts a repeated heading after the outline rather than overwriting the first', () => {
    const g = splitGuide('<h2>First time</h2><p>A</p><h2>First steps</h2><p>B</p>');
    expect(g.sections.map((s) => s.id)).toEqual(['first-time', 'extra']);
    expect(g.sections[0]?.html).toBe('<p>A</p>');
  });

  it('treats a guide with no headings as all lead, and empty input as empty', () => {
    expect(splitGuide('<p>Only prose</p>')).toEqual({ lead: '<p>Only prose</p>', sections: [] });
    expect(splitGuide(undefined)).toEqual({ lead: '', sections: [] });
  });
});

describe('per-person readiness', () => {
  const tile = (requires: string[]) => ({ requires }) as AppTile;
  it('is none without requirements, ready when all are marked, else needs', () => {
    expect(tileReadiness(tile([]), ['tailscale'])).toBe('none');
    expect(tileReadiness(tile(['tailscale']), [])).toBe('needs');
    expect(tileReadiness(tile(['tailscale']), ['tailscale'])).toBe('ready');
    expect(tileReadiness(tile(['tailscale', 'vpn']), ['tailscale'])).toBe('needs');
  });
});

describe('holdsTopRole', () => {
  const yaml = `oidc:
  client_id: grafana
  client_name: Grafana
  redirect_uris: [https://g.example.test/cb]
  audience: [https://g.example.test]
presentation:
  name: Grafana
  access: [grafana-access]
consent:
  roles:
    admin: { description: Admin, claim_emit: { r: [a] } }
    viewer: { description: View, claim_emit: { r: [v] } }
  group_role_map:
    grafana-admin: admin
    grafana-access: viewer
`;
  const t = { manifest: parseManifest(yaml, 'grafana.yaml'), requires: [] } as unknown as AppTile;
  it('is true only when the resolved role is the first declared one', () => {
    expect(holdsTopRole(t, { groups: ['grafana-access', 'grafana-admin'] })).toBe(true);
    expect(holdsTopRole(t, { groups: ['grafana-access'] })).toBe(false);
    expect(holdsTopRole(t, { groups: ['grafana-access'], roles: { grafana: 'admin' } })).toBe(true);
  });
  it('is false for an app with no manifest or a single role', () => {
    expect(holdsTopRole({ requires: [] } as unknown as AppTile, {})).toBe(false);
    const one = parseManifest(yaml.replace(/    viewer:.*\n/, ''), 'grafana.yaml');
    expect(holdsTopRole({ manifest: one, requires: [] } as unknown as AppTile, { groups: ['grafana-admin'] })).toBe(false);
  });
});

describe('metadata_admin.prerequisites', () => {
  it('accepts a list of slugs', () => {
    expect(validateMetadataAdmin({ prerequisites: ['tailscale'] }).prerequisites).toEqual(['tailscale']);
    expect(validateMetadataAdmin({ prerequisites: [] }).prerequisites).toEqual([]);
  });
  it('rejects non-arrays, bad names and duplicates', () => {
    expect(() => validateMetadataAdmin({ prerequisites: 'tailscale' })).toThrow(MetadataAdminError);
    expect(() => validateMetadataAdmin({ prerequisites: ['Tail Scale'] })).toThrow(MetadataAdminError);
    expect(() => validateMetadataAdmin({ prerequisites: [3] })).toThrow(MetadataAdminError);
    expect(() => validateMetadataAdmin({ prerequisites: ['a', 'a'] })).toThrow(/duplicate/);
  });
  it('still rejects unknown keys', () => {
    expect(() => validateMetadataAdmin({ prereqs: [] })).toThrow(/unknown field/);
  });
});

describe('manifest lint: requires', () => {
  const m = (yaml: string) => parseManifest(yaml, 'vault.yaml');
  const body = TILE('  requires: [tailscale, ghost]\n');
  it('warns once per unknown name and stays quiet for a defined one', () => {
    const f = lintManifests([m(body)], ['everyone'], ['tailscale']);
    const reqs = f.filter((x) => x.message.includes('presentation.requires'));
    expect(reqs).toHaveLength(1);
    expect(reqs[0]?.severity).toBe('warn');
    expect(reqs[0]?.message).toContain('"ghost"');
  });
  it('skips the check when no requirement set is given', () => {
    const f = lintManifests([m(body)], ['everyone']);
    expect(f.filter((x) => x.message.includes('presentation.requires'))).toHaveLength(0);
  });
});
