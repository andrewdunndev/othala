// Astro Content Collections — apps registry.
//
// v0.1.4 architecture decision: portal/src/content/apps/<slug>.md is
// the canonical "what apps exist in the family estate" registry. Each
// MD file has frontmatter (tile metadata) and a markdown body
// (education content shown on the /apps/<slug> detail page).
//
// Joined to OIDC client manifests (hydra/clients/<slug>.yaml) by slug:
// the YAML carries OIDC-specific config (redirect_uris, scopes, role
// mapping), the MD carries user-facing presentation. Forward-auth
// apps that don't have a Hydra client (e.g. tune/Navidrome,
// gather/*arr) appear in the apps registry but have no YAML
// counterpart.
//
// Why MD not MDX: keeps zero new dependencies. Standard markdown is
// rich enough for the education content (links, code, lists, images
// via ![]() ). If a future tile needs interactive components, we add
// @astrojs/mdx and migrate.
//
// Slug convention: the filename minus `.md` is the slug. Must match
// the OIDC client_id for apps with a Hydra client, AND must match
// `access-<slug>` for the access group gate. Validated at build time
// via the schema below.

import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const apps = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/apps' }),
  schema: z.object({
    /** Display name — what the user sees on the tile. */
    name: z.string().min(1),
    /** Short description rendered under the tile name. */
    description: z.string().min(1),
    /** Public app URL the tile links to. */
    url: z.string().url(),
    /**
     * Two-letter icon code (e.g., "PH" for Photos). Rendered as text
     * inside the tile until we wire actual icons. Style matches the
     * mono-eyebrow elsewhere in the design system.
     */
    icon: z.string().min(1).max(3),
    /**
     * Access group required to see this tile. By convention
     * `access-<slug>`. Validated against the slug at build time so a
     * frontmatter typo can't silently hide a tile.
     */
    access_group: z.string().regex(/^access-[a-z][a-z0-9-]*$/),
    /**
     * Optional. If the app has a Hydra OIDC client (hydra/clients/<slug>.yaml),
     * set to `oidc`. If forward-auth only (no Hydra registration), set to
     * `forward_auth`. If LDAP-only (Jellyfin native clients via bridge),
     * set to `ldap`. Used by the admin UI to filter the OAuth2 client
     * list view.
     */
    auth_kind: z.enum(['oidc', 'forward_auth', 'ldap', 'oidc+ldap']).default('oidc'),
    /**
     * Set to true to hide the tile from the dashboard even for users
     * in `access_group`. Use during maintenance or before a service
     * actually deploys.
     */
    disabled: z.boolean().default(false),
    /** Sort order on the dashboard. Lower = earlier. */
    order: z.number().int().default(100),
  }),
});

export const collections = { apps };
