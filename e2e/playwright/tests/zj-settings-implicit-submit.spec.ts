// ZJ — Enter in a settings text field must never submit a removal. Reads the served HTML the way a browser resolves
// implicit submission: the form's default button is its first submit button in tree order (a `form="id"` button
// belongs to that form, not to the one it sits in).

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';

const attr = (tag: string, name: string) => tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1];
const DESTRUCTIVE = /(_remove|_unlink|_disable)$/;

test('ZJ1 — no settings text input has a removal as its default button', async ({ ctx, baseURL, kratosAdminURL }) => {
  const identity = await createIdentityWithPassword({
    email: 'implicit.submit@othala.test',
    username: 'implicit.submit',
    displayName: 'Implicit Submit Tester',
    groups: [],
    kratosAdminURL,
  });
  await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);

  const resp = await ctx.request.get(`${baseURL}/auth/settings`, { headers: { Accept: 'text/html' }, maxRedirects: 5 });
  expect(resp.status()).toBe(200);
  const html = await resp.text();

  // Walk the document once: track the open form, collect text inputs and submit buttons with their owning form id.
  const owners: Array<{ kind: 'text' | 'submit'; owner: string; tag: string }> = [];
  let open: string | null = null;
  let n = 0;
  for (const m of html.matchAll(/<(\/?)(form|input|button)\b[^>]*>/gi)) {
    const [tag, close, el] = m;
    if (el.toLowerCase() === 'form') {
      open = close ? null : (attr(tag, 'id') ?? `form-${n++}`);
      continue;
    }
    const owner = attr(tag, 'form') ?? open;
    if (!owner) continue;
    const type = (attr(tag, 'type') ?? (el.toLowerCase() === 'button' ? 'submit' : 'text')).toLowerCase();
    if (el.toLowerCase() === 'input' && ['text', 'email', 'password', 'search', 'tel', 'url', 'number'].includes(type)) {
      owners.push({ kind: 'text', owner, tag });
    } else if (el.toLowerCase() === 'button' && type === 'submit') {
      owners.push({ kind: 'submit', owner, tag });
    }
  }

  const texts = owners.filter((o) => o.kind === 'text');
  expect(texts.length, 'ZJ1 precondition: the page has text inputs').toBeGreaterThan(0);
  for (const t of texts) {
    const first = owners.find((o) => o.kind === 'submit' && o.owner === t.owner);
    const name = first ? (attr(first.tag, 'name') ?? '') : '';
    expect(DESTRUCTIVE.test(name), `Enter in ${t.tag} would press ${first?.tag}`).toBe(false);
  }
  const anyDestructiveShared = owners.filter((o) => o.kind === 'submit' && DESTRUCTIVE.test(attr(o.tag, 'name') ?? '')).some((b) => texts.some((t) => t.owner === b.owner));
  expect(anyDestructiveShared, 'a removal shares a form with a text input').toBe(false);
});
