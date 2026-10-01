// ZJ — Enter in a settings text field must never submit a removal. Reads the served HTML the way a browser resolves
// implicit submission: the form's default button is its first submit button in tree order (a `form="id"` button
// belongs to that form, not to the one it sits in).

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
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

test('ZJ2 — Enter in the new key name never removes an enrolled key', async ({ browser, baseURL, kratosAdminURL }) => {
  const identity = await createIdentityWithPassword({
    email: 'implicit.enter@othala.test',
    username: 'implicit.enter',
    displayName: 'Implicit Enter Tester',
    groups: [],
    kratosAdminURL,
  });
  const ctx = await browser.newContext();
  const keyCount = async () => {
    const c = ((await readIdentity(kratosAdminURL, identity.id, ['webauthn'])) as { credentials?: { webauthn?: { config?: { credentials?: unknown[] } } } }).credentials;
    return c?.webauthn?.config?.credentials?.length ?? 0;
  };
  try {
    await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true },
    });
    await page.goto(`${baseURL}/auth/settings`);
    await page.waitForLoadState('networkidle');
    await page.locator('.lbl-setup', { hasText: /Add (a|another) security key/ }).first().click();
    await page.locator('input[name="webauthn_register_displayname"]').fill('ZJ2 first');
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryWebAuthnRegistration === 'function');
    await page.locator('button[name="webauthn_register_trigger"]').first().click();
    await expect.poll(keyCount, { timeout: 15_000, message: 'the first key is stored' }).toBe(1);

    // With no authenticator left, a ceremony started by Enter cannot add a key; a removal would drop the count to 0.
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    await page.goto(`${baseURL}/auth/settings`);
    await page.waitForLoadState('networkidle');
    await page.locator('.lbl-setup', { hasText: /Add (a|another) security key/ }).first().click();
    const posts: string[] = [];
    page.on('request', (r) => { if (r.method() === 'POST') posts.push(r.url()); });
    const name = page.locator('input[name="webauthn_register_displayname"]');
    await name.fill('ZJ2 second');
    await name.press('Enter');
    await page.waitForTimeout(1500);
    expect(posts, 'Enter posted nothing').toEqual([]);
    expect(await keyCount(), 'the enrolled key is still there').toBe(1);
  } finally {
    await ctx.close();
  }
});
