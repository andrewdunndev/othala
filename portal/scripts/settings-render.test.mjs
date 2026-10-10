// Invariant: the credential rows keep the names and values Kratos's settings form expects and the selectors the e2e
// suite drives, whatever the markup around them, and never nest a form.

import { test, beforeAll, afterAll } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getViteConfig } from 'astro/config';
import { createServer } from 'vite';

let server;
let AstroContainer;
let CredentialRows;
let view;
let fixtures;

beforeAll(async () => {
  const inline = await getViteConfig({ server: { middlewareMode: true } })({ command: 'serve', mode: 'test' });
  server = await createServer({ ...inline, server: { middlewareMode: true }, appType: 'custom', logLevel: 'silent' });
  ({ experimental_AstroContainer: AstroContainer } = await server.ssrLoadModule('astro/container'));
  CredentialRows = (await server.ssrLoadModule('/src/components/settings/CredentialRows.astro')).default;
  view = await server.ssrLoadModule('/src/lib/settings-view.ts');
  fixtures = await server.ssrLoadModule('/src/lib/settings-fixtures.ts');
});

afterAll(async () => {
  if (server) await server.close();
});

async function rows(props) {
  const container = await AstroContainer.create();
  return container.renderToString(CredentialRows, { props });
}

const nodes = () => fixtures.devSettings('enrolled').flow.ui.nodes;

test('each passkey gets a remove submit carrying its credential id, behind an inline confirm', async () => {
  const items = view.credentialItems(nodes(), 'passkey_remove');
  const html = await rows({ items, kind: 'passkey', noun: 'passkey', fallbackName: 'Passkey', rename: true });
  for (const it of items) {
    assert.match(html, new RegExp(`<button[^>]*type="submit"[^>]*name="passkey_remove"[^>]*value="${it.id}"`));
    assert.ok(html.includes(`data-credential-id="${it.id}"`));
  }
  assert.match(html, /aria-label="Remove passkey &quot;Passkey&quot;"/);
  assert.equal((html.match(/class="disclose cb-remove"/g) ?? []).length, items.length);
  assert.ok(!html.includes('<form'), 'rows must not nest a form');
});

test('rename inputs belong to the page-level sibling forms by the form attribute', async () => {
  const items = view.credentialItems(nodes(), 'passkey_remove');
  const html = await rows({ items, kind: 'passkey', noun: 'passkey', fallbackName: 'Passkey', rename: true });
  assert.ok(html.includes('form="rename-0"') && html.includes('form="rename-1"'));
  assert.match(html, /<input[^>]*name="name"[^>]*maxlength="40"/);
});

test('a stored name replaces the fallback; a removal Kratos disabled stays disabled', async () => {
  const items = view.credentialItems(nodes(), 'passkey_remove', { [view.credentialItems(nodes(), 'passkey_remove')[0].id]: 'Pixel phone' });
  items[1].removable = false;
  items.length = 2;
  const html = await rows({ items, kind: 'passkey', noun: 'passkey', fallbackName: 'Passkey' });
  assert.ok(html.includes('Pixel phone'));
  assert.match(html, /<button[^>]*type="button"[^>]*disabled/);
  assert.equal((html.match(/name="passkey_remove"/g) ?? []).length, 1);
});

test('security keys post webauthn_remove and show Kratos\'s name', async () => {
  const items = view.credentialItems(nodes(), 'webauthn_remove');
  const html = await rows({ items, kind: 'webauthn', noun: 'security key', fallbackName: 'Security key' });
  assert.ok(html.includes('Keyring key'));
  assert.match(html, /name="webauthn_remove"/);
  assert.ok(!html.includes('cb-rename'));
});

async function render(path, props, slots) {
  const mod = (await server.ssrLoadModule(path)).default;
  const container = await AstroContainer.create();
  return container.renderToString(mod, { props, slots });
}

test('the password field is new-password beside a visible username anchor managers can file it under', async () => {
  const html = await render('/src/components/settings/PasswordField.astro', { username: 'sam', name: 'password', label: 'New password', required: true });
  assert.match(html, /<input[^>]*type="password"[^>]*autocomplete="new-password"|<input[^>]*autocomplete="new-password"[^>]*type="password"/);
  const user = html.match(/<input[^>]*autocomplete="username"[^>]*>/)?.[0] ?? '';
  assert.ok(user.includes('value="sam"'));
  assert.ok(!/readonly|disabled|type="hidden"|name=/.test(user), 'not hidden from managers, not posted');
  assert.ok(html.indexOf('autocomplete="username"') < html.indexOf('autocomplete="new-password"'));
});

test('the TOTP setup key sits beside the QR as grouped text with its copy button, behind no disclosure', async () => {
  const html = await render('/src/components/settings/TotpKey.astro', { qr: { src: 'data:image/png;base64,AA', alt: 'QR' }, secret: 'ABCDEFGHIJKLMNOP' });
  assert.match(html, /<code[^>]*id="totp-secret"[^>]*>\s*ABCD EFGH IJKL MNOP\s*<\/code>/);
  assert.match(html, /data-copy="totp-secret"/);
  assert.ok(!html.includes('<details'));
  assert.ok(html.indexOf('<img') < html.indexOf('totp-secret'));
});

test('each setup-link copy control names the one field it copies', async () => {
  const html = await render('/src/components/SetupLink.astro', { url: 'https://x.test/s?f=1', code: '123456', ttl: '1h', name: 'Sam' });
  const label = (target) => html.match(new RegExp(`data-copy="${target}"[^>]*>([^<]*)<`))?.[1];
  assert.equal(label('recoveryUrl'), 'Copy link');
  assert.equal(label('recoveryCode'), 'Copy code');
  assert.equal(label('recoveryMessage'), 'Copy message');
  assert.match(html, /<input id="recoveryUrl"[^>]*value="https:\/\/x\.test\/s\?f=1"/);
  assert.match(html, /<input id="recoveryCode"[^>]*value="123456"/);
});

test('the settings page hands the account name to the password field and renders the key beside the QR', () => {
  const page = readFileSync(new URL('../src/pages/auth/settings.astro', import.meta.url), 'utf8');
  assert.match(page, /<PasswordField username=\{traits\.username\}/);
  assert.match(page, /^\s*<TotpKey qr=\{totp\.qr\} secret=\{totp\.secret\}/m);
  assert.match(page, /checked=\{pwOpen\}/);
  assert.match(page, /pwOpen = passwordPanelOpen\(nodes, parseIdentity\(stored\)\.hasPassword\)/);
  assert.ok(!page.includes('Show setup key'));
});
