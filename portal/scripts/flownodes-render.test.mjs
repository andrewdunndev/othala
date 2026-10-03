// Invariant: FlowNodes renders Kratos flow nodes equivalently to the reference output.

import { test, beforeAll, afterAll } from 'vitest';
import assert from 'node:assert/strict';
import { getViteConfig } from 'astro/config';
import { createServer } from 'vite';

let server;
let AstroContainer;
let FlowNodes;

beforeAll(async () => {
  const inline = await getViteConfig({ server: { middlewareMode: true } })({
    command: 'serve',
    mode: 'test',
  });
  server = await createServer({
    ...inline,
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  });
  ({ experimental_AstroContainer: AstroContainer } =
    await server.ssrLoadModule('astro/container'));
  FlowNodes = (await server.ssrLoadModule('/src/components/FlowNodes.astro')).default;
});

afterAll(async () => {
  if (server) await server.close();
});

async function render(props) {
  const container = await AstroContainer.create();
  return container.renderToString(FlowNodes, { props });
}

function clean(html) {
  return html.replace(/\s+data-astro-source-(?:file|loc)="[^"]*"/g, '');
}

function input(group, attributes, meta) {
  return meta ? { group, attributes, meta } : { group, attributes };
}

test('hidden node renders a hidden input carrying its CSRF token value', async () => {
  const nodes = [
    input('code', { node_type: 'input', name: 'csrf_token', type: 'hidden', value: 'tok-xyz' }),
  ];
  const html = clean(await render({
    nodes,
    group: 'code',
    buttonClass: 'button button-primary',
    submitLabel: 'Go',
  }));
  assert.match(html, /<input type="hidden" name="csrf_token" value="tok-xyz">/);
});

test('submit node renders a button with the given buttonClass', async () => {
  const nodes = [
    input(
      'code',
      { node_type: 'input', name: 'method', type: 'submit', value: 'Submit code' },
      { label: { text: 'Submit code' } },
    ),
  ];
  const html = clean(await render({
    nodes,
    group: 'code',
    buttonClass: 'button button-secondary',
    submitLabel: 'Fallback',
  }));
  assert.match(html, /<button class="button button-secondary" type="submit" name="method"/);
  assert.match(html, />Submit code<\/button>/);
  assert.doesNotMatch(html, />Fallback<\/button>/);
});

test('submit fallback label is used when meta.label.text is absent', async () => {
  const nodes = [
    input('passkey', { node_type: 'input', name: 'webauthn_register_trigger', type: 'submit', value: '' }),
  ];
  const html = clean(await render({
    nodes,
    group: 'passkey',
    buttonClass: 'button button-secondary',
    submitLabel: 'Register a passkey',
  }));
  assert.match(html, />Register a passkey<\/button>/);
});

test('passOnclick=true forwards the node onclick onto the button', async () => {
  const nodes = [
    input(
      'passkey',
      { node_type: 'input', name: 'passkey', type: 'button', value: '', onclickTrigger: 'oryWebAuthnLogin' },
      { label: { text: 'Use passkey' } },
    ),
  ];
  const html = clean(await render({
    nodes,
    group: 'passkey',
    buttonClass: 'button button-secondary',
    submitLabel: 'Use passkey',
    passOnclick: true,
  }));
  assert.match(html, /onclick="window.oryWebAuthnLogin\(\)"/);
});

test('passOnclick=false (default) drops the node onclick', async () => {
  const nodes = [
    input(
      'passkey',
      { node_type: 'input', name: 'passkey', type: 'button', value: '', onclickTrigger: 'oryWebAuthnLogin' },
      { label: { text: 'Use passkey' } },
    ),
  ];
  const html = clean(await render({
    nodes,
    group: 'passkey',
    buttonClass: 'button button-secondary',
    submitLabel: 'Use passkey',
  }));
  assert.doesNotMatch(html, /onclick=/);
});

test('labeled input reads its label from node.meta.label.text', async () => {
  const nodes = [
    input(
      'code',
      { node_type: 'input', name: 'code', type: 'text', required: true },
      { label: { text: 'Verification code' } },
    ),
  ];
  const html = clean(await render({
    nodes,
    group: 'code',
    buttonClass: 'button button-primary',
    submitLabel: 'Go',
  }));
  assert.match(html, /<label for="code">Verification code<\/label>/);
  assert.match(html, /<input id="code" name="code" type="text"/);
});

test('passValue=false suppresses the value attribute (password fields)', async () => {
  const nodes = [
    input(
      'password',
      { node_type: 'input', name: 'password', type: 'password', value: 'leak-me', required: true },
      { label: { text: 'Password' } },
    ),
  ];
  const html = clean(await render({
    nodes,
    group: 'password',
    buttonClass: 'button button-secondary',
    submitLabel: 'Change password',
    passValue: false,
    defaultAutocomplete: 'new-password',
  }));
  assert.doesNotMatch(html, /value="leak-me"/);
  assert.doesNotMatch(html, /<input id="password"[^>]*\svalue=/);
  assert.match(html, /autocomplete="new-password"/);
});

test('passValue=true (default) renders the value attribute on labeled inputs', async () => {
  const nodes = [
    input(
      'profile',
      { node_type: 'input', name: 'traits.email', type: 'text', value: 'a@othala.test' },
      { label: { text: 'Email' } },
    ),
  ];
  const html = clean(await render({
    nodes,
    group: 'profile',
    buttonClass: 'button button-primary',
    submitLabel: 'Save',
  }));
  assert.match(html, /value="a@othala.test"/);
});

test('only nodes in the requested group are rendered', async () => {
  const nodes = [
    input('default', { node_type: 'input', name: 'csrf_token', type: 'hidden', value: 'tok' }),
    input('code', { node_type: 'input', name: 'code', type: 'text' }, { label: { text: 'Code' } }),
  ];
  const html = clean(await render({
    nodes,
    group: 'code',
    buttonClass: 'button button-primary',
    submitLabel: 'Go',
  }));
  assert.doesNotMatch(html, /name="csrf_token"/);
  assert.match(html, /name="code"/);
});
