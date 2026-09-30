// Invariant: Kratos UI node helpers filter by group and return safe empty values.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  nodesByGroup,
  defaultNodes,
  csrfToken,
  hasMethod,
  findInput,
  scriptNodes,
  inputProps,
} from '../src/lib/nodes.ts';

const SAMPLE_LOGIN_NODES = [
  { group: 'default', attributes: { node_type: 'input', name: 'csrf_token', type: 'hidden', value: 'abc123' } },
  { group: 'default', attributes: { node_type: 'input', name: 'return_to', type: 'hidden', value: '/' } },
  { group: 'password', attributes: { node_type: 'input', name: 'identifier', type: 'text', required: true, autocomplete: 'username' } },
  { group: 'password', attributes: { node_type: 'input', name: 'password', type: 'password', required: true, autocomplete: 'current-password' } },
  { group: 'password', attributes: { node_type: 'input', name: 'method', type: 'submit', value: 'password' } },
  { group: 'webauthn', attributes: { node_type: 'script', id: 'webauthn_script', src: '/.well-known/ory/webauthn.js', async: true } },
  { group: 'webauthn', attributes: { node_type: 'input', name: 'webauthn_login', type: 'button', value: 'sign in with passkey', onclick: 'window.__oryWebAuthnLogin(); return false;' } },
];

test('nodesByGroup: filters to a single group', () => {
  const password = nodesByGroup(SAMPLE_LOGIN_NODES, 'password');
  assert.equal(password.length, 3);
  for (const n of password) assert.equal(n.group, 'password');
});

test('nodesByGroup: unknown group returns []', () => {
  assert.deepEqual(nodesByGroup(SAMPLE_LOGIN_NODES, 'totp'), []);
});

test('defaultNodes: returns default-group nodes only', () => {
  const def = defaultNodes(SAMPLE_LOGIN_NODES);
  assert.equal(def.length, 2);
  assert.equal(def[0].attributes.name, 'csrf_token');
  assert.equal(def[1].attributes.name, 'return_to');
});

test('csrfToken: pulls the token from default group', () => {
  assert.equal(csrfToken(SAMPLE_LOGIN_NODES), 'abc123');
});

test('csrfToken: empty string when no csrf input present', () => {
  const without = SAMPLE_LOGIN_NODES.filter((n) => n.attributes.name !== 'csrf_token');
  assert.equal(csrfToken(without), '');
});

test('csrfToken: ignores non-default-group csrf-shaped inputs', () => {
  const sneaky = [
    { group: 'password', attributes: { node_type: 'input', name: 'csrf_token', type: 'hidden', value: 'not-real' } },
    ...SAMPLE_LOGIN_NODES.filter((n) => n.attributes.name !== 'csrf_token'),
  ];
  assert.equal(csrfToken(sneaky), '');
});

test('hasMethod: true when group has at least one node', () => {
  assert.equal(hasMethod(SAMPLE_LOGIN_NODES, 'password'), true);
  assert.equal(hasMethod(SAMPLE_LOGIN_NODES, 'webauthn'), true);
});

test('hasMethod: false when group has none', () => {
  assert.equal(hasMethod(SAMPLE_LOGIN_NODES, 'totp'), false);
  assert.equal(hasMethod(SAMPLE_LOGIN_NODES, 'oidc'), false);
});

test('findInput: finds an input by name across groups', () => {
  const ident = findInput(SAMPLE_LOGIN_NODES, 'identifier');
  assert.equal(ident?.name, 'identifier');
  assert.equal(ident?.type, 'text');
});

test('findInput: null for missing name', () => {
  assert.equal(findInput(SAMPLE_LOGIN_NODES, 'nope'), null);
});

test('findInput: null when matching node is non-input', () => {
  assert.equal(findInput(SAMPLE_LOGIN_NODES, 'webauthn_script'), null);
});

test('scriptNodes: returns script nodes with id + src', () => {
  const scripts = scriptNodes(SAMPLE_LOGIN_NODES);
  assert.equal(scripts.length, 1);
  assert.equal(scripts[0].id, 'webauthn_script');
  assert.equal(scripts[0].src, '/.well-known/ory/webauthn.js');
});

test('scriptNodes: empty when no scripts present', () => {
  const noScripts = SAMPLE_LOGIN_NODES.filter((n) => n.attributes.node_type !== 'script');
  assert.deepEqual(scriptNodes(noScripts), []);
});

test('inputProps: basic input → name + type + value', () => {
  const props = inputProps({ node_type: 'input', name: 'identifier', type: 'text', value: 'a.user' });
  assert.equal(props.name, 'identifier');
  assert.equal(props.type, 'text');
  assert.equal(props.value, 'a.user');
});

test('inputProps: submit input → carries button label in value', () => {
  const props = inputProps({ node_type: 'input', name: 'method', type: 'submit', value: 'password' });
  assert.equal(props.value, 'password');
});

test('inputProps: passes required + autocomplete through', () => {
  const props = inputProps({
    node_type: 'input',
    name: 'password',
    type: 'password',
    required: true,
    autocomplete: 'current-password',
  });
  assert.equal(props.required, true);
  assert.equal(props.autocomplete, 'current-password');
});

test('inputProps: disabled true preserved', () => {
  const props = inputProps({ node_type: 'input', name: 'x', type: 'text', disabled: true });
  assert.equal(props.disabled, true);
});

test('inputProps: raw onclick is stripped (security; pages emit via safeOnclick allowlist)', () => {
  const props = inputProps({
    node_type: 'input',
    name: 'webauthn_login',
    type: 'button',
    value: 'sign in with passkey',
    onclick: 'window.oryWebAuthnLogin(); return false;',
  });
  assert.equal('onclick' in props, false);
});

test('inputProps: null value on non-submit → no value field', () => {
  const props = inputProps({ node_type: 'input', name: 'identifier', type: 'text', value: null });
  assert.equal('value' in props, false);
});

test('inputProps: undefined value → no value field', () => {
  const props = inputProps({ node_type: 'input', name: 'identifier', type: 'text' });
  assert.equal('value' in props, false);
});
