// Invariant: the render writes caddy/othala.caddy with the literal public URL and every Caddy placeholder intact. It
// defines exactly othala-routes, othala-forward-auth and othala-oidc-app, each one route block, with the two rate-limit
// zones and no site address, TLS or server option. Forward-auth strips client identity headers before the auth call,
// redirects only a 401 and answers 403 and 503 in place. A missing or malformed OTHALA_PUBLIC_URL fails by name.

import { afterAll, test } from 'vitest';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, render, renderTemplate, SECRETS } from '../src/lib/render.ts';

const root = fileURLToPath(new URL('../../', import.meta.url));
const URL_VALUE = 'https://auth.example.org';
const VALUES = {
  OTHALA_PUBLIC_URL: URL_VALUE,
  OTHALA_APEX: 'example.org',
  OTHALA_INSTANCE_NAME: 'Example Household',
  KRATOS_ADMIN_BIND_HOST: '10.0.0.1',
  HYDRA_ADMIN_BIND_HOST: '10.0.0.2',
};
const ENV = { ...VALUES, ...Object.fromEntries(SECRETS.map((n) => [n, `fake-${n.toLowerCase()}`])), KRATOS_CIPHER_SECRET_CURRENT: 'c'.repeat(32) };

const CONTENT = mkdtempSync(join(tmpdir(), 'othala-content-'));
mkdirSync(join(CONTENT, 'apps'));
afterAll(() => rmSync(CONTENT, { recursive: true, force: true }));

const TEMPLATE = readFileSync(join(root, 'caddy/othala.caddy'), 'utf8');
const renderedCaddy = (env = ENV, policy = root) => render(policy, CONTENT, env).find((f) => f.path === 'caddy/othala.caddy').content;

const STRIPPED = [
  'X-Kratos-Authenticated-Identity-Id', 'X-Kratos-Groups', 'X-Remote-User', 'X-Remote-Groups', 'X-Remote-Email', 'X-Remote-Name',
  'X-Forwarded-User', 'X-Forwarded-Groups', 'X-Forwarded-Email', 'X-Auth-Request-User', 'X-Auth-Request-Groups', 'X-Auth-Request-Email',
];

// The file's block tree: a line ending in `{` opens a block, a lone `}` closes it; placeholders never span lines.
function tree(text) {
  const top = { head: '', body: [] };
  const stack = [top];
  for (const line of text.split('\n').map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'))) {
    const current = stack[stack.length - 1];
    if (line === '}') {
      assert.ok(stack.length > 1, 'a } closes nothing');
      stack.pop();
    } else if (line.endsWith('{')) {
      const block = { head: line.slice(0, -1).trim(), body: [] };
      current.body.push(block);
      stack.push(block);
    } else current.body.push(line);
  }
  assert.equal(stack.length, 1, 'a block is never closed');
  return top;
}
const blocksOf = (b) => b.body.filter((x) => typeof x !== 'string');
const linesOf = (b) => b.body.filter((x) => typeof x === 'string');
const walk = (b) => [b, ...blocksOf(b).flatMap(walk)];
const allLines = (b) => walk(b).flatMap((x) => [x.head, ...linesOf(x)]).filter(Boolean);
const placeholders = (text) => [...text.matchAll(/\{[^{}\s]*\}/g)].map((m) => m[0]).sort();

const out = tree(renderedCaddy());
const snippet = (name) => blocksOf(out).find((b) => b.head === `(${name})`);
const routeOf = (name) => blocksOf(snippet(name))[0];

test('render writes the snippets with the public URL substituted and every Caddy placeholder intact', () => {
  const text = renderedCaddy();
  assert.ok(text.includes(`redir ${URL_VALUE}/auth/login?return_to={http.request.scheme}://{http.request.host}{http.request.uri.path} 302`));
  assert.equal(text.includes('${'), false);
  const expected = placeholders(TEMPLATE.replace(/\$\{[A-Za-z_][A-Za-z0-9_]*\}/g, ''));
  assert.ok(expected.length >= 15 && expected.includes('{client_ip}') && expected.includes('{args[2]}'), 'placeholder corpus is vacuous');
  assert.deepEqual(placeholders(text), expected);
});

test('the render token never matches Caddy syntax', () => {
  const src = 'a {$OTHALA_PUBLIC_URL} {$X:default} {env.OTHALA_PUBLIC_URL} {args[0]} {args[:]} {client_ip} {http.request.uri.path}\nb ${OTHALA_PUBLIC_URL}/x\n';
  const want = 'a {$OTHALA_PUBLIC_URL} {$X:default} {env.OTHALA_PUBLIC_URL} {args[0]} {args[:]} {client_ip} {http.request.uri.path}\nb https://auth.example.org/x\n';
  assert.equal(renderTemplate('x.caddy', src, { OTHALA_PUBLIC_URL: URL_VALUE }), want);
});

test('the snippets may name only OTHALA_PUBLIC_URL, so a $ before a Caddy placeholder fails closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'othala-policy-'));
  try {
    for (const tree of ['kratos', 'hydra', 'caddy']) cpSync(join(root, tree), join(dir, tree), { recursive: true });
    writeFileSync(join(dir, 'caddy/othala.caddy'), `${TEMPLATE}\n(x) {\n\trespond "\${client_ip} \${CSRF_SECRET}"\n}\n`);
    assert.deepEqual(check(dir, CONTENT, VALUES), ['caddy/othala.caddy: the edge snippets may name only OTHALA_PUBLIC_URL; remove CSRF_SECRET, client_ip']);
    assert.throws(() => render(dir, CONTENT, ENV), /remove CSRF_SECRET, client_ip/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('three snippets, each one route block, and nothing a site Caddyfile owns', () => {
  assert.deepEqual(linesOf(out), []);
  assert.deepEqual(blocksOf(out).map((b) => b.head), ['(othala-routes)', '(othala-forward-auth)', '(othala-oidc-app)']);
  for (const b of blocksOf(out)) {
    assert.deepEqual(linesOf(b), [], b.head);
    assert.deepEqual(blocksOf(b).map((x) => x.head), ['route'], b.head);
  }
  const owned = /^(tls|dns|order|servers|trusted_proxies|client_ip_headers|proxy_protocol|listener_wrappers|bind|https_port|http_port|auto_https|email|acme_dns)\b/;
  for (const line of allLines(out)) assert.ok(!owned.test(line), line);
});

test('othala-routes carries the two zones ahead of the upstreams, which all see the verified client address', () => {
  const zones = walk(out).filter((b) => b.head.startsWith('zone ')).map((b) => b.head);
  assert.deepEqual(zones, ['zone othala_device', 'zone othala_selfservice']);
  assert.deepEqual(walk(routeOf('othala-routes')).filter((b) => b.head.startsWith('zone ')).map((b) => b.head), zones);
  const body = routeOf('othala-routes').body;
  const firstHandle = body.findIndex((x) => typeof x !== 'string' && x.head.startsWith('handle'));
  const limits = body.flatMap((x, i) => (typeof x !== 'string' && x.head.startsWith('rate_limit') ? [i] : []));
  assert.deepEqual(limits.length, 2);
  assert.ok(limits.every((i) => i < firstHandle), 'a rate_limit runs after a handle');
  const proxies = walk(routeOf('othala-routes')).filter((b) => b.head.startsWith('reverse_proxy '));
  assert.deepEqual([...new Set(proxies.map((b) => b.head))].sort(), ['reverse_proxy hydra:4444', 'reverse_proxy kratos:4433', 'reverse_proxy othala:8080']);
  for (const p of proxies) assert.ok(p.body.includes('header_up X-Forwarded-For {client_ip}'), p.head);
});

test('every snippet strips the client identity headers first', () => {
  for (const name of ['othala-routes', 'othala-forward-auth', 'othala-oidc-app']) {
    const body = routeOf(name).body;
    assert.deepEqual(body.slice(0, STRIPPED.length), STRIPPED.map((h) => `request_header -${h}`), name);
  }
});

test('forward-auth asks the portal with the group, copies the verified id, and proxies with no cookies', () => {
  const body = routeOf('othala-forward-auth').body;
  const blocks = body.filter((x) => typeof x !== 'string');
  assert.deepEqual(blocks.map((b) => b.head), ['forward_auth othala:8080', 'reverse_proxy {args[0]}:{args[1]}']);
  assert.ok(body.indexOf(blocks[0]) > body.lastIndexOf('request_header -X-Kratos-Authenticated-Identity-Id'));
  assert.ok(blocks[0].body.includes('uri /api/forward-auth?group={args[2]}'));
  assert.ok(blocks[0].body.includes('copy_headers X-Kratos-Authenticated-Identity-Id'));
  assert.deepEqual(blocks[1].body, ['header_up -Cookie']);
  assert.ok(!allLines(snippet('othala-forward-auth')).some((l) => l.includes('/sessions/whoami')));
});

test('only a 401 redirects to login; 403 and 503 answer in place without echoing the group', () => {
  const fa = blocksOf(routeOf('othala-forward-auth'))[0];
  const matchers = linesOf(fa).filter((l) => l.startsWith('@'));
  assert.deepEqual(matchers, ['@unauthorized status 401', '@denied status 403', '@idp_down status 503']);
  const arms = Object.fromEntries(blocksOf(fa).map((b) => [b.head, b.body]));
  assert.deepEqual(Object.keys(arms), ['handle_response @unauthorized', 'handle_response @denied', 'handle_response @idp_down']);
  assert.deepEqual(arms['handle_response @unauthorized'].map((l) => l.split(' ')[0]), ['redir']);
  for (const [arm, status] of [['handle_response @denied', 403], ['handle_response @idp_down', 503]]) {
    const [header, respond] = arms[arm];
    assert.equal(header, 'header Content-Type "text/html; charset=utf-8"');
    assert.match(respond, new RegExp(`^respond "<!doctype html>[^"{}]*" ${status}$`));
  }
  assert.deepEqual(allLines(snippet('othala-forward-auth')).filter((l) => l.startsWith('redir')).length, 1);
});

test('oidc-app removes only the Kratos session cookie before proxying', () => {
  const body = routeOf('othala-oidc-app').body;
  assert.deepEqual(body.slice(STRIPPED.length), ['request_header Cookie "(^|;\\s*)ory_kratos_session=[^;]*" ""', 'reverse_proxy {args[0]}:{args[1]}']);
});

test('a missing or malformed OTHALA_PUBLIC_URL fails check and render, naming it and never its value', () => {
  assert.throws(() => render(root, CONTENT, { ...ENV, OTHALA_PUBLIC_URL: undefined }), /caddy\/othala\.caddy: missing render variable\(s\): OTHALA_PUBLIC_URL/);
  const bad = ['https://auth.example.org/', 'https://auth.example.org/sso', 'auth.example.org', 'ftp://auth.example.org', 'https://Auth.example.org',
    'https://auth.example.org {', 'https://{a}.example.org', 'https://auth.example.org"', 'https://auth.example.org?x=1', 'https://user@auth.example.org', ''];
  for (const value of bad) {
    const errors = check(root, CONTENT, { ...VALUES, OTHALA_PUBLIC_URL: value });
    assert.ok(errors.some((e) => e.startsWith('caddy/othala.caddy: OTHALA_PUBLIC_URL must be a lowercase origin')), JSON.stringify(value));
    let message = '';
    try {
      render(root, CONTENT, { ...ENV, OTHALA_PUBLIC_URL: value });
    } catch (err) {
      message = err.message;
    }
    assert.match(message, /OTHALA_PUBLIC_URL must be a lowercase origin/, JSON.stringify(value));
    if (value !== '') assert.ok(!message.includes(value), 'error carries the value');
  }
  for (const value of ['http://auth.othala.test', 'https://sso.example.org:8443', 'http://10.0.0.5:8080']) {
    assert.deepEqual(check(root, CONTENT, { ...VALUES, OTHALA_PUBLIC_URL: value }), [], value);
  }
});
