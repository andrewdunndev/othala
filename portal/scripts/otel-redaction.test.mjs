// Tests for src/server/otel.mjs — the PII redaction contract (review finding H1).
//
// Run with: npx vitest run scripts/otel-redaction.test.mjs
//
// This is the IdP telemetry path: spans must never carry session cookies, CSRF
// tokens, bearer headers, OAuth challenge ids, recovery/login codes, or one-time
// tokens. We import ONLY the exported pure functions + the processor class — we
// do NOT call startTelemetry / stand up the SDK (importing the module is a no-op
// because OTEL_EXPORTER_OTLP_ENDPOINT is unset in the test env).

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  scrubUrl,
  scrubQuery,
  isAdminSpan,
  redactAttributes,
  RedactingSpanProcessor,
} from '../src/server/otel.mjs';

const REDACTED = '[REDACTED]';

// ── scrubUrl: '?'-bearing URLs ──────────────────────────────────────────────

test('scrubUrl redacts every sensitive value in a ?-bearing http.url', () => {
  const url =
    'https://auth.example.test/auth/login?token=t1&code=c1&state=s1' +
    '&login_challenge=lc1&consent_challenge=cc1&logout_challenge=gc1&flow=f1';
  const out = scrubUrl(url);
  for (const k of [
    'token',
    'code',
    'state',
    'login_challenge',
    'consent_challenge',
    'logout_challenge',
    'flow',
  ]) {
    assert.match(out, new RegExp(`${k}=\\[REDACTED\\]`), `${k} not redacted`);
  }
  // Path is preserved; no raw sensitive value survives.
  assert.ok(out.startsWith('https://auth.example.test/auth/login?'));
  for (const v of ['t1', 'c1', 's1', 'lc1', 'cc1', 'gc1', 'f1']) {
    assert.equal(out.includes(`=${v}`), false, `raw value ${v} leaked`);
  }
});

test('scrubUrl preserves non-sensitive params and a relative http.target shape', () => {
  const out = scrubUrl('/auth/login?token=secret&return_to=/dashboard&foo=bar');
  assert.match(out, /token=\[REDACTED\]/);
  assert.match(out, /return_to=\/dashboard/);
  assert.match(out, /foo=bar/);
  assert.ok(out.startsWith('/auth/login?'));
});

test('scrubUrl preserves path and trailing fragment verbatim', () => {
  const out = scrubUrl('/oauth2/consent?consent_challenge=abc&ok=1#section-2');
  assert.match(out, /consent_challenge=\[REDACTED\]/);
  assert.match(out, /ok=1/);
  assert.ok(out.endsWith('#section-2'), 'fragment not preserved');
  assert.ok(out.startsWith('/oauth2/consent?'));
});

test('scrubUrl returns a ?-less string unchanged', () => {
  assert.equal(scrubUrl('/auth/login'), '/auth/login');
  assert.equal(scrubUrl(''), '');
  assert.equal(scrubUrl(undefined), undefined);
});

// ── scrubQuery: the bare-query path (url.query, no leading '?') ──────────────

test('scrubQuery scrubs a bare query string (no leading ?)', () => {
  const out = scrubQuery('token=abc&foo=bar');
  assert.match(out, /token=\[REDACTED\]/);
  assert.match(out, /foo=bar/);
  assert.equal(out.includes('abc'), false, 'raw token leaked');
});

test('scrubQuery is case-insensitive on the key and keeps bare flags', () => {
  assert.match(scrubQuery('TOKEN=abc'), /TOKEN=\[REDACTED\]/);
  assert.equal(scrubQuery('debug&foo=bar'), 'debug&foo=bar');
});

// ── isAdminSpan ─────────────────────────────────────────────────────────────

test('isAdminSpan is true for /admin/ targets and absolute admin URLs', () => {
  assert.equal(isAdminSpan({ 'http.target': '/admin/' }), true);
  assert.equal(isAdminSpan({ 'http.target': '/admin/revoke-user' }), true);
  assert.equal(isAdminSpan({ 'http.route': '/admin/recovery-gate' }), true);
  assert.equal(
    isAdminSpan({ 'http.url': 'https://host/admin/revoke-user' }),
    true,
  );
});

test('isAdminSpan is false for non-admin routes and empty/missing attrs', () => {
  assert.equal(isAdminSpan({ 'http.target': '/auth/login' }), false);
  assert.equal(isAdminSpan({ 'url.path': '/' }), false);
  assert.equal(isAdminSpan({}), false);
  assert.equal(isAdminSpan(null), false);
});

// ── redactAttributes: headers (incl. array-valued) + url attrs ──────────────

test('redactAttributes redacts sensitive request/response header attrs', () => {
  const attrs = {
    'http.request.header.cookie': 'ory_kratos_session=abc',
    'http.request.header.authorization': 'Bearer xyz',
    'http.request.header.x-csrf-token': 'csrf123',
    'http.response.header.set-cookie': 'ory_kratos_session=def; Path=/',
    'http.request.header.accept': 'text/html',
  };
  redactAttributes(attrs);
  assert.equal(attrs['http.request.header.cookie'], REDACTED);
  assert.equal(attrs['http.request.header.authorization'], REDACTED);
  assert.equal(attrs['http.request.header.x-csrf-token'], REDACTED);
  assert.equal(attrs['http.response.header.set-cookie'], REDACTED);
  // Non-sensitive header untouched.
  assert.equal(attrs['http.request.header.accept'], 'text/html');
});

test('redactAttributes redacts ARRAY-valued sensitive headers (set-cookie)', () => {
  const attrs = {
    'http.response.header.set-cookie': ['a=1; Path=/', 'b=2; HttpOnly'],
    'http.request.header.cookie': ['v'],
  };
  redactAttributes(attrs);
  assert.equal(attrs['http.response.header.set-cookie'], REDACTED);
  assert.equal(attrs['http.request.header.cookie'], REDACTED);
});

test('redactAttributes scrubs ?-bearing url attrs and the bare url.query', () => {
  const attrs = {
    'http.url': 'https://host/auth/login?token=t&foo=bar',
    'http.target': '/oauth2/consent?consent_challenge=cc&ok=1',
    'url.full': 'https://host/x?code=c',
    'url.query': 'flow=f&keep=1', // BARE — no leading '?'
  };
  redactAttributes(attrs);
  assert.match(attrs['http.url'], /token=\[REDACTED\]/);
  assert.match(attrs['http.url'], /foo=bar/);
  assert.match(attrs['http.target'], /consent_challenge=\[REDACTED\]/);
  assert.match(attrs['url.full'], /code=\[REDACTED\]/);
  // The bare-query path — must be scrubbed even with no '?' (finding M2).
  assert.match(attrs['url.query'], /flow=\[REDACTED\]/);
  assert.match(attrs['url.query'], /keep=1/);
  assert.equal(attrs['url.query'].includes('=f&'), false, 'raw flow leaked');
});

// ── RedactingSpanProcessor.onEnd ────────────────────────────────────────────

// Fake delegate capturing the lifecycle calls the processor forwards.
function fakeDelegate() {
  const calls = { onStart: [], onEnd: [], forceFlush: 0, shutdown: 0 };
  return {
    calls,
    onStart(span, ctx) {
      calls.onStart.push([span, ctx]);
    },
    onEnd(span) {
      calls.onEnd.push(span);
    },
    forceFlush() {
      calls.forceFlush += 1;
      return Promise.resolve();
    },
    shutdown() {
      calls.shutdown += 1;
      return Promise.resolve();
    },
  };
}

test('RedactingSpanProcessor DROPS an admin span (delegate.onEnd not called)', () => {
  const delegate = fakeDelegate();
  const proc = new RedactingSpanProcessor(delegate);
  proc.onEnd({ attributes: { 'http.target': '/admin/revoke-user' } });
  assert.equal(delegate.calls.onEnd.length, 0, 'admin span was forwarded');
});

test('RedactingSpanProcessor forwards a non-admin span ONCE with scrubbed attrs', () => {
  const delegate = fakeDelegate();
  const proc = new RedactingSpanProcessor(delegate);
  const span = {
    attributes: {
      'http.target': '/auth/login?token=secret&foo=bar',
      'http.request.header.cookie': 'ory_kratos_session=abc',
    },
  };
  proc.onEnd(span);
  assert.equal(delegate.calls.onEnd.length, 1, 'non-admin span not forwarded once');
  const forwarded = delegate.calls.onEnd[0];
  assert.strictEqual(forwarded, span, 'forwarded a different span object');
  // Redaction happened in place before the delegate saw it.
  assert.match(forwarded.attributes['http.target'], /token=\[REDACTED\]/);
  assert.match(forwarded.attributes['http.target'], /foo=bar/);
  assert.equal(forwarded.attributes['http.request.header.cookie'], REDACTED);
});
