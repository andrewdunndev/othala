// Invariant: portal tracing is off unless OTHALA_OTLP_ENDPOINT is set; the OTEL_* inputs are not read.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { otlpTracesUrl, startTelemetry } from '../src/server/otel.mjs';

test('otlpTracesUrl: off when OTHALA_OTLP_ENDPOINT is unset or blank', () => {
  assert.equal(otlpTracesUrl({}), null);
  assert.equal(otlpTracesUrl({ OTHALA_OTLP_ENDPOINT: '  ' }), null);
});

test('otlpTracesUrl: host:port becomes the plaintext HTTP traces URL', () => {
  assert.equal(otlpTracesUrl({ OTHALA_OTLP_ENDPOINT: 'alloy:4318' }), 'http://alloy:4318/v1/traces');
});

test('otlpTracesUrl: ignores the standard OTEL_EXPORTER_OTLP_ENDPOINT', () => {
  assert.equal(otlpTracesUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector:4318' }), null);
});

test('startTelemetry: returns null without starting the SDK when the endpoint is unset', () => {
  assert.equal(startTelemetry({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector:4318' }), null);
});
