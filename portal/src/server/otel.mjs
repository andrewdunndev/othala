// OpenTelemetry bootstrap, PII-safe by construction: spans never carry cookies, CSRF tokens, bearer headers,
// challenge ids, codes or bodies. Loaded via NODE_OPTIONS="--import ./otel.mjs" so http is patched before listen.mjs
// runs. OFF unless OTHALA_OTLP_ENDPOINT (host:port, plaintext HTTP to the collector, as Kratos and Hydra use it) is
// set; service name, environment and sampling are fixed.
// A telemetry failure must never take down the IdP: the bootstrap is try/catch-wrapped and logs one stderr line.

import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { BatchSpanProcessor, ParentBasedSampler, TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';

// One log line, prefixed like listen.mjs.
function log(msg) {
  process.stderr.write(`[portal:otel] ${msg}\n`);
}


// Placeholder written over any sensitive value.
const REDACTED = '[REDACTED]';

// Header attributes to overwrite with REDACTED (kept, so the trace shows presence); matched by lower-cased
// `http.{request,response}.header.<name>` suffix.
const SENSITIVE_HEADER_SUFFIXES = [
  'cookie',          // http.request.header.cookie
  'set-cookie',      // http.response.header.set-cookie
  'authorization',   // http.request.header.authorization
  'x-csrf-token',    // http.{request,response}.header.x-csrf-token
];

// Attributes that may hold a '?'-bearing URL; sensitive query values are scrubbed. `url.query` is a bare query
// string, so redactAttributes routes it through scrubQuery directly.
const URL_ATTR_KEYS = ['http.url', 'http.target', 'url.full'];

// Query params whose VALUES are scrubbed.
const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'code',
  'state',
  'login_challenge',
  'consent_challenge',
  'logout_challenge',
  'flow',
  // return_to can carry a nested URL that itself holds a challenge id.
  'return_to',
]);

/** Header attribute to redact? Case-insensitive suffix match. */
function isSensitiveHeaderAttr(key) {
  const k = key.toLowerCase();
  if (!k.startsWith('http.') || k.indexOf('.header.') === -1) return false;
  return SENSITIVE_HEADER_SUFFIXES.some((suffix) => k.endsWith(`.header.${suffix}`));
}

/** Scrub sensitive VALUES from a bare query string (no '?', path or fragment), keeping keys; shared by scrubUrl and `url.query`. */
export function scrubQuery(query) {
  if (typeof query !== 'string' || query.length === 0) return query;
  return query
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      if (eq === -1) return pair; // bare flag, no value to scrub
      const key = pair.slice(0, eq);
      return SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())
        ? `${key}=${REDACTED}`
        : pair;
    })
    .join('&');
}

/** Scrub sensitive query VALUES from a '?'-bearing string, keeping keys. Splits on the first '?' rather than URL-parsing, which throws on relative targets; the bare-query case is scrubQuery's. */
export function scrubUrl(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  const q = value.indexOf('?');
  if (q === -1) return value;
  const head = value.slice(0, q);
  // A trailing fragment carries no query params; keep it verbatim.
  let query = value.slice(q + 1);
  let frag = '';
  const h = query.indexOf('#');
  if (h !== -1) {
    frag = query.slice(h); // includes the '#'
    query = query.slice(0, h);
  }
  return `${head}?${scrubQuery(query)}${frag}`;
}

/** True if a span targets /admin/…, which is never exported. */
export function isAdminSpan(attributes) {
  if (!attributes) return false;
  // Prefer the parsed route/target, else scan the URL attrs; any /admin/ prefix is dropped.
  const candidates = [
    attributes['http.route'],
    attributes['http.target'],
    attributes['url.path'],
    attributes['http.url'],
    attributes['url.full'],
  ];
  for (const c of candidates) {
    if (typeof c !== 'string') continue;
    // Strip scheme://host so the prefix test sees the path.
    const path = c.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+/, '');
    if (path.startsWith('/admin/') || path === '/admin') return true;
  }
  return false;
}

/** Redact header attributes and scrub URL attributes in place; exported so the contract is testable without the SDK. */
export function redactAttributes(attributes) {
  if (!attributes) return attributes;
  for (const key of Object.keys(attributes)) {
    if (isSensitiveHeaderAttr(key)) {
      attributes[key] = REDACTED;
    }
  }
  for (const key of URL_ATTR_KEYS) {
    if (typeof attributes[key] === 'string') {
      attributes[key] = scrubUrl(attributes[key]);
    }
  }
  // `url.query` is a bare query string; scrubUrl would pass it through unscrubbed (review finding M2).
  if (typeof attributes['url.query'] === 'string') {
    attributes['url.query'] = scrubQuery(attributes['url.query']);
  }
  return attributes;
}

/** Span processor enforcing the PII contract: /admin/ spans are dropped, all others redacted in place; wraps the delegate and intercepts only onEnd. */
export class RedactingSpanProcessor {
  constructor(delegate) {
    this._delegate = delegate;
  }
  onStart(span, parentContext) {
    this._delegate.onStart(span, parentContext);
  }
  onEnd(span) {
    if (isAdminSpan(span.attributes)) return;
    redactAttributes(span.attributes);
    this._delegate.onEnd(span);
  }
  forceFlush() {
    return this._delegate.forceFlush();
  }
  shutdown() {
    return this._delegate.shutdown();
  }
}

// ── Bootstrap ──

const SERVICE_NAME = 'othala-portal';
const SAMPLING_RATIO = 0.1; // matches the Kratos and Hydra tracing blocks

/** The exporter URL for OTHALA_OTLP_ENDPOINT, or null when tracing is off (unset or blank). */
export function otlpTracesUrl(env = process.env) {
  const endpoint = (env.OTHALA_OTLP_ENDPOINT ?? '').trim();
  return endpoint ? `http://${endpoint}/v1/traces` : null;
}

/** Start the OTel Node SDK iff OTHALA_OTLP_ENDPOINT is set; returns the SDK, or null when disabled or init failed. Never throws. */
export function startTelemetry(env = process.env) {
  const url = otlpTracesUrl(env);
  if (!url) {
    log('disabled (OTHALA_OTLP_ENDPOINT unset) — no spans exported');
    return null;
  }

  try {
    const resource = resourceFromAttributes({
      [ATTR_SERVICE_NAME]: SERVICE_NAME,
      'deployment.environment': 'production',
    });

    const traceExporter = new OTLPTraceExporter({ url });

    // Batch, then redact: every exported span is scrubbed and admin spans never leave the process.
    const spanProcessor = new RedactingSpanProcessor(new BatchSpanProcessor({ exporter: traceExporter }));

    const sdk = new NodeSDK({
      resource,
      spanProcessors: [spanProcessor],
      // HTTP instrumentation only: getNodeAutoInstrumentations() would pull in body-capturing ones.
      instrumentations: [
        new HttpInstrumentation({
          // Skip /admin/ spans at creation so their attributes are never built.
          ignoreIncomingRequestHook: (req) => {
            const url = req.url ?? '';
            const path = url.split('?')[0];
            return path.startsWith('/admin/') || path === '/admin';
          },
        }),
      ],
      sampler: new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(SAMPLING_RATIO) }),
    });

    sdk.start();
    log(`enabled — service=${SERVICE_NAME} url=${url} (HTTP/protobuf, redaction on)`);

    // Flush the final batch on shutdown, best-effort.
    const shutdown = () => {
      sdk.shutdown().catch(() => {});
    };
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);

    return sdk;
  } catch (err) {
    // Non-fatal: log one line and continue without tracing.
    log(`init failed, continuing without telemetry: ${err?.message ?? err}`);
    return null;
  }
}

// Auto-start on import (the --import entrypoint); a no-op in unit tests unless an endpoint is set.
startTelemetry();
