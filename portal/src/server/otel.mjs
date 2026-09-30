// OpenTelemetry bootstrap for the portal SSR/admin process — PII-SAFE by
// construction. This is the IdP: spans must never carry session cookies, CSRF
// tokens, bearer headers, OAuth challenge ids, recovery/login codes, or request
// bodies. Redaction here is a HARD requirement, not a nicety.
//
// LOADED via NODE_OPTIONS="--import ./otel.mjs" (see portal/Containerfile), so
// it runs BEFORE listen.mjs imports anything — the http instrumentation must
// monkey-patch node:http before the SSR handler binds. ESM `--import` runs this
// module in the same realm as the app, ahead of the entrypoint.
//
// OFF by default: if OTEL_EXPORTER_OTLP_ENDPOINT is unset/empty we do NOT start
// the SDK. Dev (`astro dev`) and the e2e harness set no endpoint, so this is a
// pure no-op there — and a deploy with no reachable collector degrades to "no
// telemetry", never a crash. Unlike Ory (which ignores OTEL_* and reads its
// own `tracing:` block), the Node SDK natively honors the standard OTEL_* env:
//   OTEL_EXPORTER_OTLP_ENDPOINT   collector base URL (HTTP/protobuf, :4318)
//   OTEL_EXPORTER_OTLP_HEADERS    e.g. "authorization=Bearer <ingest-token>"
//   OTLP_INGEST_TOKEN             bare ingestion key; we compose the
//                                 Authorization header from it (deploy convenience
//                                 so a podman Secret= can carry just the token).
//                                 An explicit OTEL_EXPORTER_OTLP_HEADERS wins.
//   OTEL_SERVICE_NAME             resource service.name (default othala-portal)
//   OTEL_TRACES_SAMPLER           e.g. parentbased_traceidratio
//   OTEL_TRACES_SAMPLER_ARG       e.g. 0.1
//   OTEL_RESOURCE_ATTRIBUTES      e.g. "deployment.environment=production"
//
// A telemetry failure must NEVER take down the IdP, so the whole bootstrap is
// wrapped in try/catch and we log exactly one line to stderr on enable/disable.

import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';

// One stable log line, prefixed like listen.mjs's `[portal] …` messages.
function log(msg) {
  process.stderr.write(`[portal:otel] ${msg}\n`);
}

// ── Redaction primitives ────────────────────────────────────────────────────

// The literal placeholder we write over any sensitive value.
const REDACTED = '[REDACTED]';

// Header attributes the http instrumentation may capture. The attribute key is
// `http.{request,response}.header.<lower-cased-header-name>`. We match the
// suffix case-insensitively so both the old (`http.request.header.cookie`) and
// any header-name casing collapse to one rule. Anything here is OVERWRITTEN
// with REDACTED rather than deleted, so the trace still shows the header was
// present without leaking its value.
const SENSITIVE_HEADER_SUFFIXES = [
  'cookie',          // http.request.header.cookie
  'set-cookie',      // http.response.header.set-cookie
  'authorization',   // http.request.header.authorization
  'x-csrf-token',    // http.{request,response}.header.x-csrf-token
];

// Span attributes that may hold a '?'-bearing URL/target. We scrub named-
// sensitive query params out of each (keeping the key, replacing the value) so
// a sampled span can't carry an OAuth challenge id or a one-time code. NOTE:
// `url.query` is handled SEPARATELY (see redactAttributes) — the stable-semconv
// `url.query` attribute is a BARE query string (no leading '?'), so it goes
// through scrubQuery directly rather than scrubUrl (which keys off the '?').
const URL_ATTR_KEYS = ['http.url', 'http.target', 'url.full'];

// Query-param names whose VALUES must be scrubbed. Cookies/codes/challenge ids
// /flow ids are all sensitive in an IdP request line.
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

/** Is this a header attribute we must redact? Case-insensitive suffix match. */
function isSensitiveHeaderAttr(key) {
  const k = key.toLowerCase();
  if (!k.startsWith('http.') || k.indexOf('.header.') === -1) return false;
  return SENSITIVE_HEADER_SUFFIXES.some((suffix) => k.endsWith(`.header.${suffix}`));
}

/**
 * Scrub sensitive query-param VALUES out of a BARE query string (no leading
 * '?', no path, no fragment) — e.g. "token=abc&flow=xyz". Keeps each key,
 * replacing only the sensitive values. This is the shared primitive used by
 * both scrubUrl (for the query portion of a '?'-bearing attr) and the bare
 * `url.query` attribute path. Returns the (possibly) rewritten query string.
 */
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

/**
 * Scrub sensitive query-param VALUES out of a '?'-bearing URL-ish string,
 * keeping each key. Operates on the query portion only; the path is untouched.
 * Tolerant of values that are not full URLs (e.g. a bare "/path?token=…"
 * target) — we split on the first '?' and rewrite the query manually rather
 * than rely on URL parsing, which would throw on a relative target. Returns the
 * (possibly) rewritten string; if there is no query string it is returned
 * unchanged. The BARE-query case (a query with no leading '?', as carried by
 * the stable-semconv `url.query` attribute) is handled by scrubQuery directly.
 */
export function scrubUrl(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  const q = value.indexOf('?');
  if (q === -1) return value;
  const head = value.slice(0, q);
  // Preserve a trailing fragment (#…) verbatim — it carries no query params.
  let query = value.slice(q + 1);
  let frag = '';
  const h = query.indexOf('#');
  if (h !== -1) {
    frag = query.slice(h); // includes the '#'
    query = query.slice(0, h);
  }
  return `${head}?${scrubQuery(query)}${frag}`;
}

/** True if a span targets an admin route (/admin/…) we must NOT export. */
export function isAdminSpan(attributes) {
  if (!attributes) return false;
  // Prefer the parsed route/target; fall back to scanning the URL attrs. The
  // admin mux serves /admin/recovery-gate and the other webhooks
  // (see listen.mjs) — any /admin/ prefix is dropped wholesale.
  const candidates = [
    attributes['http.route'],
    attributes['http.target'],
    attributes['url.path'],
    attributes['http.url'],
    attributes['url.full'],
  ];
  for (const c of candidates) {
    if (typeof c !== 'string') continue;
    // Strip scheme://host for absolute URLs so the prefix test sees the path.
    const path = c.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+/, '');
    if (path.startsWith('/admin/') || path === '/admin') return true;
  }
  return false;
}

/**
 * Mutate a span's attributes in place: redact sensitive header attributes and
 * scrub sensitive query params from URL attributes. Pure-ish helper, exported
 * so the redaction contract is unit-testable without standing up the SDK.
 */
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
  // `url.query` (stable semconv) is a BARE query string — no leading '?', so
  // scrubUrl's '?'-keyed early-return would pass it through UNSCRUBBED. Scrub
  // it directly as a bare query (review finding M2).
  if (typeof attributes['url.query'] === 'string') {
    attributes['url.query'] = scrubQuery(attributes['url.query']);
  }
  return attributes;
}

/**
 * SpanProcessor that enforces the PII contract before any span reaches the
 * wrapped exporter pipeline:
 *   - /admin/ spans are DROPPED entirely (never forwarded to onEnd).
 *   - all other spans have their header + URL attributes redacted in place.
 * It delegates lifecycle (onStart/forceFlush/shutdown) to the real processor,
 * intercepting only onEnd. Implemented as a thin wrapper rather than a
 * subclass so it works against the BatchSpanProcessor instance regardless of
 * its internal shape.
 */
export class RedactingSpanProcessor {
  constructor(delegate) {
    this._delegate = delegate;
  }
  onStart(span, parentContext) {
    this._delegate.onStart(span, parentContext);
  }
  onEnd(span) {
    // Drop admin spans outright — do not forward to the exporter.
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

// ── Bootstrap ─────────────────────────────────────────────────────────────

/**
 * Start the OTel Node SDK iff a collector endpoint is configured. Returns the
 * started NodeSDK, or null when telemetry is disabled or init failed. Never
 * throws — a telemetry failure must not crash the IdP.
 */
export function startTelemetry(env = process.env) {
  const endpoint = (env.OTEL_EXPORTER_OTLP_ENDPOINT ?? '').trim();
  if (!endpoint) {
    // OFF: no collector configured (dev / e2e / collector-less deploy).
    log('disabled (OTEL_EXPORTER_OTLP_ENDPOINT unset) — no spans exported');
    return null;
  }

  try {
    const serviceName = env.OTEL_SERVICE_NAME?.trim() || 'othala-portal';
    // deployment.environment travels via OTEL_RESOURCE_ATTRIBUTES (the standard
    // OTEL_* channel), which the SDK's env detector already merges into the
    // resource — so we don't parse it by hand here, we just name the service.
    const resource = resourceFromAttributes({ [ATTR_SERVICE_NAME]: serviceName });

    // HTTP/protobuf exporter. The SDK reads OTEL_EXPORTER_OTLP_ENDPOINT (and
    // OTEL_EXPORTER_OTLP_HEADERS, when set) from env. For the ingestion key we
    // also accept a BARE token via OTLP_INGEST_TOKEN — a clean podman Secret=
    // delivers just the token, and we compose the `Authorization: Bearer …`
    // header here (matching the Ory-side authorization_header). An explicit
    // OTEL_EXPORTER_OTLP_HEADERS takes precedence and disables this composition.
    const ingestToken = (env.OTLP_INGEST_TOKEN ?? '').trim();
    const explicitHeaders = (env.OTEL_EXPORTER_OTLP_HEADERS ?? '').trim();
    const exporterOpts = {};
    if (ingestToken && ingestToken !== 'disabled' && !explicitHeaders) {
      exporterOpts.headers = { authorization: `Bearer ${ingestToken}` };
    }
    const traceExporter = new OTLPTraceExporter(exporterOpts);

    // Batch for efficiency, then wrap in the redactor so EVERY exported span is
    // scrubbed and admin spans are dropped before they leave the process.
    const spanProcessor = new RedactingSpanProcessor(new BatchSpanProcessor(traceExporter));

    const sdk = new NodeSDK({
      resource,
      spanProcessors: [spanProcessor],
      // HTTP instrumentation ONLY. We do not use getNodeAutoInstrumentations()
      // — those would pull in body/payload-capturing instrumentations (express,
      // fs, etc.) we explicitly do not want on an IdP. The http instrumentation
      // captures NO request/response body by default; we add nothing that would.
      instrumentations: [
        new HttpInstrumentation({
          // Belt-and-suspenders: don't even create spans for /admin/ incoming
          // requests (the RedactingSpanProcessor would drop them, but skipping
          // here avoids ever building the attributes). Match the path prefix.
          ignoreIncomingRequestHook: (req) => {
            const url = req.url ?? '';
            const path = url.split('?')[0];
            return path.startsWith('/admin/') || path === '/admin';
          },
        }),
      ],
      // Sampler: honored from OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG
      // (e.g. parentbased_traceidratio + 0.1). Leaving `sampler` unset lets the
      // SDK's env-driven sampler resolution take over, which is the conservative
      // parent-based default we want.
    });

    sdk.start();
    log(`enabled — service=${serviceName} endpoint=${endpoint} (HTTP/protobuf, redaction on)`);

    // Flush on shutdown so the final batch is not lost. Best-effort; swallow.
    const shutdown = () => {
      sdk.shutdown().catch(() => {});
    };
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);

    return sdk;
  } catch (err) {
    // A telemetry init failure is non-fatal: log one line and continue with no
    // tracing. The IdP keeps serving.
    log(`init failed, continuing without telemetry: ${err?.message ?? err}`);
    return null;
  }
}

// Auto-start on import (the --import entrypoint). Guarded so importing this
// module from a unit test does not stand up the SDK unless an endpoint is set.
startTelemetry();
