// Helpers for working with Kratos UI node arrays.
//
// A flow.ui.nodes array is a flat list of inputs, scripts, anchors, images,
// and text. Pages render these grouped by `group` (default | password |
// passkey | webauthn | totp | code | profile | lookup_secret | oidc).

import type { FlowNode, NodeInputAttributes, NodeScriptAttributes } from './types';

// ── Onclick guard ────────────────────────────────────────────────────────────
//
// Kratos passkey/webauthn nodes carry an `onclickTrigger` attribute naming the
// /.well-known/ory/webauthn.js function to call (e.g. "oryPasskeyLogin").
// Some older Kratos versions (and the legacy webauthn strategy) also send a raw
// `onclick` string that already contains the full window.<fn>() call — these
// are generated server-side by Ory and are safe to use as-is, but the raw
// value still comes from untrusted flow JSON.
//
// Policy (HIGH-1 fix, centralised here so both login.astro and settings.astro
// use the same logic):
//   1. If `onclickTrigger` is set AND it is in KNOWN_TRIGGERS → emit
//      `window.<trigger>()`. This is the preferred, explicit path.
//   2. Else if `onclick` is set AND it starts with one of the known trigger
//      call prefixes (`window.ory...()`) → allow it through unchanged.
//      This preserves compatibility with Kratos builds that emit the full call.
//   3. Otherwise → return undefined (omit the handler; form submit fallback).
//
// The allowlist covers every trigger name from Kratos v26.2.0 passkey/webauthn
// strategy code (ui/node/identifiers.go).

export const KNOWN_TRIGGERS = new Set([
  'oryWebAuthnRegistration',
  'oryWebAuthnLogin',
  'oryPasskeyLogin',
  'oryPasskeyLoginAutocompleteInit',
  'oryPasskeyRegistration',
  'oryPasskeySettingsRegistration',
]);

/**
 * Derive the safe onclick string for a Kratos trigger button.
 *
 * Returns a `window.<trigger>()` string if the node carries a validated
 * trigger, or `undefined` if neither onclickTrigger nor onclick is
 * recognizable. Pages must never emit a raw `a.onclick` directly.
 */
export function safeOnclick(a: NodeInputAttributes): string | undefined {
  // Preferred: explicit onclickTrigger validated against the allowlist.
  if (a.onclickTrigger && KNOWN_TRIGGERS.has(a.onclickTrigger)) {
    return `window.${a.onclickTrigger}()`;
  }
  // Compat: older Kratos emits the full call in onclick. Accept it only when
  // it looks exactly like `window.ory<Fn>()` for a known trigger.
  if (a.onclick) {
    for (const trigger of KNOWN_TRIGGERS) {
      if (a.onclick === `window.${trigger}()`) {
        return a.onclick;
      }
    }
  }
  return undefined;
}

export function nodesByGroup(nodes: FlowNode[], group: FlowNode['group']): FlowNode[] {
  return nodes.filter((n) => n.group === group);
}

export function defaultNodes(nodes: FlowNode[]): FlowNode[] {
  return nodesByGroup(nodes, 'default');
}

/** Pull the CSRF token value out of the default-group hidden inputs. */
export function csrfToken(nodes: FlowNode[]): string {
  for (const n of defaultNodes(nodes)) {
    if (n.attributes.node_type !== 'input') continue;
    const a = n.attributes as NodeInputAttributes;
    if (a.name === 'csrf_token') return String(a.value ?? '');
  }
  return '';
}

/** True if a method group has at least one node (so the form should render). */
export function hasMethod(nodes: FlowNode[], group: FlowNode['group']): boolean {
  return nodes.some((n) => n.group === group);
}

/** Extract a labelled input attribute set from a node. Returns null for non-inputs. */
export function asInput(node: FlowNode): NodeInputAttributes | null {
  return node.attributes.node_type === 'input'
    ? (node.attributes as NodeInputAttributes)
    : null;
}

/** Find a single input by name across all groups. */
export function findInput(nodes: FlowNode[], name: string): NodeInputAttributes | null {
  for (const n of nodes) {
    const a = asInput(n);
    if (a && a.name === name) return a;
  }
  return null;
}

/**
 * Pull the script tag(s) Kratos returns for the passkey/webauthn flows.
 * The response includes a <script src="/.well-known/ory/webauthn.js"> node
 * that wires up the trigger button + conditional UI on the identifier input.
 *
 * Carries SRI-related attributes (integrity, crossorigin, referrerpolicy,
 * nonce) when Kratos supplies them — all four are optional; forward-compat
 * with Kratos adding SRI in a future version. Pages render them conditionally
 * (undefined-safe).
 */
// HTMLAttributeReferrerPolicy is the narrow union Astro/TSX expects on
// <script referrerpolicy>. We redeclare the relevant members here so that
// ScriptNodeData is assignable without a DOM lib import in every consumer.
type ReferrerPolicy =
  | ''
  | 'no-referrer'
  | 'no-referrer-when-downgrade'
  | 'origin'
  | 'origin-when-cross-origin'
  | 'same-origin'
  | 'strict-origin'
  | 'strict-origin-when-cross-origin'
  | 'unsafe-url';

export interface ScriptNodeData {
  id: string;
  src: string;
  integrity?: string;
  crossorigin?: string;
  /** Typed as the narrow HTMLAttributeReferrerPolicy union so Astro <script> can consume it directly. */
  referrerpolicy?: ReferrerPolicy;
  nonce?: string;
}

export function scriptNodes(nodes: FlowNode[]): ScriptNodeData[] {
  const out: ScriptNodeData[] = [];
  for (const n of nodes) {
    if (n.attributes.node_type === 'script') {
      const a = n.attributes as NodeScriptAttributes;
      out.push({
        id: a.id,
        src: a.src,
        // Carry SRI attrs when present; undefined when absent (Kratos v26.2.0
        // does not send them yet, but the type already has them).
        integrity: a.integrity,
        crossorigin: a.crossorigin,
        // NodeScriptAttributes.referrerpolicy is string | undefined; cast to
        // the narrow ReferrerPolicy union so <script referrerpolicy> in Astro
        // templates is assignable without a per-site DOM lib cast.
        referrerpolicy: a.referrerpolicy as ReferrerPolicy | undefined,
        nonce: a.nonce,
      });
    }
  }
  return out;
}

/** Map a Kratos input attribute to a DOM-safe attribute set for HTML rendering.
 *
 * NOTE: `onclick` is intentionally excluded. Callers that need a button
 * handler must call `safeOnclick(a)` directly — raw Kratos onclick strings
 * must never pass through to the DOM without trigger-allowlist validation.
 */
export function inputProps(a: NodeInputAttributes): Record<string, string | boolean> {
  const props: Record<string, string | boolean> = {
    name: a.name,
    type: a.type,
  };
  if (a.value !== undefined && a.value !== null && a.type !== 'submit') {
    props.value = String(a.value);
  } else if (a.value !== undefined && a.type === 'submit') {
    // submit buttons carry their button text in `value`
    props.value = String(a.value);
  }
  if (a.required) props.required = true;
  if (a.disabled) props.disabled = true;
  if (a.autocomplete) props.autocomplete = a.autocomplete;
  return props;
}
