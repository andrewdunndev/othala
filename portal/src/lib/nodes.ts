// Helpers for Kratos UI node arrays: flat lists of inputs, scripts, anchors,
// images and text, rendered grouped by `group`.

import type { FlowNode, NodeInputAttributes, NodeScriptAttributes } from './types';

// Onclick guard. Kratos passkey/webauthn nodes carry `onclickTrigger` naming a
// /.well-known/ory/webauthn.js function; older builds send a raw `onclick`,
// which is untrusted flow JSON. safeOnclick emits `window.<trigger>()` only for
// a trigger in KNOWN_TRIGGERS, passes through an `onclick` that is exactly such
// a call, and otherwise returns undefined (form-submit fallback).
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
 * The script nodes Kratos returns for passkey/webauthn flows
 * (/.well-known/ory/webauthn.js), with optional SRI attributes.
 */
// Redeclared so ScriptNodeData is assignable to <script referrerpolicy> without
// a DOM lib import in every consumer.
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
  /** Narrow union so Astro <script> can consume it directly. */
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
        // SRI attrs: undefined when Kratos omits them.
        integrity: a.integrity,
        crossorigin: a.crossorigin,
        // The narrow union lets <script referrerpolicy> accept it without a cast.
        referrerpolicy: a.referrerpolicy as ReferrerPolicy | undefined,
        nonce: a.nonce,
      });
    }
  }
  return out;
}

/**
 * Map a Kratos input attribute to a DOM-safe attribute set. `onclick` is
 * excluded on purpose: callers use safeOnclick(a) so a raw string never
 * reaches the DOM unvalidated.
 */
export function inputProps(a: NodeInputAttributes): Record<string, string | boolean> {
  const props: Record<string, string | boolean> = {
    name: a.name,
    type: a.type,
  };
  if (a.value !== undefined && a.value !== null && a.type !== 'submit') {
    props.value = String(a.value);
  } else if (a.value !== undefined && a.type === 'submit') {
    // submit buttons carry their text in `value`
    props.value = String(a.value);
  }
  if (a.required) props.required = true;
  if (a.disabled) props.disabled = true;
  if (a.autocomplete) props.autocomplete = a.autocomplete;
  return props;
}
