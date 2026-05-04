// Helpers for working with Kratos UI node arrays.
//
// A flow.ui.nodes array is a flat list of inputs, scripts, anchors, images,
// and text. Pages render these grouped by `group` (default | password |
// passkey | webauthn | totp | code | profile | lookup_secret | oidc).

import type { FlowNode, NodeInputAttributes } from './types';

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
 */
export function scriptNodes(nodes: FlowNode[]): Array<{ id: string; src: string }> {
  const out: Array<{ id: string; src: string }> = [];
  for (const n of nodes) {
    if (n.attributes.node_type === 'script') {
      const a = n.attributes;
      out.push({ id: a.id, src: a.src });
    }
  }
  return out;
}

/** Map a Kratos input attribute to a DOM-safe attribute set for HTML rendering. */
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
  if (a.onclick) props.onclick = a.onclick;
  return props;
}
