// View model for the account settings page: digests a Kratos settings flow's flat node list into the lists and
// states the cards render (passkeys, security keys, authenticator app, backup codes) and the status line. Pure, so
// the page stays markup and the fixtures and tests share one reading of the flow.

import { asInput } from './nodes';
import type { FlowNode, FlowMessage, NodeImageAttributes, NodeInputAttributes, NodeTextAttributes } from './types';
import type { PasskeyNames } from './passkey-names';

export interface CredentialItem {
  /** Hex credential id: the passkey_remove / webauthn_remove node value. */
  id: string;
  /** Name Kratos holds (security keys), or the person's stored name (passkeys); null when unnamed. */
  name: string | null;
  addedAt: Date | null;
  /** False when Kratos disabled the remove node (the last way to sign in). */
  removable: boolean;
  /** Kratos's own button label, kept as the accessible name of the remove action. */
  removeLabel: string;
}

const UNNAMED = 'unnamed';

function parseDate(v: unknown): Date | null {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const d = new Date(typeof v === 'number' ? v * 1000 : v);
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() < 2000 ? null : d;
}

/** The listed credentials of one kind, in flow order. `names` overrides the name Kratos holds (passkeys). */
export function credentialItems(
  nodes: FlowNode[],
  removeName: 'passkey_remove' | 'webauthn_remove',
  names: PasskeyNames = {},
): CredentialItem[] {
  const out: CredentialItem[] = [];
  for (const n of nodes) {
    const a = asInput(n);
    if (!a || a.name !== removeName) continue;
    const id = String(a.value ?? '');
    const ctx = n.meta?.label?.context ?? {};
    const held = typeof ctx.display_name === 'string' && ctx.display_name !== UNNAMED ? ctx.display_name : null;
    out.push({
      id,
      name: names[id] ?? held,
      addedAt: parseDate(ctx.added_at) ?? parseDate(ctx.added_at_unix),
      removable: !a.disabled,
      removeLabel: n.meta?.label?.text ?? 'Remove',
    });
  }
  return out;
}

export interface TotpView {
  enrolled: boolean;
  qr: { src: string; alt: string; width: number; height: number } | null;
  secret: string | null;
  codeInput: NodeInputAttributes | null;
  codeMessages: FlowMessage[];
  unlink: { name: string; value: string; label: string } | null;
  save: { name: string; value: string; label: string } | null;
}

export function totpView(nodes: FlowNode[]): TotpView {
  const group = nodes.filter((n) => n.group === 'totp');
  const view: TotpView = { enrolled: false, qr: null, secret: null, codeInput: null, codeMessages: [], unlink: null, save: null };
  for (const n of group) {
    if (n.attributes.node_type === 'img') {
      const a = n.attributes as NodeImageAttributes;
      view.qr = { src: a.src, alt: n.meta?.label?.text ?? 'Authenticator app QR code', width: a.width ?? 200, height: a.height ?? 200 };
      continue;
    }
    if (n.attributes.node_type === 'text') {
      view.secret = (n.attributes as NodeTextAttributes).text?.text ?? null;
      continue;
    }
    const a = asInput(n);
    if (!a) continue;
    if (a.name === 'totp_unlink') {
      view.enrolled = true;
      view.unlink = { name: a.name, value: String(a.value ?? ''), label: n.meta?.label?.text ?? 'Remove' };
    } else if (a.name === 'totp_code') {
      view.codeInput = a;
      view.codeMessages = n.messages ?? [];
    } else if (a.type === 'submit') {
      view.save = { name: a.name, value: String(a.value ?? ''), label: n.meta?.label?.text ?? 'Verify and add' };
    }
  }
  return view;
}

export interface LookupView {
  /** Backup codes exist (the flow offers to reveal or disable them). */
  enrolled: boolean;
  /** The codes, when this flow shows them. */
  codes: string | null;
  codesLabel: string | null;
}

export function lookupView(nodes: FlowNode[]): LookupView {
  const view: LookupView = { enrolled: false, codes: null, codesLabel: null };
  for (const n of nodes) {
    if (n.group !== 'lookup_secret') continue;
    const a = asInput(n);
    if (a && (a.name === 'lookup_secret_reveal' || a.name === 'lookup_secret_disable')) view.enrolled = true;
    if (n.attributes.node_type === 'text') {
      const t = n.attributes as NodeTextAttributes;
      if (t.id === 'lookup_secret_codes' || t.text?.text) {
        view.codes = t.text?.text ?? null;
        view.codesLabel = n.meta?.label?.text ?? null;
      }
    }
  }
  return view;
}

export interface SecurityStatus {
  passkeys: number;
  securityKeys: number;
  twoStep: boolean;
  backupCodes: boolean;
  emailUnverified: boolean;
}

export function securityStatus(
  nodes: FlowNode[],
  opts: { emailVerified: boolean | null },
): SecurityStatus {
  const passkeys = credentialItems(nodes, 'passkey_remove').length;
  const securityKeys = credentialItems(nodes, 'webauthn_remove').length;
  return {
    passkeys,
    securityKeys,
    twoStep: totpView(nodes).enrolled || securityKeys > 0,
    backupCodes: lookupView(nodes).enrolled,
    emailUnverified: opts.emailVerified === false,
  };
}

/** Whether the email address is verified, from the identity's verifiable addresses; null when unknown. */
export function emailVerified(
  identity: { traits?: { email?: string }; verifiable_addresses?: Array<{ value?: string; verified?: boolean }> } | null | undefined,
): boolean | null {
  const email = identity?.traits?.email?.toLowerCase();
  const addr = identity?.verifiable_addresses?.find((v) => v.value?.toLowerCase() === email);
  return addr ? addr.verified === true : null;
}

/** "12 Jun 2026", fixed locale so the page reads the same on every server. */
export function formatAdded(d: Date | null): string | null {
  return d ? d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : null;
}
