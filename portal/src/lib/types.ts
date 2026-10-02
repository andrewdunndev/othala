// Portal type surface. Admin types (Identity, Session, OAuth2Client) come from
// the Ory SDK. The browser-flow / UI-node types stay hand-maintained: the SDK
// deserialises dates and UiNode differently from the raw JSON the renderer
// reads, and the casts in kratos.ts are safe because only unchanged fields are read.

import type {
  AuthenticatorAssuranceLevel as SdkAAL,
  Identity as SdkIdentity,
  Session as SdkSession,
} from '@ory/client-fetch';

// ── Admin / programmatic surface: SDK types ─────────────────────────────────

export type { OAuth2Client } from '@ory/client-fetch';

/**
 * SDK Identity, with `metadata_admin` narrowed to the portal's structured
 * shape. The OpenAPI generator types `metadata_admin` as the opaque
 * `object` (it's free-form on the wire), but every portal consumer reads
 * `metadata_admin.groups` / `.roles` — and `metadata-admin.ts` validates
 * exactly that contract at the write boundary. Narrowing here restores
 * those reads without re-hand-rolling the whole Identity shape.
 */
export type Identity = Omit<SdkIdentity, 'metadata_admin'> & {
  metadata_admin?: {
    groups?: string[];
    /** Per-app role overrides keyed by OIDC client_id. */
    roles?: Record<string, string>;
    /**
     * Admin authority marker. Set to `true` (boolean strict) via
     * the Kratos admin API only — never through self-service flows. The portal
     * reads this only from admin-API-fetched identities; Kratos v26.2.0
     * excludes metadata_admin from the public /sessions/whoami response.
     */
    admin?: boolean;
    /** Prerequisite names the admin marked set up for this person (see admin-api patchPrerequisites). */
    prerequisites?: string[];
    /** Passkey names keyed by hex credential id (see passkey-names.ts). */
    passkeyNames?: Record<string, string>;
  } | null;
};

/** SDK Session, carrying the narrowed Identity (metadata_admin reads). */
export type Session = Omit<SdkSession, 'identity'> & {
  identity?: Identity;
};

// ── Browser-flow / UI-node rendering surface: hand-maintained ───────────────

export type AAL = SdkAAL;
export type FlowType = 'browser' | 'api';
export type MessageType = 'info' | 'error' | 'success';

export interface FlowMessage {
  id: number;
  text: string;
  type: MessageType;
  context?: Record<string, unknown>;
}

// A node attribute is one of: input | a | img | text | script.
// Input is by far the common case for forms.
export interface NodeInputAttributes {
  name: string;
  type:
    | 'text'
    | 'password'
    | 'email'
    | 'hidden'
    | 'submit'
    | 'button'
    | 'checkbox'
    | 'number'
    | 'datetime-local'
    | 'date'
    | 'url'
    | 'tel';
  value?: string | number | boolean;
  required?: boolean;
  disabled?: boolean;
  autocomplete?: string;
  // Kratos uses "node_type": "input" to discriminate.
  node_type: 'input';
  // Buttons/triggers carry an onclick handler string the script wires up.
  onclick?: string;
  // Used by passkey discoverable-credential trigger.
  onclickTrigger?: string;
}

export interface NodeScriptAttributes {
  node_type: 'script';
  id: string;
  src: string;
  async?: boolean;
  // Kratos serves /.well-known/ory/webauthn.js, sometimes with integrity hash.
  integrity?: string;
  crossorigin?: string;
  referrerpolicy?: string;
  type?: string;
  nonce?: string;
}

export interface NodeAnchorAttributes {
  node_type: 'a';
  id?: string;
  href: string;
  title?: { text?: string };
}

export interface NodeImageAttributes {
  node_type: 'img';
  id?: string;
  src: string;
  alt?: string;
  width?: number;
  height?: number;
}

export interface NodeTextAttributes {
  node_type: 'text';
  id?: string;
  text: { id?: number; text: string; type?: MessageType; context?: Record<string, unknown> };
}

export type NodeAttributes =
  | NodeInputAttributes
  | NodeScriptAttributes
  | NodeAnchorAttributes
  | NodeImageAttributes
  | NodeTextAttributes;

export interface FlowNode {
  type: 'input' | 'a' | 'img' | 'text' | 'script';
  // Group: default | password | passkey | webauthn | totp | code | profile | lookup_secret | oidc | identifier_first
  group:
    | 'default'
    | 'password'
    | 'passkey'
    | 'webauthn'
    | 'totp'
    | 'code'
    | 'profile'
    | 'lookup_secret'
    | 'oidc'
    | 'identifier_first';
  attributes: NodeAttributes;
  messages?: FlowMessage[];
  meta?: { label?: { id?: number; text?: string; context?: Record<string, unknown> } };
}

export interface FlowUI {
  action: string;
  method: 'POST' | 'GET';
  nodes: FlowNode[];
  messages?: FlowMessage[];
}

export interface BaseFlow {
  id: string;
  type: FlowType;
  expires_at: string;
  issued_at: string;
  request_url: string;
  return_to?: string;
  ui: FlowUI;
}

export interface LoginFlow extends BaseFlow {
  refresh?: boolean;
  requested_aal?: AAL;
  oauth2_login_challenge?: string;
}

export interface SettingsFlow extends BaseFlow {
  identity: Identity;
  state: 'show_form' | 'success';
}

export interface RecoveryFlow extends BaseFlow {
  state: 'choose_method' | 'sent_email' | 'passed_challenge';
  active?: 'code' | 'link';
}

export interface VerificationFlow extends BaseFlow {
  state: 'choose_method' | 'sent_email' | 'passed_challenge';
  active?: 'code' | 'link';
}

// Convenience: flow lookup may resolve to "flow gone" rather than throwing.
export type FlowResult<T> =
  | { kind: 'ok'; flow: T }
  | { kind: 'gone' }
  | { kind: 'unauthorized' };
