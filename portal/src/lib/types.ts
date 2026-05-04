// Kratos types lifted from the OpenAPI spec, narrowed to the shapes
// this portal actually consumes. Not exhaustive: nodes carry many more
// attributes than we touch.
//
// Source: https://www.ory.com/docs/kratos/reference/api

export type AAL = 'aal0' | 'aal1' | 'aal2' | 'aal3';
export type FlowType = 'browser' | 'api';
export type MessageType = 'info' | 'error' | 'success';

export interface Identity {
  id: string;
  schema_id: string;
  schema_url?: string;
  state?: 'active' | 'inactive';
  traits: {
    username: string;
    email: string;
    displayName?: string;
    recoveryEmail?: string;
  };
  metadata_admin?: {
    groups?: string[];
    /** Per-app role overrides keyed by OIDC client_id. */
    roles?: Record<string, string>;
  };
  verifiable_addresses?: Array<{
    id: string;
    value: string;
    verified: boolean;
    via: string;
    status: string;
  }>;
  recovery_addresses?: Array<{
    id: string;
    value: string;
    via: string;
  }>;
}

export interface Session {
  id: string;
  active: boolean;
  expires_at: string;
  authenticated_at: string;
  authenticator_assurance_level: AAL;
  identity?: Identity;
}

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
  text: { id?: number; text: string; type?: MessageType };
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
  meta?: { label?: { id?: number; text?: string } };
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

export interface RegistrationFlow extends BaseFlow {
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
