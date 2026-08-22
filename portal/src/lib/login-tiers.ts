// Login page tier/step-up derivation — extracted from login.astro (af6927f)
// so the v0.5.0 outage class (an unfiltered webauthn glue-script node
// counted as a second factor, forcing every AAL1 login into an empty
// step-up card) has a push-gated unit guard. See login-tiers.test.ts.
//
// LITERAL extraction: the expressions below are unchanged from login.astro
// — same operators, same order, same ternaries. login.astro imports
// deriveLoginTiers() and destructures its result in place of the const
// block that used to compute these locally.

import { hasMethod, nodesByGroup, asInput } from './nodes';
import type { FlowNode, LoginFlow } from './types';

export interface LoginTiers {
  hasPasskey: boolean;
  hasCode: boolean;
  hasPassword: boolean;
  totpNodes: FlowNode[];
  aal2WebauthnNodes: FlowNode[];
  lookupNodes: FlowNode[];
  isAal2: boolean;
  hasAal2Methods: boolean;
}

/**
 * Derive what the login page branches on: the three primary sign-in tiers
 * (passkey / code / password presence) and whether the flow is an AAL2
 * step-up (and, if so, which second-factor method nodes it carries).
 *
 * `flow` is the landed LoginFlow object (or null — dev preview / no flow).
 * `aal` is the `?aal=aal2` query param, used ONLY as a fallback when there
 * is no flow to inspect at all (see the isAal2 ternary below).
 *
 * Second-factor node counting (totpNodes / aal2WebauthnNodes / lookupNodes)
 * filters through asInput() — Kratos populates the webauthn group's glue
 * <script src=".../webauthn.js"> node on EVERY flow that offers passkey or
 * webauthn, not just a step-up. Counting it unfiltered made
 * hasSecondFactorNodes — and so isAal2 — true for every ordinary AAL1
 * login (the v0.5.0 bug).
 */
export function deriveLoginTiers(flow: LoginFlow | null, aal?: 'aal1' | 'aal2'): LoginTiers {
  const ui = flow?.ui;
  const hasPasskey = ui ? hasMethod(ui.nodes, 'passkey') : true;
  const hasCode = ui ? hasMethod(ui.nodes, 'code') : true;
  const hasPassword = ui ? hasMethod(ui.nodes, 'password') : true;

  const totpNodes = ui ? nodesByGroup(ui.nodes, 'totp').filter((n) => asInput(n)) : [];
  const aal2WebauthnNodes = ui ? nodesByGroup(ui.nodes, 'webauthn').filter((n) => asInput(n)) : [];
  const lookupNodes = ui ? nodesByGroup(ui.nodes, 'lookup_secret').filter((n) => asInput(n)) : [];
  const flowRequestsAal2 = flow?.requested_aal === 'aal2';
  const hasSecondFactorNodes =
    totpNodes.length > 0 || aal2WebauthnNodes.length > 0 || lookupNodes.length > 0;
  const isAal2 = flow ? (flowRequestsAal2 || hasSecondFactorNodes) : aal === 'aal2';
  const hasAal2Methods = isAal2 && hasSecondFactorNodes;

  return {
    hasPasskey,
    hasCode,
    hasPassword,
    totpNodes,
    aal2WebauthnNodes,
    lookupNodes,
    isAal2,
    hasAal2Methods,
  };
}
