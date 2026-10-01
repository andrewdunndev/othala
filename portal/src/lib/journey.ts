// House wording for the first-run pages (sign in, setup code, verification). Kratos phrases its errors for developers;
// the portal says what happened and what to do next. Ids are Kratos message ids; anything unlisted passes through.

import type { FlowMessage } from './types';
import type { NodeSpecs } from './nodes';

const BAD_CODE = "That code didn't work. Check it and try again, or ask for a new one.";

const MESSAGES: Record<number, string> = {
  4000006: "That didn't match. Check your username and password, or sign in with a passkey or an emailed code instead.",
  4010008: BAD_CODE,
  4060006: BAD_CODE,
  4070006: BAD_CODE,
  4000008: "That code didn't work. Authenticator codes change every 30 seconds, so try the one showing now.",
  4010001: 'This sign-in page timed out. Start again below.',
  4060005: 'This setup link has expired. Enter your email below and we will send a new code.',
  4070005: 'This verification page timed out. Start again below.',
};

export const journeyText = (m: Pick<FlowMessage, 'id' | 'text'>): string => MESSAGES[m.id] ?? m.text;

export const noticeClass = (type: FlowMessage['type']): string =>
  `notice notice-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'warning'}`;

/** A one-time code input: large, numeric, offered to the phone's code autofill. */
const CODE_INPUT = { inputmode: 'numeric', autocomplete: 'one-time-code', autofocus: true, class: 'code-input', placeholder: '123456' } as const;
const EMAIL_INPUT = { inputmode: 'email', autocomplete: 'email', placeholder: 'you@example.com', label: 'Email address' } as const;

/** Recovery (setup link or emailed code) wording by flow phase, keyed as FlowNodes expects. */
export function recoverySpecs(phase: 'request' | 'sent'): NodeSpecs {
  return phase === 'request'
    ? { email: EMAIL_INPUT, 'button:method': { label: 'Email me a code' } }
    : {
        code: { ...CODE_INPUT, label: 'Your code' },
        'button:method': { label: 'Verify code' },
        'button:email': { label: 'Send a new code', class: 'button button-secondary focus-btn', formnovalidate: true },
      };
}

export function verificationSpecs(phase: 'request' | 'sent'): NodeSpecs {
  return phase === 'request'
    ? { email: EMAIL_INPUT, 'button:method': { label: 'Email me a code' } }
    : {
        code: { ...CODE_INPUT, label: 'Your code' },
        'button:method': { label: 'Verify email' },
        'button:email': { label: 'Send a new code', class: 'button button-secondary focus-btn', formnovalidate: true },
      };
}

