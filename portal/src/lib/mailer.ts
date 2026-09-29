// SMTP mailer for portal-originated mail (the dashboard contact/request form).
//
// Reuses the SAME courier connection Kratos uses: OTHALA_SMTP_CONNECTION_URI is
// the single source of truth for the SMTP relay, consumed by both
// kratos/kratos.yml (`courier.smtp.connection_uri`) and this module. One URI,
// one relay — a contact-form mail travels the exact same outbound path as a
// recovery/verification code.
//
// The transport is built LAZILY and cached: the module imports cleanly without
// opening a socket, so `astro build` and unit tests don't need a live relay.
//
// Error discipline (project posture): on a send failure the caller surfaces a
// generic 5xx. This module throws a MailerError whose message is safe to LOG
// server-side but the API route never echoes SMTP internals to the client.

import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { smtpConnectionUri, smtpFromAddress, instanceName } from './config';

export class MailerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MailerError';
  }
}

/**
 * Parse a courier SMTP connection URI into nodemailer transport options.
 *
 * Accepts `smtps://user:pass@host:port` (implicit TLS) and
 * `smtp://user:pass@host:port` (plain / STARTTLS). User and password are
 * URL-decoded (Kratos requires them URL-encoded in the URI).
 *
 * Exported for unit testing the parse without opening a socket.
 */
export interface SmtpOptions {
  host: string;
  port: number;
  secure: boolean;
  auth?: { user: string; pass: string };
}

export function parseSmtpUri(uri: string): SmtpOptions {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    throw new MailerError('SMTP connection URI is not a valid URL');
  }
  const scheme = u.protocol.replace(/:$/, '').toLowerCase();
  if (scheme !== 'smtp' && scheme !== 'smtps') {
    throw new MailerError(`unsupported SMTP scheme "${scheme}" (want smtp|smtps)`);
  }
  const secure = scheme === 'smtps';
  const host = u.hostname;
  if (!host) throw new MailerError('SMTP connection URI has no host');
  const port = u.port ? Number(u.port) : secure ? 465 : 587;
  if (!Number.isFinite(port) || port <= 0) {
    throw new MailerError('SMTP connection URI has an invalid port');
  }
  const opts: SmtpOptions = { host, port, secure };
  if (u.username) {
    opts.auth = {
      user: decodeURIComponent(u.username),
      pass: decodeURIComponent(u.password),
    };
  }
  return opts;
}

let _transport: Transporter | null = null;

function transport(): Transporter {
  if (_transport) return _transport;
  _transport = nodemailer.createTransport(parseSmtpUri(smtpConnectionUri));
  return _transport;
}

export interface ContactMail {
  /** Resolved recipient (config.contactRecipient). */
  to: string;
  /** Verified Kratos identity id of the signed-in sender. */
  identityId: string;
  /** Verified username of the signed-in sender. */
  username: string;
  /** Submitter-provided display name (already validated + length-capped). */
  fromName: string;
  /** Request category (already validated against the allowlist). */
  requestType: string;
  /** Free-text body (already validated + length-capped). */
  message: string;
}

/**
 * Send a contact/request-form submission to the operator. Throws MailerError
 * on any transport failure; the message is safe to log but MUST NOT be relayed
 * verbatim to the HTTP client.
 *
 * Submitted content is placed in the BODY only (never interpolated into headers
 * or the envelope), so a hostile name/message cannot inject headers.
 */
export async function sendContactRequest(mail: ContactMail): Promise<void> {
  const subject = `[${instanceName}] ${mail.requestType} request from ${mail.fromName}`;
  const text =
    `A request came in from the ${instanceName} dashboard.\n\n` +
    `Account: ${mail.username} (${mail.identityId})\n` +
    `Name:    ${mail.fromName}\n` +
    `Type:    ${mail.requestType}\n` +
    `\nMessage:\n${mail.message}\n`;
  try {
    await transport().sendMail({
      from: smtpFromAddress,
      to: mail.to,
      subject: subject.replace(/[\r\n]+/g, ' '), // belt-and-suspenders header hygiene
      text,
    });
  } catch (err) {
    throw new MailerError(
      `contact mail send failed: ${err instanceof Error ? err.message : 'unknown transport error'}`,
    );
  }
}

/** Test-only: drop the cached transport so a fresh URI is re-parsed. */
export function _resetForTests(): void {
  _transport = null;
}
