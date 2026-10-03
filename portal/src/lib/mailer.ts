import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { smtpConnectionUri, smtpFromAddress, instanceName } from './config';

/** Safe to log; never echoed to the HTTP client. */
export class MailerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MailerError';
  }
}

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
    // Kratos requires the credentials URL-encoded in the URI.
    opts.auth = {
      user: decodeURIComponent(u.username),
      pass: decodeURIComponent(u.password),
    };
  }
  return opts;
}

let _transport: Transporter | null = null;

export function smtpTransportOptions() {
  return {
    ...parseSmtpUri(smtpConnectionUri),
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 30_000,
  };
}

function transport(): Transporter {
  if (_transport) return _transport;
  _transport = nodemailer.createTransport(smtpTransportOptions());
  return _transport;
}

export interface ContactMail {
  to: string;
  identityId: string;
  username: string;
  fromName: string;
  requestType: string;
  message: string;
}

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
      subject: subject.replace(/[\r\n]+/g, ' '), // fromName is user input in a header
      text,
    });
  } catch (err) {
    throw new MailerError(
      `contact mail send failed: ${err instanceof Error ? err.message : 'unknown transport error'}`,
    );
  }
}

export function _resetForTests(): void {
  _transport = null;
}
