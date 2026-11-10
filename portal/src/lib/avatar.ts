// A member's picture, stored in metadata_admin.avatar and served at /avatar/<identity>/<hash>. Only PNG, JPEG and WebP
// are accepted, identified by their bytes: a declared type is never trusted and SVG is never an option.

import { createHash } from 'node:crypto';

export const AVATAR_TYPES = ['image/png', 'image/jpeg', 'image/webp'] as const;
export type AvatarType = (typeof AVATAR_TYPES)[number];

export interface Avatar {
  type: AvatarType;
  sha256: string;
  data: string;
}

export const AVATAR_MAX_BYTES = 64 * 1024;

export const AVATAR_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const AVATAR_HASH_RE = /^[0-9a-f]{16}$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MARKUP_RE = /<\s*(svg|script|html|iframe|\?xml)/i;

const startsWith = (b: Uint8Array, sig: readonly number[], at = 0) => sig.every((v, i) => b[at + i] === v);
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0));

/** The type a file's leading and trailing bytes prove, or null. A trailer or size mismatch means appended data. */
export function sniffImageType(b: Uint8Array): AvatarType | null {
  const n = b.length;
  if (n >= 20 && startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return startsWith(b, [0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82], n - 12) ? 'image/png' : null;
  }
  if (n >= 4 && startsWith(b, [0xff, 0xd8, 0xff])) {
    return b[n - 2] === 0xff && b[n - 1] === 0xd9 ? 'image/jpeg' : null;
  }
  if (n >= 12 && startsWith(b, ascii('RIFF')) && startsWith(b, ascii('WEBP'), 8)) {
    const size = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
    return size === n - 8 ? 'image/webp' : null;
  }
  return null;
}

export type AvatarRefusal = 'empty' | 'too-large' | 'type';

export const AVATAR_REFUSALS: Record<AvatarRefusal, string> = {
  empty: 'Choose a picture first.',
  'too-large': 'That picture is too large. Use one under 64 KB, or a smaller image.',
  type: 'Use a PNG, JPEG or WebP picture.',
};

export function parseAvatarBytes(bytes: Uint8Array): { ok: true; avatar: Avatar } | { ok: false; code: AvatarRefusal } {
  if (bytes.length === 0) return { ok: false, code: 'empty' };
  if (bytes.length > AVATAR_MAX_BYTES) return { ok: false, code: 'too-large' };
  const type = sniffImageType(bytes);
  if (!type || MARKUP_RE.test(Buffer.from(bytes).toString('latin1'))) return { ok: false, code: 'type' };
  return {
    ok: true,
    avatar: {
      type,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      data: Buffer.from(bytes).toString('base64'),
    },
  };
}

/** Why a stored value is not a well-formed avatar, or null. Re-derives the type and hash from the bytes. */
export function avatarProblem(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return 'must be an object.';
  const v = value as Record<string, unknown>;
  const extra = Object.keys(v).find((k) => k !== 'type' && k !== 'sha256' && k !== 'data');
  if (extra) return `has unknown field "${extra}".`;
  if (typeof v.data !== 'string' || !BASE64_RE.test(v.data)) return 'data must be base64.';
  if (typeof v.sha256 !== 'string' || !SHA_RE.test(v.sha256)) return 'sha256 must be 64 lowercase hex digits.';
  const parsed = parseAvatarBytes(Buffer.from(v.data, 'base64'));
  if (!parsed.ok) return AVATAR_REFUSALS[parsed.code];
  if (parsed.avatar.type !== v.type) return 'type does not match the image bytes.';
  if (parsed.avatar.sha256 !== v.sha256) return 'sha256 does not match the image bytes.';
  return null;
}

export const avatarPath = (identityId: string, avatar: Pick<Avatar, 'sha256'>): string =>
  `/avatar/${identityId}/${avatar.sha256.slice(0, 16)}`;

/** The stored avatar when it is well-formed, else undefined. */
export function readAvatar(meta: unknown): Avatar | undefined {
  if (!meta || typeof meta !== 'object') return undefined;
  const a = (meta as Record<string, unknown>).avatar;
  return avatarProblem(a) === null ? (a as Avatar) : undefined;
}

/** The adapter's bodySizeLimit rejects a stream with this message once it passes the cap (astro core limitAsyncIterable). */
export const isBodyLimitError = (err: unknown): boolean => {
  for (let e = err; e instanceof Error; e = e.cause as unknown) if (/body size limit exceeded/i.test(e.message)) return true;
  return false;
};
