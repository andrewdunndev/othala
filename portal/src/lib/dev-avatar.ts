// A placeholder member picture for `astro dev`, drawn in code: a 96px PNG of concentric diamonds. Fixtures use it so the
// picture UI renders without Kratos; pages read it only when import.meta.env.DEV is true.

import { deflateSync } from 'node:zlib';
import { parseAvatarBytes, type Avatar } from './avatar';

const SIZE = 96;
const PALETTE: Array<[number, number, number]> = [
  [38, 70, 83],
  [42, 157, 143],
  [233, 196, 106],
  [244, 162, 97],
  [231, 111, 81],
];

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(b: Buffer): number {
  let c = 0xffffffff;
  for (const v of b) c = CRC_TABLE[(c ^ v) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type: string, data: Buffer): Buffer {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const out = Buffer.alloc(body.length + 8);
  out.writeUInt32BE(data.length, 0);
  body.copy(out, 4);
  out.writeUInt32BE(crc32(body), body.length + 4);
  return out;
}

function drawPng(): Buffer {
  const rows = Buffer.alloc((SIZE * 3 + 1) * SIZE);
  for (let y = 0; y < SIZE; y++) {
    const base = y * (SIZE * 3 + 1);
    for (let x = 0; x < SIZE; x++) {
      const d = Math.abs(x - SIZE / 2 + 0.5) + Math.abs(y - SIZE / 2 + 0.5);
      const [r, g, b] = PALETTE[Math.floor(d / 10) % PALETTE.length];
      rows.set([r, g, b], base + 1 + x * 3);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(SIZE, 0);
  ihdr.writeUInt32BE(SIZE, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(rows)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const parsed = parseAvatarBytes(drawPng());
if (!parsed.ok) throw new Error(`[othala/dev-avatar] placeholder refused: ${parsed.code}`);

/** The placeholder as a stored avatar, so fixtures take the same read path as a real one. */
export const DEV_AVATAR: Avatar = parsed.avatar;

/** The placeholder as a data: URL, which the page can show without the /avatar route. */
export const DEV_AVATAR_SRC = `data:${DEV_AVATAR.type};base64,${DEV_AVATAR.data}`;
