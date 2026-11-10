import { describe, it, expect } from 'vitest';
import { AVATAR_MAX_BYTES, avatarPath, avatarProblem, parseAvatarBytes, readAvatar, readCapped, sniffImageType } from './avatar';
import { validateMetadataAdmin } from './metadata-admin';
import { avatarOf, imageBytes } from './test-builders';

const text = (s: string) => new TextEncoder().encode(s);
const cat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...p]));

describe('sniffImageType', () => {
  it('names png, jpeg and webp by their bytes', () => {
    expect(sniffImageType(imageBytes('png'))).toBe('image/png');
    expect(sniffImageType(imageBytes('jpeg'))).toBe('image/jpeg');
    expect(sniffImageType(imageBytes('webp'))).toBe('image/webp');
  });
  it('refuses svg, html and unknown bytes', () => {
    expect(sniffImageType(text('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBeNull();
    expect(sniffImageType(text('<html><script>alert(1)</script></html>'))).toBeNull();
    expect(sniffImageType(new Uint8Array(40))).toBeNull();
  });
  it('refuses data appended after the image, the polyglot shape', () => {
    expect(sniffImageType(cat(imageBytes('png'), text('<svg/>')))).toBeNull();
    expect(sniffImageType(cat(imageBytes('jpeg'), text('<svg/>')))).toBeNull();
    expect(sniffImageType(cat(imageBytes('webp'), text('<svg/>')))).toBeNull();
  });
});

describe('parseAvatarBytes', () => {
  it('returns the stored shape with the hash of the bytes', () => {
    const r = parseAvatarBytes(imageBytes('webp'));
    expect(r).toEqual({ ok: true, avatar: avatarOf('webp') });
  });
  it('refuses empty, over the cap, and a wrong type', () => {
    expect(parseAvatarBytes(new Uint8Array())).toEqual({ ok: false, code: 'empty' });
    const big = cat(imageBytes('jpeg').slice(0, 4), new Uint8Array(AVATAR_MAX_BYTES), Uint8Array.of(0xff, 0xd9));
    expect(parseAvatarBytes(big)).toEqual({ ok: false, code: 'too-large' });
    expect(parseAvatarBytes(text('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toEqual({ ok: false, code: 'type' });
  });
  it('accepts exactly the cap', () => {
    const edge = cat(imageBytes('jpeg').slice(0, 4), new Uint8Array(AVATAR_MAX_BYTES - 6), Uint8Array.of(0xff, 0xd9));
    expect(edge.length).toBe(AVATAR_MAX_BYTES);
    expect(parseAvatarBytes(edge).ok).toBe(true);
  });
  it('refuses markup hidden inside a well-formed image', () => {
    const png = imageBytes('png');
    const sneaky = cat(png.slice(0, 16), text('<svg onload=1>'), png.slice(16));
    expect(parseAvatarBytes(sneaky)).toEqual({ ok: false, code: 'type' });
  });
});

describe('stored avatar', () => {
  it('rejects a declared type that the bytes contradict, a wrong hash, extra keys and non-base64', () => {
    const a = avatarOf('png');
    expect(avatarProblem(a)).toBeNull();
    expect(avatarProblem({ ...a, type: 'image/svg+xml' })).toMatch(/type/);
    expect(avatarProblem({ ...a, type: 'image/jpeg' })).toMatch(/type/);
    expect(avatarProblem({ ...a, sha256: 'a'.repeat(64) })).toMatch(/sha256/);
    expect(avatarProblem({ ...a, extra: 1 })).toMatch(/unknown field/);
    expect(avatarProblem({ ...a, data: '<svg/>' })).toMatch(/base64/);
  });
  it('validateMetadataAdmin carries a valid avatar and refuses a bad one', () => {
    const a = avatarOf('webp');
    expect(validateMetadataAdmin({ groups: ['family'], avatar: a })).toEqual({ groups: ['family'], avatar: a });
    expect(() => validateMetadataAdmin({ avatar: { ...a, type: 'image/svg+xml' } })).toThrow(/avatar/);
  });
  it('readAvatar ignores a malformed value; avatarPath uses the first 16 hex digits', () => {
    const a = avatarOf('png');
    expect(readAvatar({ avatar: a })).toEqual(a);
    expect(readAvatar({ avatar: { ...a, data: 'AAAA' } })).toBeUndefined();
    expect(avatarPath('id-1', a)).toBe(`/avatar/id-1/${a.sha256.slice(0, 16)}`);
  });
});

describe('readCapped', () => {
  const post = (body: BodyInit, headers: Record<string, string> = {}) => new Request('http://portal.test/x', { method: 'POST', body, headers });
  it('returns the body under the limit and null over it, by header or by stream', async () => {
    expect(Buffer.from((await readCapped(post('abc'), 10))!).toString()).toBe('abc');
    expect(await readCapped(post('x'.repeat(11)), 10)).toBeNull();
    const stream = new ReadableStream({ start(c) { c.enqueue(text('x'.repeat(6))); c.enqueue(text('x'.repeat(6))); c.close(); } });
    const chunked = new Request('http://portal.test/x', { method: 'POST', body: stream, duplex: 'half' } as RequestInit);
    expect(await readCapped(chunked, 10)).toBeNull();
  });
});
