// The picture size cap and its refusal copy, shared by the server (avatar.ts) and the browser cropper. No Node imports,
// so the cropper bundle can take it.

export const AVATAR_MAX_BYTES = 64 * 1024;

export const AVATAR_TOO_LARGE = `That picture is too large. Choose a smaller one, under ${AVATAR_MAX_BYTES / 1024} KB.`;
