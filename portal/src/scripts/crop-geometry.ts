// Pure math for the picture cropper. The stage is a square of side L showing the image scaled by s and shifted by
// (ox, oy), both in stage pixels; the crop is whatever the stage shows.

export const OUTPUT = 256;

export const cover = (L: number, w: number, h: number) => L / Math.min(w, h);

// Keeps the cropped source square at least OUTPUT px, so the output is never upscaled.
export const zoomMax = (w: number, h: number) => Math.max(1, Math.min(4, Math.min(w, h) / OUTPUT));

export const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

export function clampOffset(ox: number, oy: number, w: number, h: number, s: number, L: number) {
  return { ox: clamp(ox, L - w * s, 0), oy: clamp(oy, L - h * s, 0) };
}

// Offset that keeps stage point (cx, cy) fixed while the scale changes.
export function zoomAbout(cx: number, cy: number, oldS: number, newS: number, ox: number, oy: number) {
  const k = newS / oldS;
  return { ox: cx - (cx - ox) * k, oy: cy - (cy - oy) * k };
}

export const centered = (w: number, h: number, s: number, L: number) => ({ ox: (L - w * s) / 2, oy: (L - h * s) / 2 });

export const sourceRect = (ox: number, oy: number, s: number, L: number) => ({ sx: -ox / s, sy: -oy / s, side: L / s });
