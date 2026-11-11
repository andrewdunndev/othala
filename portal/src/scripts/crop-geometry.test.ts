import { describe, expect, it } from 'vitest';
import { OUTPUT, centered, clampOffset, cover, zoomAbout, zoomMax, sourceRect } from './crop-geometry';

describe('crop geometry', () => {
  it('cover fits the short side to the stage', () => {
    expect(cover(280, 1600, 1200)).toBeCloseTo(280 / 1200);
    expect(cover(280, 300, 900)).toBeCloseTo(280 / 300);
  });

  it('zoomMax keeps the source square at or above the output size', () => {
    expect(zoomMax(1600, 1200)).toBe(4);
    expect(zoomMax(300, 300)).toBeCloseTo(300 / OUTPUT);
    expect(zoomMax(300, 300)).toBeGreaterThan(1.17);
    expect(zoomMax(200, 200)).toBe(1);
  });

  it('clampOffset pins the image over the stage', () => {
    const s = 0.5;
    expect(clampOffset(50, 50, 800, 600, s, 280)).toEqual({ ox: 0, oy: 0 });
    expect(clampOffset(-9999, -9999, 800, 600, s, 280)).toEqual({ ox: 280 - 400, oy: 280 - 300 });
    expect(clampOffset(-10, -5, 800, 600, s, 280)).toEqual({ ox: -10, oy: -5 });
  });

  it('zoomAbout keeps the chosen stage point on the same source point', () => {
    const [cx, cy, oldS, newS, ox, oy] = [90, 140, 0.4, 1.1, -37, -12];
    const before = { x: (cx - ox) / oldS, y: (cy - oy) / oldS };
    const n = zoomAbout(cx, cy, oldS, newS, ox, oy);
    expect((cx - n.ox) / newS).toBeCloseTo(before.x);
    expect((cy - n.oy) / newS).toBeCloseTo(before.y);
  });

  it('sourceRect at centered zoom 1 is the centre square', () => {
    const [w, h, L] = [1600, 1200, 280];
    const s = cover(L, w, h);
    const { ox, oy } = centered(w, h, s, L);
    const r = sourceRect(ox, oy, s, L);
    expect(r.side).toBeCloseTo(Math.min(w, h));
    expect(r.sx).toBeCloseTo((w - h) / 2);
    expect(r.sy).toBeCloseTo(0);
  });

  it('sourceRect at max zoom is never under the output size', () => {
    const [w, h, L] = [300, 300, 280];
    const s = cover(L, w, h) * zoomMax(w, h);
    expect(sourceRect(0, 0, s, L).side).toBeGreaterThanOrEqual(OUTPUT - 1e-9);
  });
});
