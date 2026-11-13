// The picture cropper: the chosen file is shown in a stage the member drags and zooms, then cropped to 256x256 and
// shrunk to fit the server's size cap before the form is sent. A file the browser cannot decode is reported here; one
// that cannot be made small enough is not sent. All elements come from AvatarEditor.astro; this only fills and toggles.
import { OUTPUT, centered, clamp, clampOffset, cover, sourceRect, zoomAbout, zoomMax } from './crop-geometry';
import { AVATAR_MAX_BYTES, AVATAR_TOO_LARGE } from '../lib/avatar-limits';

const UNREADABLE = 'That file is not a picture this browser can read. Choose a JPEG, PNG or WebP photo.';

const ENCODERS: ReadonlyArray<readonly [string, string, number | undefined]> = [
  ['image/webp', 'webp', 0.9],
  ['image/jpeg', 'jpg', 0.9],
  ['image/jpeg', 'jpg', 0.75],
  ['image/jpeg', 'jpg', 0.6],
  ['image/png', 'png', undefined],
];

const encode = (canvas: HTMLCanvasElement, type: string, quality?: number) =>
  new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, type, quality));

type Pt = { x: number; y: number };
interface Crop {
  file: File | null;
  url: string | null;
  previewUrl: string | null;
  origSrc: string | null;
  w: number;
  h: number;
  L: number;
  zoom: number;
  max: number;
  ox: number;
  oy: number;
  pointers: Map<number, Pt>;
}

const crops = new WeakMap<Element, Crop>();
const state = (editor: Element): Crop => {
  let c = crops.get(editor);
  if (!c) crops.set(editor, (c = { file: null, url: null, previewUrl: null, origSrc: null, w: 0, h: 0, L: 0, zoom: 1, max: 1, ox: 0, oy: 0, pointers: new Map() }));
  return c;
};

const q = <T extends Element>(root: Element, sel: string) => root.querySelector<T>(sel);
const editorOf = (el: EventTarget | null) => (el instanceof Element ? el.closest<HTMLElement>('.avatar-editor') : null);

function setState(editor: HTMLElement, s: 'empty' | 'cropping' | 'ready' | 'error') {
  editor.dataset.state = s;
  const set = (sel: string, hidden: boolean) => {
    const el = q<HTMLElement>(editor, sel);
    if (el) el.hidden = hidden;
  };
  set('.crop', s !== 'cropping' && s !== 'error');
  set('[data-ready-hint]', s !== 'ready');
  set('[data-crop-adjust]', s !== 'ready');
  const save = q<HTMLButtonElement>(editor, 'button[type="submit"]');
  if (save) save.disabled = s === 'cropping' || s === 'error';
  const use = q<HTMLButtonElement>(editor, '[data-crop-use]');
  if (use) use.disabled = s !== 'cropping';
}

function fail(editor: HTMLElement, input: HTMLInputElement, message: string, clear: boolean) {
  const err = q<HTMLElement>(editor, '[data-crop-error]');
  if (err) {
    err.textContent = message;
    err.hidden = false;
  }
  if (clear) input.value = '';
  input.setCustomValidity(message);
  setState(editor, 'error');
  input.focus();
}

function render(editor: HTMLElement) {
  const c = state(editor);
  const stage = q<HTMLElement>(editor, '[data-crop-stage]');
  const img = q<HTMLImageElement>(editor, '[data-crop-img]');
  const slider = q<HTMLInputElement>(editor, '[data-crop-zoom]');
  if (!stage || !img || !c.w) return;
  c.L = stage.clientWidth || c.L;
  const s = cover(c.L, c.w, c.h) * c.zoom;
  Object.assign(c, clampOffset(c.ox, c.oy, c.w, c.h, s, c.L));
  img.style.transform = `translate(${c.ox}px, ${c.oy}px) scale(${s})`;
  if (slider) {
    slider.value = String(c.zoom);
    slider.setAttribute('aria-valuetext', `${c.zoom.toFixed(1)}×`);
  }
}

function setZoom(editor: HTMLElement, zoom: number, cx: number, cy: number) {
  const c = state(editor);
  const next = clamp(zoom, 1, c.max);
  const base = cover(c.L, c.w, c.h);
  Object.assign(c, zoomAbout(cx, cy, base * c.zoom, base * next, c.ox, c.oy));
  c.zoom = next;
  render(editor);
}

function open(editor: HTMLElement, input: HTMLInputElement, file: File) {
  const c = state(editor);
  const img = q<HTMLImageElement>(editor, '[data-crop-img]');
  if (!img) return;
  if (c.url) URL.revokeObjectURL(c.url);
  if (c.previewUrl) {
    URL.revokeObjectURL(c.previewUrl);
    c.previewUrl = null;
    const pv = q<HTMLImageElement>(editor, '.avatar-preview img.avatar-img');
    const none = q<HTMLElement>(editor, '.avatar-none');
    c.origSrc ??= pv?.getAttribute('src') ?? '';
    if (pv) {
      pv.src = c.origSrc;
      pv.hidden = !c.origSrc;
      pv.alt = c.origSrc ? pv.alt : '';
    }
    if (none) none.hidden = !!c.origSrc;
  }
  c.file = file;
  c.url = URL.createObjectURL(file);
  const err = q<HTMLElement>(editor, '[data-crop-error]');
  if (err) err.hidden = true;
  img.onload = () => {
    c.w = img.naturalWidth;
    c.h = img.naturalHeight;
    c.max = zoomMax(c.w, c.h);
    c.zoom = 1;
    const slider = q<HTMLInputElement>(editor, '[data-crop-zoom]');
    if (slider) {
      slider.max = String(c.max);
      slider.disabled = c.max === 1;
    }
    setState(editor, 'cropping');
    c.L = q<HTMLElement>(editor, '[data-crop-stage]')?.clientWidth ?? 0;
    Object.assign(c, centered(c.w, c.h, cover(c.L, c.w, c.h), c.L));
    render(editor);
  };
  img.onerror = () => fail(editor, input, UNREADABLE, false);
  img.src = c.url;
}

async function crop(editor: HTMLElement, input: HTMLInputElement) {
  const c = state(editor);
  if (!c.file) return;
  render(editor);
  const use =q<HTMLButtonElement>(editor, '[data-crop-use]');
  if (use) use.disabled = true;
  const form = input.form;
  if (form) form.dataset.resizing = '1';
  try {
    const bitmap = await createImageBitmap(c.file, { imageOrientation: 'from-image' });
    const s = cover(c.L, c.w, c.h) * c.zoom;
    const r = sourceRect(c.ox, c.oy, s, c.L);
    const canvas = document.createElement('canvas');
    canvas.width = OUTPUT;
    canvas.height = OUTPUT;
    canvas.getContext('2d')?.drawImage(bitmap, r.sx, r.sy, r.side, r.side, 0, 0, OUTPUT, OUTPUT);
    bitmap.close();
    for (const [type, ext, quality] of ENCODERS) {
      const blob = await encode(canvas, type, quality);
      if (blob && blob.type === type && blob.size <= AVATAR_MAX_BYTES) {
        const out = new File([blob], `picture.${ext}`, { type });
        const dt = new DataTransfer();
        dt.items.add(out);
        input.files = dt.files;
        showResult(editor, out);
        return;
      }
    }
    fail(editor, input, AVATAR_TOO_LARGE, true);
  } catch {
    fail(editor, input, UNREADABLE, false);
  } finally {
    if (form) delete form.dataset.resizing;
  }
}

function showResult(editor: HTMLElement, file: File) {
  const c = state(editor);
  const img = q<HTMLImageElement>(editor, '.avatar-preview img.avatar-img');
  const none = q<HTMLElement>(editor, '.avatar-none');
  c.origSrc ??= img?.getAttribute('src') ?? '';
  if (c.previewUrl) URL.revokeObjectURL(c.previewUrl);
  c.previewUrl = URL.createObjectURL(file);
  if (img) {
    img.src = c.previewUrl;
    img.alt = 'Your new picture, not saved yet';
    img.hidden = false;
  }
  if (none) none.hidden = true;
  setState(editor, 'ready');
  q<HTMLButtonElement>(editor, 'button[type="submit"]')?.focus();
}

document.addEventListener('submit', (e) => {
  const form = e.target;
  if (form instanceof HTMLFormElement && form.dataset.resizing) e.preventDefault();
});

document.addEventListener('change', (e) => {
  const input = e.target;
  if (!(input instanceof HTMLInputElement) || input.type !== 'file' || !input.form?.hasAttribute('data-avatar-form')) return;
  const editor = editorOf(input);
  const file = input.files?.[0];
  if (!editor || !file) return;
  input.setCustomValidity('');
  const save = q<HTMLButtonElement>(editor, 'button[type="submit"]');
  if (save) save.disabled = true;
  open(editor, input, file);
});

const stageOf = (e: Event) => (e.target instanceof Element ? e.target.closest<HTMLElement>('[data-crop-stage]') : null);
const local = (stage: HTMLElement, e: PointerEvent): Pt => {
  const b = stage.getBoundingClientRect();
  return { x: e.clientX - b.left, y: e.clientY - b.top };
};
const dist = (a: Pt, b: Pt) => Math.hypot(a.x - b.x, a.y - b.y);

document.addEventListener('pointerdown', (e) => {
  if (e.button !== 0) return;
  const stage = stageOf(e);
  const editor = editorOf(stage);
  if (!stage || !editor) return;
  state(editor).pointers.set(e.pointerId, local(stage, e));
  try {
    stage.setPointerCapture(e.pointerId);
  } catch {
    /* pointer already gone */
  }
});

document.addEventListener('pointermove', (e) => {
  const stage = stageOf(e);
  const editor = editorOf(stage);
  if (!stage || !editor) return;
  const c = state(editor);
  const prev = c.pointers.get(e.pointerId);
  if (!prev) return;
  const now = local(stage, e);
  if (c.pointers.size === 1) {
    c.ox += now.x - prev.x;
    c.oy += now.y - prev.y;
    c.pointers.set(e.pointerId, now);
    render(editor);
    return;
  }
  const other = [...c.pointers.entries()].find(([id]) => id !== e.pointerId)?.[1];
  c.pointers.set(e.pointerId, now);
  if (!other) return;
  const before = dist(prev, other);
  if (before > 0) setZoom(editor, (c.zoom * dist(now, other)) / before, (now.x + other.x) / 2, (now.y + other.y) / 2);
});

const release = (e: PointerEvent) => {
  const editor = editorOf(stageOf(e));
  if (editor) state(editor).pointers.delete(e.pointerId);
};
document.addEventListener('pointerup', release);
document.addEventListener('pointercancel', release);

document.addEventListener('input', (e) => {
  const slider = e.target;
  if (!(slider instanceof HTMLInputElement) || !slider.hasAttribute('data-crop-zoom')) return;
  const editor = editorOf(slider);
  if (!editor) return;
  const c = state(editor);
  setZoom(editor, Number(slider.value), c.L / 2, c.L / 2);
});

document.addEventListener('keydown', (e) => {
  const stage = stageOf(e);
  const editor = editorOf(stage);
  if (!stage || !editor || e.ctrlKey || e.metaKey || e.altKey) return;
  const c = state(editor);
  const step = e.shiftKey ? 32 : 8;
  const move: Record<string, [number, number]> = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
  if (e.key in move) {
    c.ox += move[e.key][0];
    c.oy += move[e.key][1];
    render(editor);
  } else if (e.key === '+' || e.key === '=') setZoom(editor, c.zoom + 0.1, c.L / 2, c.L / 2);
  else if (e.key === '-' || e.key === '_') setZoom(editor, c.zoom - 0.1, c.L / 2, c.L / 2);
  else return;
  e.preventDefault();
});

document.addEventListener('click', (e) => {
  const t = e.target instanceof Element ? e.target : null;
  const editor = editorOf(t);
  if (!t || !editor) return;
  if (t.closest('[data-crop-use]')) {
    const input = q<HTMLInputElement>(editor, '[data-avatar-form] input[type=file]');
    if (input) void crop(editor, input);
  } else if (t.closest('[data-crop-adjust]')) {
    setState(editor, 'cropping');
    render(editor);
    q<HTMLElement>(editor, '[data-crop-stage]')?.focus();
  }
});

window.addEventListener('resize', () => {
  document.querySelectorAll<HTMLElement>('.avatar-editor[data-state="cropping"]').forEach(render);
});
