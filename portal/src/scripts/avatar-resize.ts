// Crops a chosen picture to a centered square and shrinks it to 256x256 (WebP, else PNG) before the form is sent, so a
// phone photo fits the server's 64 KB cap. A file the browser cannot decode is left for the server to refuse.

const SIZE = 256;
const CAP = 64 * 1024;

const encode = (canvas: HTMLCanvasElement, type: string, quality?: number) =>
  new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, type, quality));

async function squared(file: File): Promise<File | null> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return null;
  }
  const side = Math.min(bitmap.width, bitmap.height);
  const canvas = document.createElement('canvas');
  canvas.width = SIZE;
  canvas.height = SIZE;
  canvas.getContext('2d')?.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, SIZE, SIZE);
  bitmap.close();
  for (const [type, ext, qualities] of [['image/webp', 'webp', [0.9, 0.7, 0.5]], ['image/png', 'png', [undefined]]] as const) {
    for (const q of qualities) {
      const blob = await encode(canvas, type, q);
      if (blob && blob.type === type && blob.size <= CAP) return new File([blob], `picture.${ext}`, { type });
    }
  }
  return null;
}

document.addEventListener('change', async (e) => {
  const input = e.target;
  if (!(input instanceof HTMLInputElement) || input.type !== 'file' || !input.form?.hasAttribute('data-avatar-form')) return;
  const file = input.files?.[0];
  if (!file) return;
  const out = await squared(file);
  if (!out) return;
  const dt = new DataTransfer();
  dt.items.add(out);
  input.files = dt.files;
});
