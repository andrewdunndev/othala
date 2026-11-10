// Crops a chosen picture to a centered square and shrinks it to 256x256 before the form is sent, so a phone photo fits
// the server's 64 KB cap. A file the browser cannot decode is left for the server to refuse; one that cannot be made
// small enough is not sent.

const SIZE = 256;
const CAP = 64 * 1024;
const TOO_LARGE = 'That picture is too large. Use one under 64 KB, or a smaller image.';

const ENCODERS: ReadonlyArray<readonly [string, string, number | undefined]> = [
  ['image/webp', 'webp', 0.9],
  ['image/jpeg', 'jpg', 0.9],
  ['image/jpeg', 'jpg', 0.75],
  ['image/jpeg', 'jpg', 0.6],
  ['image/png', 'png', undefined],
];

const encode = (canvas: HTMLCanvasElement, type: string, quality?: number) =>
  new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, type, quality));

type Squared = { file: File } | { tooLarge: true } | null;

async function squared(file: File): Promise<Squared> {
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
  for (const [type, ext, quality] of ENCODERS) {
    const blob = await encode(canvas, type, quality);
    if (blob && blob.type === type && blob.size <= CAP) return { file: new File([blob], `picture.${ext}`, { type }) };
  }
  return { tooLarge: true };
}

document.addEventListener('change', async (e) => {
  const input = e.target;
  if (!(input instanceof HTMLInputElement) || input.type !== 'file' || !input.form?.hasAttribute('data-avatar-form')) return;
  const file = input.files?.[0];
  if (!file) return;
  input.setCustomValidity('');
  const out = await squared(file);
  if (!out) return;
  if ('tooLarge' in out) {
    input.value = '';
    input.setCustomValidity(TOO_LARGE);
    input.reportValidity();
    return;
  }
  const dt = new DataTransfer();
  dt.items.add(out.file);
  input.files = dt.files;
});
