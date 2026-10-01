// One-time code inputs take digits only: " 482 913" typed, pasted or autofilled becomes 482913, so a copied code never
// meets the browser's "match the requested format" message. Without script the pattern and title still guard the field.

const digits = (v: string, max: number) => v.replace(/\D+/g, '').slice(0, max);
const maxOf = (el: HTMLInputElement) => (el.maxLength > 0 ? el.maxLength : 6);

document.addEventListener('input', (e) => {
  const el = e.target;
  if (!(el instanceof HTMLInputElement) || !el.classList.contains('code-input')) return;
  const clean = digits(el.value, maxOf(el));
  if (clean !== el.value) el.value = clean;
});

document.addEventListener('paste', (e) => {
  const el = e.target;
  if (!(el instanceof HTMLInputElement) || !el.classList.contains('code-input')) return;
  const text = e.clipboardData?.getData('text');
  if (text === undefined) return;
  e.preventDefault();
  el.value = digits(text, maxOf(el));
  el.dispatchEvent(new Event('input', { bubbles: true }));
});
