// One-time code inputs take digits only: " 482 913" typed, pasted or autofilled becomes 482913, so a copied code never
// meets the browser's "match the requested format" message. Without script the pattern and title still guard the field.

import { createSubmitOnce, guardSubmits } from './submit-once';

const digits = (v: string, max: number) => v.replace(/\D+/g, '').slice(0, max);
// maxlength is set above six so the browser never truncates a spaced code before the script strips it.
const LEN = 6;
const isCode = (el: EventTarget | null): el is HTMLInputElement => el instanceof HTMLInputElement && (el.classList.contains('code-input') || el.classList.contains('codeinput'));

document.addEventListener('input', (e) => {
  const el = e.target;
  if (!isCode(el)) return;
  const clean = digits(el.value, LEN);
  if (clean !== el.value) el.value = clean;
});

document.addEventListener('paste', (e) => {
  const el = e.target;
  if (!isCode(el)) return;
  const text = e.clipboardData?.getData('text');
  if (text === undefined) return;
  e.preventDefault();
  el.value = digits(text, LEN);
  el.dispatchEvent(new Event('input', { bubbles: true }));
});

const once = createSubmitOnce();
const codeSel = 'input.code-input, input.codeinput';
const isCodeForm = (f: unknown): f is HTMLFormElement => f instanceof HTMLFormElement && f.querySelector(codeSel) !== null;
const codeForms = () => [...document.forms].filter(isCodeForm);

guardSubmits(document, once, isCodeForm);

window.addEventListener('pageshow', (e) => {
  if (e.persisted) for (const f of codeForms()) once.rearm(f);
});
