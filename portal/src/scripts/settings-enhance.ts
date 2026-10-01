// Progressive enhancement over the native forms (see Layout's `router`). Native posts work without this file; with it,
// a post swaps the page in place and, once swapped, the script puts the person where the answer is:
//   - a refused code (aria-invalid) takes focus and scrolls to the field, so the error is announced and in view;
//   - a saved change writes a one-line confirmation, in house voice for the action taken, into the card that was edited
//     and focuses it (Kratos only says "saved", so the action is remembered from the submit);
//   - anything else scrolls back to the card that was edited.
// The passkey and security-key ceremonies end in the script's own form.submit(), a native navigation, so they take the
// same path. A response that is not this page (a re-sign-in) navigates for real.
import { FLASH, LOST_KEYS, flashKey } from '../lib/settings-flash';

const KEY = 'othala:settings-edit';
const cardOf = (el: EventTarget | null) => (el instanceof Element ? el.closest<HTMLElement>('[data-card]') : null);
const remember = (el: EventTarget | null, action: string) => {
  const card = cardOf(el)?.id;
  if (!card) return;
  try { sessionStorage.setItem(KEY, JSON.stringify({ card, action })); } catch { /* storage unavailable */ }
};
const take = (): { card: string; action: string } | null => {
  try {
    const raw = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
};

const lostLink = () => {
  const a = document.createElement('a');
  a.href = '#signout-all';
  a.dataset.open = 'signout-all';
  a.textContent = 'Also sign out everywhere';
  return a;
};

const settle = () => {
  const edit = take();
  // A replaced app leaves the setup steps for the new one; open them where the person is looking.
  if (edit?.action === 'totp_replace') {
    const open = document.getElementById('totp-setup');
    if (open instanceof HTMLInputElement) open.checked = true;
  }
  // Copy and print need script; they stay hidden without it.
  document.querySelectorAll<HTMLElement>('[data-copy], [data-codes-tools]').forEach((el) => { el.hidden = false; });
  const wrong = document.querySelector<HTMLElement>('[aria-invalid="true"]');
  const saved = document.querySelector<HTMLElement>('[data-flow-success]');
  // A card the server already filled (the dev fixtures render the saved line themselves).
  const filled = document.querySelector<HTMLElement>('[data-flash]:not(:empty)');
  if (edit && wrong) {
    wrong.focus({ preventScroll: true });
    wrong.scrollIntoView({ block: 'center' });
  } else if (edit && (filled || ((saved || edit.action === 'passkey_rename') && FLASH[edit.action]))) {
    const slot = filled ?? document.getElementById(edit.card)?.querySelector<HTMLElement>('[data-flash]');
    if (slot) {
      if (!filled) {
        const note = document.createElement('div');
        note.className = 'notice notice-success';
        note.textContent = FLASH[edit.action];
        if (LOST_KEYS.has(edit.action)) note.append(' Lost it? ', lostLink());
        slot.replaceChildren(note);
        saved?.remove();
      }
      slot.focus({ preventScroll: true });
      slot.scrollIntoView({ block: 'center' });
    }
  } else if (edit) {
    document.getElementById(edit.card)?.scrollIntoView({ block: 'start' });
  }
  if (matchMedia('(max-width: 640px)').matches) {
    document.querySelectorAll<HTMLDetailsElement>('details[data-open-narrow]').forEach((d) => { d.open = true; });
  }
};

document.addEventListener('submit', (e) => {
  const s = (e as SubmitEvent).submitter as HTMLButtonElement | null;
  remember(e.target, s?.dataset.flashKey ?? (s?.name ? flashKey(s.name, s.value) : ''));
}, true);
const write = async (text: string, btn: HTMLElement) => {
  const label = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied';
  } catch {
    btn.textContent = 'Press Cmd/Ctrl+C';
    const r = document.createRange();
    const src = btn.closest('.secret-row, .lookup-codes')?.querySelector('code');
    if (src) { r.selectNodeContents(src); getSelection()?.removeAllRanges(); getSelection()?.addRange(r); }
  }
  setTimeout(() => { btn.textContent = label; }, 1800);
};

document.addEventListener('click', (e) => {
  const el = e.target instanceof Element ? e.target : null;
  const open = el?.closest<HTMLAnchorElement>('a[data-open]');
  if (open) {
    const box = document.getElementById(open.dataset.open ?? '');
    if (box instanceof HTMLInputElement) {
      e.preventDefault();
      box.checked = true;
      box.closest('[data-card]')?.scrollIntoView({ block: 'center' });
      box.closest('form')?.querySelector<HTMLElement>('.panel-remove button')?.focus({ preventScroll: true });
    }
    return;
  }
  const copy = el?.closest<HTMLElement>('[data-copy]');
  if (copy) {
    e.preventDefault();
    void write((document.getElementById(copy.dataset.copy ?? '')?.textContent ?? '').replace(/\s+/g, ''), copy);
    return;
  }
  const copyCodes = el?.closest<HTMLElement>('[data-copy-codes]');
  if (copyCodes) {
    e.preventDefault();
    const codes = [...document.querySelectorAll('#lookup-codes li:not(.used) code')].map((c) => c.textContent ?? '');
    void write(codes.join('\n'), copyCodes);
    return;
  }
  if (el?.closest('[data-print-codes]')) {
    e.preventDefault();
    document.body.classList.add('printing-codes');
    addEventListener('afterprint', () => document.body.classList.remove('printing-codes'), { once: true });
    print();
    return;
  }

  const t = el?.closest<HTMLButtonElement>('button[onclick]') ?? null;
  if (t) remember(t, flashKey(t.name, t.value));
}, true);
// Opening a rename puts the cursor in the name, so typing starts at once.
document.addEventListener('change', (e) => {
  const t = e.target;
  if (t instanceof HTMLInputElement && t.classList.contains('cb-rename') && t.checked) {
    t.closest('li')?.querySelector<HTMLInputElement>('.panel-rename input[type="text"]')?.focus();
  }
});
document.addEventListener('astro:before-swap', (e) => {
  const ev = e as Event & { to: URL; swap: () => void };
  if (ev.to.pathname !== '/auth/settings') ev.swap = () => location.assign(ev.to.href);
});
document.addEventListener('astro:page-load', settle);
settle();
