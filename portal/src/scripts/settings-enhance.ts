// Progressive enhancement over the native forms (see Layout's `router`). Native posts work without this file; with it,
// a post swaps the page in place and, once swapped, the script puts the person where the answer is:
//   - a refused code (aria-invalid) takes focus and scrolls to the field, so the error is announced and in view;
//   - a saved change writes a one-line confirmation, in house voice for the action taken, into the card that was edited
//     and focuses it (Kratos only says "saved", so the action is remembered from the submit);
//   - anything else scrolls back to the card that was edited.
// The passkey and security-key ceremonies end in the script's own form.submit(), a native navigation, so they take the
// same path. A response that is not this page (a re-sign-in) navigates for real.
import { FLASH, flashKey } from '../lib/settings-flash';

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

const settle = () => {
  const edit = take();
  const wrong = document.querySelector<HTMLElement>('[aria-invalid="true"]');
  const saved = document.querySelector<HTMLElement>('[data-flow-success]');
  // A card the server already filled (the dev fixtures render the saved line themselves).
  const filled = document.querySelector<HTMLElement>('[data-flash]:not(:empty)');
  if (edit && wrong) {
    wrong.focus({ preventScroll: true });
    wrong.scrollIntoView({ block: 'center' });
  } else if (edit && (filled || (saved && FLASH[edit.action]))) {
    const slot = filled ?? document.getElementById(edit.card)?.querySelector<HTMLElement>('[data-flash]');
    if (slot) {
      if (!filled && saved) {
        const note = document.createElement('div');
        note.className = 'notice notice-success';
        note.textContent = FLASH[edit.action];
        slot.replaceChildren(note);
        saved.remove();
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
  remember(e.target, s?.name ? flashKey(s.name, s.value) : '');
}, true);
document.addEventListener('click', (e) => {
  const t = e.target instanceof Element ? e.target.closest<HTMLButtonElement>('button[onclick]') : null;
  if (t) remember(t, flashKey(t.name, t.value));
}, true);
document.addEventListener('astro:before-swap', (e) => {
  const ev = e as Event & { to: URL; swap: () => void };
  if (ev.to.pathname !== '/auth/settings') ev.swap = () => location.assign(ev.to.href);
});
document.addEventListener('astro:page-load', settle);
settle();
