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
  // Backup-code results belong to Recovery, wherever the button that asked for them sits.
  const card = action.startsWith('lookup_secret') ? 'recovery' : (cardOf(el)?.id ?? 'sign-in');
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

// An opened authenticator setup keeps its card and puts the person at step 1.
const focusStep = () => {
  const h = document.querySelector<HTMLElement>('#two-step .panel-setup h4');
  if (!h) return;
  h.focus({ preventScroll: true });
  (h.closest<HTMLElement>('.group') ?? h).scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
};

// Disclosures are checkbox-and-label so they work without script. With script each label becomes a real button
// (Enter and Space toggle it, assistive tech hears expanded or collapsed) and the checkbox leaves the tab order.
const syncExpanded = () => {
  document.querySelectorAll<HTMLButtonElement>('button[data-disclose]').forEach((b) => {
    const box = document.getElementById(b.dataset.disclose ?? '');
    if (!(box instanceof HTMLInputElement)) return;
    b.setAttribute('aria-expanded', String(box.checked));
    // The opener keeps the item's name ("Rename passkey Work laptop"); while open it names what it does instead.
    const name = b.dataset.itemName;
    const closeText = b.querySelector('.on-open')?.textContent;
    if (name) b.setAttribute('aria-label', box.checked && closeText ? `${closeText} ${name.charAt(0).toLowerCase()}${name.slice(1)}` : name);
  });
};
const enhanceDisclosures = () => {
  document.querySelectorAll<HTMLLabelElement>('label.toggle-label[for]').forEach((label) => {
    const box = document.getElementById(label.htmlFor);
    if (!(box instanceof HTMLInputElement)) return;
    const b = document.createElement('button');
    b.type = 'button';
    b.className = label.className;
    b.dataset.disclose = box.id;
    // The checkbox carried the item's name ("Remove passkey Work laptop"); the button now speaks for it.
    // Only the opener (lbl-*) speaks for the item; a Keep it button keeps its own text.
    const name = box.getAttribute('aria-label');
    if (name && /\blbl-/.test(label.className)) {
      b.dataset.itemName = name;
      b.setAttribute('aria-label', name);
    }
    const panel = box.parentElement?.querySelector<HTMLElement>(box.classList.contains('cb-rename') ? '.panel-rename' : box.classList.contains('cb-remove') ? '.panel-remove' : '.panel-setup');
    if (panel) {
      panel.id ||= `${box.id}-panel`;
      b.setAttribute('aria-controls', panel.id);
    }
    b.append(...label.childNodes);
    label.replaceWith(b);
    box.tabIndex = -1;
    box.setAttribute('aria-hidden', 'true');
  });
  syncExpanded();
};

const settle = () => {
  enhanceDisclosures();
  const edit = take();
  // A replaced app leaves the setup steps for the new one; open them where the person is looking.
  if (edit?.action === 'totp_replace') {
    const open = document.getElementById('totp-setup');
    if (open instanceof HTMLInputElement) {
      open.checked = true;
      syncExpanded();
      queueMicrotask(focusStep);
    }
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
      const codes = edit.action.startsWith('lookup_secret') ? document.getElementById('lookup-codes') : null;
      (codes ?? slot).scrollIntoView({ block: 'center' });
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
    (window as { announce?: (m: string) => void }).announce?.('Copied');
  } catch {
    btn.textContent = 'Press Cmd/Ctrl+C';
    (window as { announce?: (m: string) => void }).announce?.('Copy failed. Press Command or Control plus C to copy the selection.');
    const r = document.createRange();
    const src = btn.closest('.secret-row, .lookup-codes')?.querySelector('code');
    if (src) { r.selectNodeContents(src); getSelection()?.removeAllRanges(); getSelection()?.addRange(r); }
  }
  setTimeout(() => { btn.textContent = label; }, 1800);
};

document.addEventListener('click', (e) => {
  const el = e.target instanceof Element ? e.target : null;
  const toggle = el?.closest<HTMLButtonElement>('button[data-disclose]');
  if (toggle) {
    const box = document.getElementById(toggle.dataset.disclose ?? '');
    if (box instanceof HTMLInputElement) {
      box.checked = !box.checked;
      box.dispatchEvent(new Event('change', { bubbles: true }));
      syncExpanded();
    }
    return;
  }
  const hide = el?.closest<HTMLButtonElement>('button[data-hide-codes]');
  if (hide) {
    const grid = document.querySelector<HTMLElement>('#lookup-codes .lookup-grid');
    if (grid) {
      grid.hidden = !grid.hidden;
      hide.textContent = grid.hidden ? 'Show codes' : 'Hide codes';
      hide.setAttribute('aria-expanded', String(!grid.hidden));
      hide.parentElement?.querySelectorAll<HTMLElement>('[data-copy-codes], [data-print-codes]').forEach((b) => { b.hidden = grid.hidden; });
    }
    return;
  }
  const open = el?.closest<HTMLAnchorElement>('a[data-open]');
  if (open) {
    const box = document.getElementById(open.dataset.open ?? '');
    if (box instanceof HTMLInputElement) {
      e.preventDefault();
      box.checked = true;
      syncExpanded();
      box.closest('[data-card]')?.scrollIntoView({ block: 'center' });
      box.parentElement?.querySelector<HTMLElement>('.panel-remove button')?.focus({ preventScroll: true });
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
  if (t instanceof HTMLInputElement && t.id === 'totp-setup' && t.checked) focusStep();
});
// Enter in the new key's name starts adding that key: the add button is a script trigger, so without this the browser
// would submit the bare form.
document.addEventListener('keydown', (e) => {
  const t = e.target;
  if (e.key !== 'Enter' || !(t instanceof HTMLInputElement) || t.id !== 'webauthn-register-displayname') return;
  e.preventDefault();
  t.form?.querySelector<HTMLButtonElement>('button[name="webauthn_register_trigger"]')?.click();
});
document.addEventListener('astro:before-swap', (e) => {
  const ev = e as Event & { to: URL; swap: () => void };
  if (ev.to.pathname !== '/auth/settings') ev.swap = () => location.assign(ev.to.href);
});
document.addEventListener('astro:page-load', settle);
settle();
