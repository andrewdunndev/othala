// Progressive enhancement over the native forms (see Layout's `router`): after a post swaps the page, scroll returns
// to the card that was edited; a response that is not this page (a re-sign-in) navigates for real. The passkey and
// security-key ceremonies end in the script's own form.submit(), a native navigation, so they take the same restore.
const KEY = 'othala:settings-card';
const cardOf = (el: EventTarget | null) => (el instanceof Element ? el.closest<HTMLElement>('[data-card]') : null);
const remember = (el: EventTarget | null) => {
  const id = cardOf(el)?.id;
  if (!id) return;
  try { sessionStorage.setItem(KEY, id); } catch { /* storage unavailable */ }
};
const restore = () => {
  let id: string | null = null;
  try { id = sessionStorage.getItem(KEY); sessionStorage.removeItem(KEY); } catch { /* storage unavailable */ }
  if (id) document.getElementById(id)?.scrollIntoView({ block: 'start' });
};
document.addEventListener('submit', (e) => remember(e.target), true);
document.addEventListener('click', (e) => {
  const t = e.target instanceof Element ? e.target.closest('button[onclick]') : null;
  if (t) remember(t);
}, true);
document.addEventListener('astro:before-swap', (e) => {
  const ev = e as Event & { to: URL; swap: () => void };
  if (ev.to.pathname !== '/auth/settings') ev.swap = () => location.assign(ev.to.href);
});
document.addEventListener('astro:page-load', restore);
restore();
