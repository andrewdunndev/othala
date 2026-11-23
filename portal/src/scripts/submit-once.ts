// A code form leaves the page once per load. iOS code AutoFill submits the form itself and the person's tap is a second
// submit; the second POST would 303 somewhere else and the browser follows the last response. The button is left enabled
// so its name=value rides the one POST.

export function createSubmitOnce() {
  const sent = new WeakSet<object>();
  return {
    // True when the submit may proceed; the first one for a form is recorded.
    allow(form: object): boolean {
      if (sent.has(form)) return false;
      sent.add(form);
      return true;
    },
    // Back/forward cache restores the page with the form already marked: arm it again.
    rearm(form: object): void {
      sent.delete(form);
    },
  };
}

interface SubmitTarget {
  addEventListener(type: 'submit', h: (e: Event) => void, capture: boolean): void;
}

// Registered in the capture phase: the Astro router listens for submit on the document too and, finding the event
// not yet cancelled, posts the form itself. Running first lets this guard cancel the repeat before the router sees it.
export function guardSubmits(doc: SubmitTarget, once: ReturnType<typeof createSubmitOnce>, isGuarded: (form: unknown) => boolean): void {
  doc.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form || !isGuarded(form)) return;
    if (!once.allow(form)) e.preventDefault();
  }, true);
}
