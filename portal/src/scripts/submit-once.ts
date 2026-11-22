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
