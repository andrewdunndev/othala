// The letters on an app's plate when it has no logo: the first letter of up to two words ("New app" is NA, "Grafana" is
// G), never the first two letters of one long name.

export function monogram(name: string): string {
  const words = name.split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words.slice(0, 2).map((w) => w[0]).join('') : (words[0] ?? '?').slice(0, 1);
  return letters.toUpperCase();
}
