/**
 * - gate:   only eligible callers reach the origin; everyone else gets 403.
 * - triage: everyone reaches the origin, which reads X-AIR-Viewer and decides what to serve.
 * - off:    no check; forwarded as-is (spoofed X-AIR-* headers are still removed).
 */
export type Mode = "gate" | "triage" | "off";
/** `path` is exact ("/pricing") or a prefix ending in "*" ("/members/*"). */
export type Rule = { path: string; mode: Mode };

/** First matching rule wins. Unmatched paths are "off". */
export function modeFor(rules: Rule[], pathname: string): Mode {
  const rule = rules.find(({ path }) => (path.endsWith("*") ? pathname.startsWith(path.slice(0, -1)) : pathname === path));
  return rule?.mode ?? "off";
}
