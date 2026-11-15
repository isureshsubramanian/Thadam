// Shows where a search matched: the free-text terms of a query, marked in a row's text.
// Matching is case-insensitive and by substring, as the API's free text is. Text stays text;
// a match is wrapped in <mark>, never turned into markup (ADR-008 Decision 3).
import type { ReactNode } from "react";

/**
 * The free-text terms of a query in the Search page's syntax: bare words and "quoted phrases".
 * `field:value` terms (tool:, outcome:, since:, ...) filter rows rather than match text, so they
 * are left out.
 */
export function freeTerms(q: string): string[] {
  const terms: string[] = [];
  const re = /(\S*?:)?("([^"]*)"|\S+)/g;
  for (let m = re.exec(q); m !== null; m = re.exec(q)) {
    if (m[1] !== undefined && /^[a-z]+:$/i.test(m[1])) continue;
    const term = (m[3] ?? m[0]).trim();
    if (term !== "" && !terms.some((t) => t.toLowerCase() === term.toLowerCase())) terms.push(term);
  }
  return terms;
}

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** True when any term occurs in the text. */
export function matches(text: string, terms: readonly string[]): boolean {
  const lower = text.toLowerCase();
  return terms.some((t) => lower.includes(t.toLowerCase()));
}

/** The text with every occurrence of a term in <mark>; longer terms win where two overlap. */
export function Highlight({ text, terms }: { text: string; terms: readonly string[] }): ReactNode {
  if (terms.length === 0 || text === "") return text;
  const sorted = [...terms].sort((a, b) => b.length - a.length).map(escape);
  const parts = text.split(new RegExp(`(${sorted.join("|")})`, "gi"));
  // split() with one capture group puts the matches at the odd indexes.
  return parts.map((p, i) => (i % 2 === 1 ? <mark key={i}>{p}</mark> : p));
}
