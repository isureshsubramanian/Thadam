// The pieces every grid shares (ADR-014): a search box that asks the API, and the pager.
import { ChevronLeft, ChevronRight, ChevronsLeft, Search as SearchIcon, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { num } from "./format";
import { IconButton } from "./ui";
import type { Paged } from "./usePaged";

/** Wait after the last key before searching (ADR-014 Decision 3). */
const DEBOUNCE_MS = 300;

/**
 * A grid's search box. It reports the trimmed text once typing pauses; the grid asks the API
 * with it, so a match on any page is found, not just on the rows shown.
 */
export function GridSearch({ label, placeholder, onSearch }: { label: string; placeholder: string; onSearch: (text: string) => void }) {
  const [text, setText] = useState("");
  const report = useRef(onSearch);
  useEffect(() => { report.current = onSearch; }, [onSearch]);
  useEffect(() => {
    const t = setTimeout(() => { report.current(text.trim()); }, DEBOUNCE_MS);
    return () => { clearTimeout(t); };
  }, [text]);
  return (
    <div className="fieldwrap gridsearch">
      <SearchIcon className="ic" aria-hidden="true" />
      <input type="search" className="field compact" aria-label={label} placeholder={placeholder} value={text} maxLength={200}
        onChange={(e) => { setText(e.target.value); }} />
      {text !== "" && (
        <IconButton label="Clear search" onClick={() => { setText(""); }}>
          <X className="ic" aria-hidden="true" />
        </IconButton>
      )}
    </div>
  );
}

/** `‹ Prev · Rows 51–100 of 1,234 · Next ›` under a grid; hidden while the list is empty. */
export function Pager<T>({ page }: { page: Paged<T> }) {
  const shown = page.items?.length ?? 0;
  if (shown === 0 && page.index === 0) return null;
  const end = page.start + shown - 1;
  const of = page.total === null ? "" : ` of ${num(page.total)}${page.capped ? "+" : ""}`;
  return (
    <nav className="row pager" aria-label="Pages">
      <IconButton label="First page" onClick={() => { page.first?.(); }} disabled={page.first === undefined}>
        <ChevronsLeft className="ic" aria-hidden="true" />
      </IconButton>
      <button type="button" className="btn" disabled={page.prev === undefined} onClick={() => { page.prev?.(); }}>
        <ChevronLeft className="ic" aria-hidden="true" />Prev
      </button>
      <span className="muted small" aria-live="polite">Rows {num(page.start)}–{num(end)}{of}</span>
      <button type="button" className="btn" disabled={page.next === undefined} onClick={() => { page.next?.(); }}>
        Next<ChevronRight className="ic" aria-hidden="true" />
      </button>
    </nav>
  );
}
