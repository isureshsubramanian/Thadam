// Keyset paging with Prev and Next (ADR-014 Decision 2). The API pages by `after` = the
// previous page's `next`; this keeps the stack of `after` values that led to the current page, so
// Prev, Next and First are each one request, as fast on page 500 as on page 1.
import { useEffect, useState } from "react";
import { useApi } from "./useApi";

/** Rows a page holds: the API's default (ADR-014 Decision 1). */
export const PAGE_SIZE = 50;

export interface PageOf<T> {
  items: T[];
  next: number | null;
  /** Rows across all pages; sent with the first page (null on later pages of some lists). */
  total?: number | null | undefined;
  /** More rows matched than one request examines: `total` is a lower bound. */
  totalCapped?: boolean | undefined;
}

export interface Paged<T> {
  items: T[] | undefined;
  loading: boolean;
  /** Zero-based page number. */
  index: number;
  /** One-based number of the page's first row. */
  start: number;
  total: number | null;
  capped: boolean;
  prev: (() => void) | undefined;
  next: (() => void) | undefined;
  first: (() => void) | undefined;
  reload: () => void;
}

export function usePaged<T>(
  load: (after: number | null, signal?: AbortSignal) => Promise<PageOf<T>>,
  deps: readonly unknown[],
): Paged<T> {
  const key = JSON.stringify(deps);
  const [stack, setStack] = useState<{ key: string; afters: (number | null)[] }>({ key, afters: [null] });
  const [counted, setCounted] = useState<{ key: string; total: number | null; capped: boolean }>();
  // A change of list (filter, range, tab) starts again at page 1.
  const afters = stack.key === key ? stack.afters : [null];
  const after = afters.at(-1) ?? null;
  // Forwards the caller's deps, which the lint checks at each usePaged call instead.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const page = useApi((signal) => load(after, signal), [...deps, after]);

  const data = page.loading ? undefined : page.data;
  useEffect(() => {
    if (afters.length === 1 && data?.total !== undefined && data.total !== null) {
      setCounted({ key, total: data.total, capped: data.totalCapped ?? false });
    }
  }, [data, key, afters.length]);

  const index = afters.length - 1;
  const nextAfter = data?.next ?? null;
  const total = counted?.key === key ? counted : undefined;
  return {
    // The last page stays on screen while the next one loads, so the grid does not flash.
    items: page.data?.items,
    loading: page.loading,
    index,
    start: index * PAGE_SIZE + 1,
    total: total?.total ?? null,
    capped: total?.capped ?? false,
    prev: index > 0 && !page.loading ? () => { setStack({ key, afters: afters.slice(0, -1) }); } : undefined,
    next: nextAfter === null || page.loading ? undefined : () => { setStack({ key, afters: [...afters, nextAfter] }); },
    first: index > 0 && !page.loading ? () => { setStack({ key, afters: [null] }); } : undefined,
    reload: page.reload,
  };
}
