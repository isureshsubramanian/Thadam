// Keyset paging (ADR-008 Decision 4): the first page through useApi, later pages appended
// on "Load more" with `after` = the previous page's `next`.
import { useState } from "react";
import { SignedOut } from "../api/client";
import { useSignedOut } from "./session";
import { useApi } from "./useApi";

export interface PageOf<T> {
  items: T[];
  next: number | null;
}

export interface Paged<T> {
  items: T[] | undefined;
  loading: boolean;
  more: (() => void) | undefined;
  reload: () => void;
}

export function usePaged<T>(
  load: (after: number | null, signal?: AbortSignal) => Promise<PageOf<T>>,
  deps: readonly unknown[],
): Paged<T> {
  const signedOut = useSignedOut();
  const [extra, setExtra] = useState<{ key: string; items: T[]; next: number | null }>();
  const [error, setError] = useState<Error>();
  const key = JSON.stringify(deps);
  const first = useApi((signal) => load(null, signal), deps);
  if (error !== undefined) throw error;

  const mine = extra?.key === key ? extra : undefined;
  const next = mine ? mine.next : (first.data?.next ?? null);
  const items = first.data ? [...first.data.items, ...(mine?.items ?? [])] : undefined;
  const more =
    next === null
      ? undefined
      : () => {
          load(next).then(
            (p) => { setExtra({ key, items: [...(mine?.items ?? []), ...p.items], next: p.next }); },
            (e: unknown) => { if (e instanceof SignedOut) signedOut(); else setError(e instanceof Error ? e : new Error("request failed")); },
          );
        };
  return {
    items,
    loading: first.loading,
    more,
    reload: () => { setExtra(undefined); first.reload(); },
  };
}
