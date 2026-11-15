// Loads one API call for a view. Failures other than sign-out are rethrown during render,
// so the view's Error Boundary shows its fallback (ADR-008 acceptance test 9).
import { useCallback, useEffect, useRef, useState } from "react";
import { SignedOut } from "../api/client";
import { useSignedOut } from "./session";

export interface Loaded<T> {
  data: T | undefined;
  loading: boolean;
  reload: () => void;
}

/**
 * Calls `load` again whenever a value in `deps` changes. The lint checks each caller's `deps`
 * against what its `load` uses (`additionalHooks` in eslint.config.js); the values are plain
 * (text, numbers, null), so they are compared as one key.
 */
export function useApi<T>(load: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[]): Loaded<T> {
  const signedOut = useSignedOut();
  const key = JSON.stringify(deps);
  // The latest `load`, which closes over the current `deps`; set before the load effect runs.
  const latest = useRef(load);
  useEffect(() => { latest.current = load; });
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => { setTick((t) => t + 1); }, []);

  useEffect(() => {
    const ctl = new AbortController();
    setLoading(true);
    latest.current(ctl.signal).then(
      (d) => {
        setData(d);
        setLoading(false);
      },
      (e: unknown) => {
        if (ctl.signal.aborted) return;
        if (e instanceof SignedOut) signedOut();
        else setError(e instanceof Error ? e : new Error("request failed"));
        setLoading(false);
      },
    );
    return () => { ctl.abort(); };
  }, [key, tick, signedOut]);

  if (error !== undefined) throw error;
  return { data, loading, reload };
}
