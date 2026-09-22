import { useCallback, useEffect, useRef, useState } from "react";

// Minimal data-fetching hook with reload + optional polling.
export function useFetch(fn, deps = [], { pollMs = 0 } = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const d = await fnRef.current();
      setData(d);
      setError(null);
      return d;
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    run();
    if (pollMs > 0) {
      const t = setInterval(() => run(true), pollMs);
      return () => clearInterval(t);
    }
  }, [run, pollMs]);

  return { data, loading, error, reload: run };
}
