import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, scanApi, type ScanResponse } from "../api";
import { saveCompletedScan } from "./useHistory";

const POLL_INTERVAL = 1_500;
const MAX_DURATION = 90_000;
const NETWORK_BACKOFF = [1_500, 3_000, 6_000] as const;
const inFlightScans = new Map<string, Promise<ScanResponse>>();

function getScanOnce(scanId: string): Promise<ScanResponse> {
  const existing = inFlightScans.get(scanId);
  if (existing) return existing;
  const request = scanApi.getScan(scanId).finally(() => inFlightScans.delete(scanId));
  inFlightScans.set(scanId, request);
  return request;
}

export function useScan(scanId: string) {
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const [backendSlow, setBackendSlow] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const generation = useRef(0);

  const retry = useCallback(() => {
    generation.current += 1;
    setError(null);
    setIsLoading(true);
    setBackendSlow(false);
    setAttempt((value) => value + 1);
  }, []);

  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
    let networkRetries = 0;
    const startedAt = Date.now();
    const currentGeneration = generation.current;
    const slowTimer = globalThis.setTimeout(() => {
      if (!disposed && !scan) setBackendSlow(true);
    }, 5_000);

    const schedule = (delay: number) => {
      if (disposed) return;
      globalThis.clearTimeout(timer);
      timer = globalThis.setTimeout(poll, delay);
    };

    const poll = async () => {
      if (disposed || currentGeneration !== generation.current) return;
      if (document.visibilityState === "hidden") return;
      if (Date.now() - startedAt >= MAX_DURATION) {
        setError(new ApiError(0, "TIMEOUT", "This scan is taking longer than expected. Please try again."));
        setIsPolling(false);
        setIsLoading(false);
        return;
      }
      setIsPolling(true);
      try {
        const next = await getScanOnce(scanId);
        if (disposed) return;
        globalThis.clearTimeout(slowTimer);
        setBackendSlow(false);
        setScan(next);
        setError(null);
        setIsLoading(false);
        networkRetries = 0;
        if (next.status === "completed") {
          saveCompletedScan(next);
          setIsPolling(false);
        } else if (next.status === "failed") {
          setIsPolling(false);
        } else {
          schedule(POLL_INTERVAL);
        }
      } catch (caught) {
        if (disposed) return;
        const apiError = caught instanceof ApiError ? caught : new ApiError(0, "NETWORK", "Cannot reach the SafeLinks server.");
        if (apiError.code === "NETWORK" && networkRetries < NETWORK_BACKOFF.length) {
          schedule(NETWORK_BACKOFF[networkRetries]);
          networkRetries += 1;
          return;
        }
        globalThis.clearTimeout(slowTimer);
        setError(apiError);
        setIsLoading(false);
        setIsPolling(false);
      }
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible" && !disposed) schedule(0);
      else globalThis.clearTimeout(timer);
    };
    document.addEventListener("visibilitychange", onVisibility);
    void poll();
    return () => {
      disposed = true;
      globalThis.clearTimeout(timer);
      globalThis.clearTimeout(slowTimer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  // attempt intentionally restarts a stopped polling session.
  }, [scanId, attempt]);

  return { scan, isLoading, error, isPolling, backendSlow, retry };
}
