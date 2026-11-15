import { useCallback, useSyncExternalStore } from "react";
import type { ScanResponse, Verdict } from "../api";

export interface HistoryEntry {
  scan_id: string;
  normalized_url: string;
  verdict: Verdict;
  risk_score: number;
  created_at: string;
}

const HISTORY_KEY = "safelinks:history:v1";
const CACHE_INDEX_KEY = "safelinks:report:index:v1";
const CACHE_PREFIX = "safelinks:report:";
let memoryHistory: HistoryEntry[] = [];
let memoryCacheIndex: string[] = [];
const memoryReports = new Map<string, ScanResponse>();
const listeners = new Set<() => void>();

function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : fallback;
  } catch {
    return fallback;
  }
}

function writeJson(key: string, value: unknown): boolean {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function removeStored(key: string) {
  try { localStorage.removeItem(key); } catch { /* in-memory fallback remains available */ }
}

let history = readJson<HistoryEntry[]>(HISTORY_KEY, memoryHistory);
memoryHistory = history;
let cacheIndex = readJson<string[]>(CACHE_INDEX_KEY, memoryCacheIndex);
memoryCacheIndex = cacheIndex;

function emit() { listeners.forEach((listener) => listener()); }
function subscribe(listener: () => void) { listeners.add(listener); return () => listeners.delete(listener); }
function snapshot() { return history; }

export function saveCompletedScan(scan: ScanResponse) {
  if (scan.status !== "completed" || !scan.result) return;
  const entry: HistoryEntry = {
    scan_id: scan.scan_id,
    normalized_url: scan.normalized_url,
    verdict: scan.result.verdict,
    risk_score: scan.result.risk_score,
    created_at: scan.created_at,
  };
  history = [entry, ...history.filter((item) => item.scan_id !== entry.scan_id)].slice(0, 50);
  memoryHistory = history;
  writeJson(HISTORY_KEY, history);

  memoryReports.set(scan.scan_id, scan);
  writeJson(`${CACHE_PREFIX}${scan.scan_id}`, scan);
  cacheIndex = [scan.scan_id, ...cacheIndex.filter((id) => id !== scan.scan_id)];
  const evicted = cacheIndex.slice(20);
  cacheIndex = cacheIndex.slice(0, 20);
  memoryCacheIndex = cacheIndex;
  writeJson(CACHE_INDEX_KEY, cacheIndex);
  evicted.forEach((id) => { memoryReports.delete(id); removeStored(`${CACHE_PREFIX}${id}`); });
  emit();
}

export function getCachedReport(scanId: string): ScanResponse | null {
  const memory = memoryReports.get(scanId);
  if (memory) return memory;
  const stored = readJson<ScanResponse | null>(`${CACHE_PREFIX}${scanId}`, null);
  if (stored) memoryReports.set(scanId, stored);
  return stored;
}

export function getHistoryEntry(scanId: string): HistoryEntry | undefined {
  return history.find((item) => item.scan_id === scanId);
}

export function useHistory() {
  const items = useSyncExternalStore(subscribe, snapshot, snapshot);
  const remove = useCallback((scanId: string) => {
    history = history.filter((item) => item.scan_id !== scanId);
    memoryHistory = history;
    writeJson(HISTORY_KEY, history);
    cacheIndex = cacheIndex.filter((id) => id !== scanId);
    memoryCacheIndex = cacheIndex;
    memoryReports.delete(scanId);
    writeJson(CACHE_INDEX_KEY, cacheIndex);
    removeStored(`${CACHE_PREFIX}${scanId}`);
    emit();
  }, []);
  const clear = useCallback(() => {
    history = [];
    memoryHistory = history;
    writeJson(HISTORY_KEY, history);
    cacheIndex.forEach((id) => removeStored(`${CACHE_PREFIX}${id}`));
    cacheIndex = [];
    memoryCacheIndex = cacheIndex;
    memoryReports.clear();
    writeJson(CACHE_INDEX_KEY, cacheIndex);
    emit();
  }, []);
  return { items, remove, clear, getById: getHistoryEntry };
}
