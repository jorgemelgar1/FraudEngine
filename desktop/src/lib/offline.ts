import { Store } from '@tauri-apps/plugin-store';
import type { WatchlistDict } from './watchlist';

// Two on-disk stores under %APPDATA%\com.cubopago.fraud-engine\ (Windows) or
// the OS-equivalent app-data path. The plugin handles JSON encoding,
// path resolution, and atomic writes for us.
//
// We use separate files (not one combined store) so a corrupt watchlist
// cache can't take out the sync queue, and vice versa.
const WATCHLIST_STORE = 'watchlist-cache.json';
const QUEUE_STORE     = 'sync-queue.json';

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

export type WatchlistCache = {
  data: WatchlistDict;
  fetchedAt: string; // ISO timestamp of the successful fetch
};

// One pending sync. Stored verbatim so a successful drain doesn't need any
// info beyond what's here. `attempts` tracks retries for non-network
// failures (e.g., RLS issue), so we can surface "this one keeps failing"
// instead of looping forever.
export type QueuedRun = {
  id: string;            // local UUID — not the eventual analysis_runs.id
  queuedAt: string;      // ISO timestamp
  csvFilename: string;
  userId: string;
  userEmail: string;
  // The findings JSON is exactly what sync.ts:syncFindings consumes, so
  // draining is a 1-line call.
  findings: unknown;
  attempts: number;
  lastError?: string;
};

// ─────────────────────────────────────────────────────────────────────────
// Watchlist cache
// ─────────────────────────────────────────────────────────────────────────

export async function getCachedWatchlist(): Promise<WatchlistCache | null> {
  const store = await Store.load(WATCHLIST_STORE);
  const cache = await store.get<WatchlistCache>('cache');
  return cache ?? null;
}

export async function setCachedWatchlist(data: WatchlistDict): Promise<void> {
  const store = await Store.load(WATCHLIST_STORE);
  await store.set('cache', { data, fetchedAt: new Date().toISOString() } satisfies WatchlistCache);
  await store.save();
}

// ─────────────────────────────────────────────────────────────────────────
// Sync queue
// ─────────────────────────────────────────────────────────────────────────

async function readQueue(): Promise<QueuedRun[]> {
  const store = await Store.load(QUEUE_STORE);
  return (await store.get<QueuedRun[]>('queue')) ?? [];
}

async function writeQueue(items: QueuedRun[]): Promise<void> {
  const store = await Store.load(QUEUE_STORE);
  await store.set('queue', items);
  await store.save();
}

export async function getSyncQueue(): Promise<QueuedRun[]> {
  return readQueue();
}

export async function enqueueSync(
  item: Omit<QueuedRun, 'id' | 'queuedAt' | 'attempts'>,
): Promise<QueuedRun> {
  const queue = await readQueue();
  const queued: QueuedRun = {
    ...item,
    id: crypto.randomUUID(),
    queuedAt: new Date().toISOString(),
    attempts: 0,
  };
  queue.push(queued);
  await writeQueue(queue);
  return queued;
}

export async function removeFromQueue(id: string): Promise<void> {
  const queue = await readQueue();
  await writeQueue(queue.filter((q) => q.id !== id));
}

export async function updateQueueItem(id: string, patch: Partial<QueuedRun>): Promise<void> {
  const queue = await readQueue();
  await writeQueue(queue.map((q) => (q.id === id ? { ...q, ...patch } : q)));
}

// ─────────────────────────────────────────────────────────────────────────
// Network error classification
// ─────────────────────────────────────────────────────────────────────────

// We treat ANY of these signals as "network down — retry later":
//   - navigator.onLine === false (browser-level offline event)
//   - "Failed to fetch" / "NetworkError" / "fetch failed" in the message
//   - The standard DOMException name 'AbortError' from a timed-out request
//
// Anything else is treated as a real error and propagates to the UI rather
// than getting queued indefinitely. Schema bugs / RLS misses / 4xx auth
// errors shouldn't pile up in the queue forever.
export function isNetworkError(error: unknown): boolean {
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return true;
  if (!error) return false;
  const msg = (error instanceof Error ? error.message : String(error)).toLowerCase();
  return (
    msg.includes('failed to fetch') ||
    msg.includes('fetch failed') ||
    msg.includes('networkerror') ||
    msg.includes('network request failed') ||
    msg.includes('typeerror: load failed') ||
    msg.includes('err_internet_disconnected') ||
    msg.includes('err_network_changed') ||
    msg.includes('aborterror')
  );
}
