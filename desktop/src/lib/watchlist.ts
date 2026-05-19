import { supabase } from './supabase';
import {
  getCachedWatchlist,
  setCachedWatchlist,
  isNetworkError,
} from './offline';

// Mirror of the dict shape analyze.py expects. Must match
// api/analyze.py:load_watchlist_from_supabase() in the Vercel function —
// any divergence and the desktop's findings will silently diverge from
// what the Vercel version produces.
export type WatchlistDict = {
  merchants: Record<string, {
    first_flagged: string;
    last_flagged: string;
    flag_count: number;
    company_id: string;
    last_risk_score: number;
  }>;
  cards: Record<string, {
    first_flagged: string;
    last_flagged: string;
    flag_count: number;
  }>;
};

// Pull both watchlist tables and shape them into the dict analyze.py wants.
// Without the explicit limit, PostgREST caps at 1000 rows by default, which
// would silently drop older watchlist entries once the lists grow past that.
// Same 100k limit the Vercel function uses.
export async function loadWatchlist(): Promise<WatchlistDict> {
  const [merchantsRes, cardsRes] = await Promise.all([
    supabase.from('watchlist_merchants').select('*').limit(100000),
    supabase.from('watchlist_cards').select('*').limit(100000),
  ]);

  if (merchantsRes.error) throw new Error(`watchlist_merchants: ${merchantsRes.error.message}`);
  if (cardsRes.error)     throw new Error(`watchlist_cards: ${cardsRes.error.message}`);

  const wl: WatchlistDict = { merchants: {}, cards: {} };

  for (const m of merchantsRes.data || []) {
    wl.merchants[m.company_name] = {
      first_flagged:   m.first_flagged,
      last_flagged:    m.last_flagged,
      flag_count:      m.flag_count ?? 1,
      company_id:      m.company_id ?? '',
      last_risk_score: m.last_risk_score ?? 0,
    };
  }
  for (const c of cardsRes.data || []) {
    // `card_key` is a generated column (bin || '-' || last4) in the table.
    wl.cards[c.card_key] = {
      first_flagged: c.first_flagged,
      last_flagged:  c.last_flagged,
      flag_count:    c.flag_count ?? 1,
    };
  }
  return wl;
}

// Network-tolerant variant used by the Analyzer page. Tries a fresh Supabase
// fetch first; on a network failure (offline, DNS down, etc.) falls back to
// the locally cached copy so analysis can still run. Non-network failures
// propagate so the user sees them — we don't want to mask a schema bug or
// an RLS misconfiguration by pretending we're offline.
//
// Returns the watchlist plus metadata the UI uses to render a "stale
// watchlist" warning when we're falling back to cache.
export async function loadWatchlistWithCache(): Promise<{
  watchlist: WatchlistDict;
  fromCache: boolean;
  cachedAt?: string;
}> {
  try {
    const fresh = await loadWatchlist();
    // Refresh the cache on every successful fetch. Cheap; keeps it in sync
    // with however the team updates the watchlist on Supabase.
    await setCachedWatchlist(fresh);
    return { watchlist: fresh, fromCache: false };
  } catch (e) {
    if (!isNetworkError(e)) throw e;
    const cache = await getCachedWatchlist();
    if (!cache) {
      throw new Error(
        'Sin conexión y no hay watchlist en caché local. ' +
        'Conéctate a internet al menos una vez para que se descargue.',
      );
    }
    return {
      watchlist: cache.data,
      fromCache: true,
      cachedAt: cache.fetchedAt,
    };
  }
}
