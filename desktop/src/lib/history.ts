// The Historial screen's data layer, bound to the desktop's Supabase client.
//
// The queries themselves live in shared/history.ts so the web app runs exactly
// the same ones. They used to live here, which is why the browser had no
// watchlist screen at all: the code to read it existed, in a folder the web
// app is forbidden to import from (.vercelignore excludes desktop/).
//
// Only the client differs — the desktop holds a long-lived singleton, the
// browser builds one per session from the user's token — so that is the only
// thing this file supplies. Every function below is the shared one with the
// client already applied, which keeps every existing call site in the pages
// unchanged.

import { supabase } from './supabase';
import type { ReviewReason } from './findings';
import * as shared from '@shared/history';

export type {
  AnalysisRun, DecidedFinding, WatchlistMerchant, WatchlistCard,
  WatchlistIndicator,
} from '@shared/history';

export const listRuns = (limit = 40) =>
  shared.listRuns(supabase, limit);

export const listRunFindings = (runId: string) =>
  shared.listRunFindings(supabase, runId);

export const merchantHistory = (companyName: string) =>
  shared.merchantHistory(supabase, companyName);

export const changeDecision = (
  findingId: string,
  newStatus: 'accepted' | 'rejected',
  userId: string,
  userEmail: string,
  explanation: string,
  reason?: ReviewReason,
) => shared.changeDecision(
  supabase, findingId, newStatus, userId, userEmail, explanation, reason,
);

export const listWatchlistMerchants = (
  opts: { search?: string; removed?: boolean; limit?: number } = {},
) => shared.listWatchlistMerchants(supabase, opts);

export const listWatchlistCards = (
  opts: { search?: string; removed?: boolean; limit?: number } = {},
) => shared.listWatchlistCards(supabase, opts);

export const listWatchlistIndicators = (
  opts: { search?: string; limit?: number } = {},
) => shared.listWatchlistIndicators(supabase, opts);

export const setMerchantRemoved = (
  companyName: string, removed: boolean, userEmail: string, reason?: string,
) => shared.setMerchantRemoved(supabase, companyName, removed, userEmail, reason);

export const setCardRemoved = (
  bin: string, last4: string, removed: boolean, userEmail: string, reason?: string,
) => shared.setCardRemoved(supabase, bin, last4, removed, userEmail, reason);
