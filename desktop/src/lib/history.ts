import { supabase } from './supabase';
import type { PendingFinding, ReviewReason } from './findings';

// Everything the Historial screen reads: past analyses, their decisions, and
// the watchlist those decisions produce.
//
// The watchlist half exists because until now nothing could see it. Accepting
// a finding writes a merchant and its cards to tables migration 0001 calls
// permanent and never pruned, every analysis reads them, and no screen showed
// them — so the most durable consequence of an ops decision was the only one
// nobody could audit.

// ── Runs ─────────────────────────────────────────────────────────────────────

export type AnalysisRun = {
  id: string;
  run_at: string;
  run_by_email: string | null;
  source: string | null;
  csv_filename: string | null;
  csv_date_start: string | null;
  csv_date_end: string | null;
  total_rows: number | null;
  unique_transactions: number | null;
  critical_findings_count: number | null;
  monitor_findings_count: number | null;
  zero_settlement_findings_count: number | null;
  chargeback_exposure_usd: number | null;
  chargeback_exposure_currency: string | null;
  currency_source: string | null;
};

const RUN_SELECT = [
  'id', 'run_at', 'run_by_email', 'source', 'csv_filename',
  'csv_date_start', 'csv_date_end', 'total_rows', 'unique_transactions',
  'critical_findings_count', 'monitor_findings_count',
  'zero_settlement_findings_count', 'chargeback_exposure_usd',
  'chargeback_exposure_currency', 'currency_source',
].join(',');

export async function listRuns(limit = 40): Promise<AnalysisRun[]> {
  const { data, error } = await supabase
    .from('analysis_runs')
    .select(RUN_SELECT)
    .order('run_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error(`listRuns: ${error.message}`);
  return (data as unknown as AnalysisRun[]) || [];
}

/** Reviewed findings belonging to one run, worst first. */
export type DecidedFinding = PendingFinding & {
  review_status: string;
  review_reason?: string | null;
};

const DECIDED_SELECT = [
  'id', 'run_id', 'company_name', 'company_id', 'finding_type', 'confidence',
  'risk_score', 'fingerprints', 'action_code', 'section',
  'chargeback_exposure_usd', 'chargeback_exposure_currency', 'description_es',
  'review_status', 'review_reason', 'reviewed_at', 'reviewed_by_email',
  'review_notes', 'times_seen', 'first_seen_at', 'payload',
  'analysis_runs(run_at,run_by_email,csv_filename,csv_date_start,csv_date_end,source,currency_source)',
].join(',');

export async function listRunFindings(runId: string): Promise<DecidedFinding[]> {
  const { data, error } = await supabase
    .from('findings_history')
    .select(DECIDED_SELECT)
    .eq('run_id', runId)
    .order('confidence', { ascending: true })
    .order('risk_score', { ascending: false })
    .limit(300);
  if (error) throw new Error(`listRunFindings: ${error.message}`);
  return (data as unknown as DecidedFinding[]) || [];
}

/**
 * Everything ever found for one merchant, newest first.
 *
 * Matched on company_name because that is the identity the whole system uses —
 * `finding_key` is built from it, and the watchlist is keyed by it.
 */
export async function merchantHistory(companyName: string): Promise<DecidedFinding[]> {
  const { data, error } = await supabase
    .from('findings_history')
    .select(DECIDED_SELECT)
    .eq('company_name', companyName)
    .order('first_seen_at', { ascending: false })
    .limit(100);
  if (error) throw new Error(`merchantHistory: ${error.message}`);
  return (data as unknown as DecidedFinding[]) || [];
}

// ── Changing a decision ──────────────────────────────────────────────────────

/**
 * Overturn a decision after the 24-hour undo window, with a written reason.
 *
 * The explanation is required by the database, not just by this form: it
 * rewrites a record somebody else made, and the only useful moment to capture
 * why is now (migration 0014).
 */
export async function changeDecision(
  findingId: string,
  newStatus: 'accepted' | 'rejected',
  userId: string,
  userEmail: string,
  explanation: string,
  reason?: ReviewReason,
): Promise<void> {
  const { error } = await supabase.rpc('change_review_decision', {
    p_finding_id:  findingId,
    p_new_status:  newStatus,
    p_user_id:     userId,
    p_user_email:  userEmail,
    p_explanation: explanation,
    p_reason:      reason ?? null,
  });
  if (error) throw new Error(`change_review_decision: ${error.message}`);
}

// ── Watchlist ────────────────────────────────────────────────────────────────

export type WatchlistMerchant = {
  company_name: string;
  company_id: string | null;
  first_flagged: string;
  last_flagged: string;
  /** How many times a HUMAN accepted this merchant. The runner never bumps it. */
  flag_count: number;
  last_risk_score: number | null;
  notes: string | null;
  removed_at: string | null;
  removed_by: string | null;
  removed_reason: string | null;
};

export type WatchlistCard = {
  bin: string;
  last4: string;
  card_key: string;
  first_flagged: string;
  last_flagged: string;
  flag_count: number;
  removed_at: string | null;
  removed_by: string | null;
  removed_reason: string | null;
};

export type WatchlistIndicator = {
  id: string;
  indicator_type: string;
  value_raw: string;
  source: string | null;
  source_company_name: string | null;
  hit_count: number;
  last_hit_at: string | null;
  active: boolean;
};

export async function listWatchlistMerchants(
  { search = '', removed = false, limit = 300 } = {},
): Promise<WatchlistMerchant[]> {
  let q = supabase
    .from('watchlist_merchants')
    .select('company_name,company_id,first_flagged,last_flagged,flag_count,' +
            'last_risk_score,notes,removed_at,removed_by,removed_reason')
    .order('last_flagged', { ascending: false })
    .limit(limit);
  q = removed ? q.not('removed_at', 'is', null) : q.is('removed_at', null);
  if (search) q = q.ilike('company_name', `%${search}%`);
  const { data, error } = await q;
  if (error) throw new Error(`listWatchlistMerchants: ${error.message}`);
  return (data as unknown as WatchlistMerchant[]) || [];
}

export async function listWatchlistCards(
  { search = '', removed = false, limit = 300 } = {},
): Promise<WatchlistCard[]> {
  let q = supabase
    .from('watchlist_cards')
    .select('bin,last4,card_key,first_flagged,last_flagged,flag_count,' +
            'removed_at,removed_by,removed_reason')
    .order('last_flagged', { ascending: false })
    .limit(limit);
  q = removed ? q.not('removed_at', 'is', null) : q.is('removed_at', null);
  // card_key is `bin || '-' || last4`, so one filter covers "411111",
  // "1234" and "411111-1234" — an analyst pastes whichever they have.
  if (search) q = q.ilike('card_key', `%${search.replace(/\s+/g, '')}%`);
  const { data, error } = await q;
  if (error) throw new Error(`listWatchlistCards: ${error.message}`);
  return (data as unknown as WatchlistCard[]) || [];
}

export async function listWatchlistIndicators(
  { search = '', limit = 300 } = {},
): Promise<WatchlistIndicator[]> {
  let q = supabase
    .from('fraud_indicators')
    .select('id,indicator_type,value_raw,source,source_company_name,' +
            'hit_count,last_hit_at,active')
    .eq('active', true)
    .order('hit_count', { ascending: false })
    .limit(limit);
  if (search) q = q.ilike('value_raw', `%${search}%`);
  const { data, error } = await q;
  if (error) throw new Error(`listWatchlistIndicators: ${error.message}`);
  return (data as unknown as WatchlistIndicator[]) || [];
}

/**
 * Take a merchant off the watchlist, or put it back.
 *
 * Soft, always. The row is the evidence that justified freezing this merchant;
 * deleting it destroys the record for a decision someone may have to defend
 * later. Removal marks the row and the engine's three loaders stop matching
 * it — same operational outcome, nothing lost.
 */
export async function setMerchantRemoved(
  companyName: string, removed: boolean, userEmail: string, reason?: string,
): Promise<void> {
  const { error } = await supabase.rpc('set_watchlist_merchant_removed', {
    p_company_name: companyName,
    p_removed:      removed,
    p_user_email:   userEmail,
    p_reason:       reason ?? null,
  });
  if (error) throw new Error(`set_watchlist_merchant_removed: ${error.message}`);
}

export async function setCardRemoved(
  bin: string, last4: string, removed: boolean, userEmail: string, reason?: string,
): Promise<void> {
  const { error } = await supabase.rpc('set_watchlist_card_removed', {
    p_bin:        bin,
    p_last4:      last4,
    p_removed:    removed,
    p_user_email: userEmail,
    p_reason:     reason ?? null,
  });
  if (error) throw new Error(`set_watchlist_card_removed: ${error.message}`);
}
