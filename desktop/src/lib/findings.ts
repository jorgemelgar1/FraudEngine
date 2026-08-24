import { supabase } from './supabase';

// Columns + join the review UI needs. Mirrors api/findings.py:_LIST_SELECT so
// the desktop pages render the same fields as the Vercel ones. Keep this in
// sync if the Vercel select ever grows; otherwise the two clients silently
// disagree on what data is "available".
const LIST_SELECT = [
  'id',
  'run_id',
  'company_name',
  'company_id',
  'finding_type',
  'confidence',
  'risk_score',
  'fingerprints',
  'action_code',
  'section',
  'chargeback_exposure_usd',
  'chargeback_exposure_currency',
  'description_es',
  'review_status',
  'reviewed_at',
  'reviewed_by_email',
  'review_notes',
  'watchlist_delta',
  'payload',
  'analysis_runs(run_at,run_by_email,csv_filename,csv_date_start,csv_date_end)',
].join(',');

export type PendingFinding = {
  id: string;
  run_id: string;
  company_name: string;
  company_id: string | null;
  finding_type: string;
  confidence: 'Critical';
  risk_score: number;
  fingerprints: string[];
  action_code: string | null;
  // Which detector produced this finding (migration 0007):
  //   'exposure'        — chargeback-exposure model; carries an exposure amount.
  //   'zero_settlement' — card-testing detector; settles $0, so
  //                       chargeback_exposure_usd is always null.
  // Optional so rows written before 0007 (which have no section) still parse.
  section?: 'exposure' | 'zero_settlement';
  chargeback_exposure_usd: number | null;
  chargeback_exposure_currency: string | null;
  description_es: string | null;
  payload: Record<string, unknown>;
  analysis_runs: {
    run_at: string;
    run_by_email: string;
    csv_filename: string | null;
    csv_date_start: string | null;
    csv_date_end: string | null;
  } | null;
};

export type HistoryFinding = PendingFinding & {
  review_status: 'accepted' | 'rejected';
  reviewed_at: string;
  reviewed_by_email: string | null;
  review_notes: string | null;
  watchlist_delta: Record<string, unknown> | null;
};

export type ReviewResult = { id: string; ok: boolean; error?: string; result?: unknown };

export async function listPending(): Promise<PendingFinding[]> {
  const { data, error } = await supabase
    .from('findings_history')
    .select(LIST_SELECT)
    // Only Critical findings need review. Monitor findings are inserted as
    // not_applicable by analyze.py and never enter the pending queue.
    // Both sections are returned: the tier decides reviewability, not the
    // detector, so a Critical from the zero-settlement section queues up
    // alongside one from the exposure model.
    .eq('review_status', 'pending')
    .eq('confidence', 'Critical')
    .order('run_id', { ascending: false })
    .order('risk_score', { ascending: false })
    .limit(500);
  if (error) throw new Error(`listPending: ${error.message}`);
  return (data as unknown as PendingFinding[]) || [];
}

export async function listHistory(): Promise<HistoryFinding[]> {
  const { data, error } = await supabase
    .from('findings_history')
    .select(LIST_SELECT)
    .in('review_status', ['accepted', 'rejected'])
    .eq('confidence', 'Critical')
    .order('reviewed_at', { ascending: false })
    .limit(500);
  if (error) throw new Error(`listHistory: ${error.message}`);
  return (data as unknown as HistoryFinding[]) || [];
}

// Count of pending Critical findings — used by the header badge. Cheap because
// PostgREST supports an exact-count head request that doesn't return rows.
export async function pendingCount(): Promise<number> {
  const { count, error } = await supabase
    .from('findings_history')
    .select('id', { count: 'exact', head: true })
    .eq('review_status', 'pending')
    .eq('confidence', 'Critical');
  if (error) throw new Error(`pendingCount: ${error.message}`);
  return count ?? 0;
}

export async function reviewFindings(
  findingIds: string[],
  action: 'accept' | 'reject' | 'undo',
  userId: string,
  userEmail: string,
): Promise<ReviewResult[]> {
  // The RPC returns a jsonb array of per-id results. SECURITY DEFINER, so
  // we don't need service-role; the user's session JWT is enough.
  const { data, error } = await supabase.rpc('review_findings', {
    p_finding_ids: findingIds,
    p_action:      action,
    p_user_id:     userId,
    p_user_email:  userEmail,
  });
  if (error) throw new Error(`review_findings: ${error.message}`);
  return (data as unknown as ReviewResult[]) || [];
}
