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
  // Migrations 0010/0011. Until now these were stored, correct, and read by
  // nothing: a merchant seen once may be noise, one seen on sixteen
  // consecutive runs is not, and that is the reviewer's cheapest way to
  // prioritise.
  'times_seen',
  'first_seen_at',
  'payload',
  // `source` distinguishes the runner's own analyses from someone's manual
  // upload (migration 0010). The runner's email already hints at it, but the
  // column is what actually records it — an upload made from that address
  // would otherwise be mislabelled.
  // `currency_source` is the normalized country_name the CSV itself declared —
  // the only place a finding's country reaches storage. Ops is split by
  // country, so the queue has to be able to say which one this is.
  'analysis_runs(run_at,run_by_email,csv_filename,csv_date_start,csv_date_end,source,currency_source)',
].join(',');

// Normalized country name (what analyze.py stores) -> the code ops uses.
// Mirrors runner/config.py:COUNTRIES; an unmapped country returns null rather
// than a guess, exactly as the currency logic does.
const COUNTRY_CODES: Record<string, string> = {
  'panama': 'PA',
  'el salvador': 'SV',
  'guatemala': 'GT',
};

export function countryCodeOf(currencySource: string | null | undefined): string | null {
  if (!currencySource) return null;
  return COUNTRY_CODES[currencySource.trim().toLowerCase()] || null;
}

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

  // How many runs have detected this, and since when (migrations 0010/0011).
  times_seen?: number | null;
  first_seen_at?: string | null;

  // Present on a PENDING finding only when the runner re-opened a previous
  // rejection: reopen_finding keeps them, while a human Undo clears them to
  // null. So `reviewed_at != null` on a pending row means exactly one thing —
  // this was dismissed once and came back. See reopenInfo() below.
  reviewed_at?: string | null;
  reviewed_by_email?: string | null;
  review_notes?: string | null;

  analysis_runs: {
    run_at: string;
    run_by_email: string;
    csv_filename: string | null;
    csv_date_start: string | null;
    csv_date_end: string | null;
    // 'auto' = the scheduled runner, 'manual' = someone uploaded a CSV.
    // Optional: rows written before migration 0010 have no value.
    source?: string | null;
    currency_source?: string | null;
  } | null;
};

export type ReopenInfo = {
  rejectedAt: string;
  rejectedBy: string | null;
  reason: string | null;
};

// Pulls the most recent automatic re-opening out of review_notes.
//
// reopen_finding APPENDS with ' | ', so a finding re-opened twice carries both
// entries and the last one is the current story. A human Undo overwrites the
// column instead — but it also clears reviewed_at, so those rows never reach
// here.
// Anchored on "UTC:" rather than on the first colon, because the timestamp
// migration 0010 writes is `YYYY-MM-DD HH24:MI` — it CONTAINS a colon. Cutting
// at the first one turned "…14:00 UTC: el puntaje subió de 45 a 90" into a
// reason that read "00 UTC: el puntaje subió de 45 a 90".
// tests/test_reopen_note_contract.py pins this against the SQL.
const REOPEN_RE = /^Reabierto autom[áa]ticamente .*?UTC:\s*(.+)$/;

// The note ends with "(puntaje anterior 45, ahora 90)", which just restates
// what the sentence before it already said. Dropped: the current score is on
// the row anyway.
const TRAILING_SCORES = /\s*\(puntaje anterior[^)]*\)\s*$/;

export function reopenInfo(f: PendingFinding): ReopenInfo | null {
  if (!f.reviewed_at) return null;
  let reason: string | null = null;
  for (const part of (f.review_notes || '').split(' | ').reverse()) {
    const m = part.trim().match(REOPEN_RE);
    if (m) {
      reason = m[1].replace(TRAILING_SCORES, '').trim();
      break;
    }
  }
  return {
    rejectedAt: f.reviewed_at,
    rejectedBy: f.reviewed_by_email || null,
    reason,
  };
}

export type HistoryFinding = PendingFinding & {
  review_status: 'accepted' | 'rejected';
  reviewed_at: string;
  reviewed_by_email: string | null;
  review_notes: string | null;
  watchlist_delta: Record<string, unknown> | null;
};

export type ReviewResult = { id: string; ok: boolean; error?: string; result?: unknown };

// Why a Critical finding was dismissed. Must match the check constraint in
// migration 0013 — a value outside this list is rejected by the database.
//
// Five options on purpose. Long taxonomies get answered with whichever item is
// first, which is worse than no taxonomy at all. `error_detector` is the one
// that earns its place: it separates "the engine was wrong" from "the engine
// was right and we are fine with this merchant", and only the first of those
// should ever move a threshold.
export const REVIEW_REASONS = [
  { value: 'cliente_conocido', label: 'Cliente conocido' },
  { value: 'campana_legitima', label: 'Campaña legítima' },
  { value: 'prueba_interna',   label: 'Prueba interna' },
  { value: 'error_detector',   label: 'Error del detector' },
  { value: 'ya_gestionado',    label: 'Ya gestionado' },
] as const;

export type ReviewReason = typeof REVIEW_REASONS[number]['value'];

export const REASON_LABELS: Record<string, string> =
  Object.fromEntries(REVIEW_REASONS.map(r => [r.value, r.label]));

export const PENDING_LIMIT = 500;

export type PendingPage = {
  rows: PendingFinding[];
  /** Total pending, ignoring the limit. Larger than rows.length = truncated. */
  total: number;
};

export async function listPending(): Promise<PendingPage> {
  const { data, error, count } = await supabase
    .from('findings_history')
    .select(LIST_SELECT, { count: 'exact' })
    // Only Critical findings need review. Monitor findings are inserted as
    // not_applicable by analyze.py and never enter the pending queue.
    // Both sections are returned: the tier decides reviewability, not the
    // detector, so a Critical from the zero-settlement section queues up
    // alongside one from the exposure model.
    .eq('review_status', 'pending')
    .eq('confidence', 'Critical')
    // Was `run_id desc`, which is a random v4 UUID — an arbitrary order. That
    // was invisible while the page re-sorted groups by date afterwards, but
    // the limit is applied BEFORE any of that: past 500 pending it would have
    // returned an arbitrary 500 while the header badge counted them all.
    // Ordering by score means a truncated list keeps the ones that matter.
    .order('risk_score', { ascending: false })
    .order('id', { ascending: false })
    .limit(PENDING_LIMIT);
  if (error) throw new Error(`listPending: ${error.message}`);
  return {
    rows: (data as unknown as PendingFinding[]) || [],
    total: count ?? (data?.length ?? 0),
  };
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
  reason?: ReviewReason,
  note?: string,
): Promise<ReviewResult[]> {
  // The RPC returns a jsonb array of per-id results. SECURITY DEFINER, so
  // we don't need service-role; the user's session JWT is enough.
  //
  // `p_reason` / `p_note` only apply to 'reject' and default to null in SQL,
  // so they are omitted entirely rather than sent as nulls — that keeps this
  // call identical to the pre-0013 one for accept and undo.
  const body: Record<string, unknown> = {
    p_finding_ids: findingIds,
    p_action:      action,
    p_user_id:     userId,
    p_user_email:  userEmail,
  };
  if (action === 'reject') {
    if (reason) body.p_reason = reason;
    if (note) body.p_note = note;
  }
  const { data, error } = await supabase.rpc('review_findings', body);
  if (error) throw new Error(`review_findings: ${error.message}`);
  return (data as unknown as ReviewResult[]) || [];
}

export type ReviewStats = {
  decided: number;
  confirmed: number;
  dismissed: number;
  /** Percent of decided Critical findings that were real. Null if none yet. */
  precision: number | null;
  by_reason: Record<string, number>;
  pending: number;
};

/**
 * How often the engine is right, and what it gets wrong.
 *
 * Computed server-side (migration 0013) so both clients and anyone querying by
 * hand get the same arithmetic. Counts only findings a human actually decided
 * — pending ones are not evidence either way, and including them would make
 * the engine look worse every time the queue grew.
 */
export async function reviewStats(since?: Date): Promise<ReviewStats | null> {
  const { data, error } = await supabase.rpc('review_stats', {
    p_since: since ? since.toISOString() : null,
  });
  if (error) throw new Error(`review_stats: ${error.message}`);
  return (data as unknown as ReviewStats) || null;
}
