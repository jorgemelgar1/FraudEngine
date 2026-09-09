import { supabase } from './supabase';

// Everything the Runner screen reads.
//
// The distinction this module exists to preserve: a CYCLE is the runner waking
// up and trying; a RUN is an analysis that happened. Every successful cycle
// has exactly one run; a failed cycle has none. `analysis_runs` alone
// therefore cannot show a failure — which is why a list built on it is
// precisely the list that hides them (migration 0012).

// ── Constants mirrored from the runner ───────────────────────────────────────
// These four values are defined in Python and repeated here. There is no
// shared config between a Raspberry Pi cron job and a Tauri app, so the
// duplication is real; tests/test_runner_ui_contract.py reads this file and
// fails if any of them drifts from its Python original.

/** Mirrors runner/config.py:ROTATION — one country per hour, rotating. */
export const ROTATION = ['SV', 'PA', 'GT'];

/** Hours between two slots for the same country. Mirrors len(ROTATION). */
export const SLOT_HOURS = ROTATION.length;

/**
 * Mirrors runner/state.py:STALE_AFTER (12 hours).
 *
 * Overlapping analysis windows mean no single missed slot loses data, so this
 * is deliberately several slots wide rather than one: alerting on a single
 * miss would cry wolf about something the design already absorbs.
 */
export const STALE_AFTER_HOURS = 12;

/** Mirrors runner/cycle.py:TOKEN_WARN_DAYS. */
export const TOKEN_WARN_DAYS = 7;

/** Mirrors runner/config.py:COUNTRIES. */
export const COUNTRY_NAMES: Record<string, string> = {
  SV: 'El Salvador',
  PA: 'Panamá',
  GT: 'Guatemala',
};

// ── Types ────────────────────────────────────────────────────────────────────

export type CycleOutcome =
  | 'running'
  | 'ok'
  | 'no_email'
  | 'cms_error'
  | 'token_error'
  | 'gmail_error'
  | 'supabase_error'
  | 'config_error'
  | 'unexpected';

/** The subset of analysis_runs the cycle list embeds through run_id. */
export type CycleRun = {
  run_at: string;
  run_by_email: string | null;
  csv_filename: string | null;
  csv_date_start: string | null;
  csv_date_end: string | null;
  total_rows: number | null;
  unique_transactions: number | null;
  // Recorded at run time and never rewritten. The expanded panel's live
  // finding list can legitimately disagree with these — see the note on
  // listRunFindings.
  critical_findings_count: number | null;
  monitor_findings_count: number | null;
  zero_settlement_findings_count: number | null;
  chargeback_exposure_usd: number | null;
  chargeback_exposure_currency: string | null;
  // The country the CSV itself declared. Worth comparing against the cycle's
  // country_code: they are derived independently, so a mismatch is a real
  // signal and not a tautology.
  currency_source: string | null;
  source: string | null;
};

export type RunnerCycle = {
  id: string;
  started_at: string;
  finished_at: string | null;
  country_code: string;
  outcome: CycleOutcome;
  detail: string | null;
  run_id: string | null;
  window_start: string | null;
  window_end: string | null;
  token_expires_at: string | null;
  host: string | null;
  analysis_runs: CycleRun | null;
};

export type CountryHealth = {
  country_code: string;
  last_success_at: string | null;
  last_success_run_id: string | null;
  last_cycle_at: string | null;
  last_outcome: CycleOutcome | null;
  last_detail: string | null;
  consecutive_failures: number;
  cycles_24h: number;
  ok_24h: number;
  token_expires_at: string | null;
};

/** A finding as the Runner screen shows it: read-only, with sighting counts. */
export type RunFinding = {
  id: string;
  company_name: string;
  finding_type: string;
  confidence: string;
  risk_score: number;
  fingerprints: string[];
  section?: 'exposure' | 'zero_settlement';
  chargeback_exposure_usd: number | null;
  chargeback_exposure_currency: string | null;
  description_es: string | null;
  review_status: string;
  reviewed_by_email: string | null;
  // Migration 0010/0011. Nothing in either front-end read these before the
  // Runner screen: a merchant seen once may be noise, one seen on sixteen
  // consecutive cycles is not, and that distinction is the reviewer's
  // cheapest way to prioritise.
  times_seen: number | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  payload: Record<string, unknown>;
};

const CYCLE_SELECT = [
  'id',
  'started_at',
  'finished_at',
  'country_code',
  'outcome',
  'detail',
  'run_id',
  'window_start',
  'window_end',
  'token_expires_at',
  'host',
  'analysis_runs(run_at,run_by_email,csv_filename,csv_date_start,' +
    'csv_date_end,total_rows,unique_transactions,critical_findings_count,' +
    'monitor_findings_count,zero_settlement_findings_count,' +
    'chargeback_exposure_usd,chargeback_exposure_currency,' +
    'currency_source,source)',
].join(',');

const FINDING_SELECT = [
  'id',
  'company_name',
  'finding_type',
  'confidence',
  'risk_score',
  'fingerprints',
  'section',
  'chargeback_exposure_usd',
  'chargeback_exposure_currency',
  'description_es',
  'review_status',
  'reviewed_by_email',
  'times_seen',
  'first_seen_at',
  'last_seen_at',
  'payload',
].join(',');

// ── Reads ────────────────────────────────────────────────────────────────────

export async function listCycles(limit = 30): Promise<RunnerCycle[]> {
  const { data, error } = await supabase
    .from('runner_cycles')
    .select(CYCLE_SELECT)
    .order('started_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error(`listCycles: ${error.message}`);
  return (data as unknown as RunnerCycle[]) || [];
}

/**
 * Per-country health, exact rather than derived from the fetched window.
 *
 * The window matters: a country that has been failing for three days has its
 * last success outside any list we would reasonably fetch, so computing this
 * client-side would report "never ran" for the exact outage it exists to
 * surface. The RPC scans the whole table (behind a partial index).
 */
export async function runnerHealth(): Promise<CountryHealth[]> {
  const { data, error } = await supabase.rpc('runner_health');
  if (error) throw new Error(`runner_health: ${error.message}`);
  return (data as unknown as CountryHealth[]) || [];
}

/**
 * The findings currently attributed to one run.
 *
 * Fetched lazily, when a cycle is expanded: the collapsed row shows counts
 * recorded on the run itself, so nothing here is needed to render the list.
 *
 * "Currently attributed" is load-bearing. De-duplication moves a finding's
 * run_id forward to the most recent cycle that saw it (migration 0011's
 * touch_finding), so an older run legitimately loses findings to newer ones
 * as they are re-detected. That is why the collapsed header uses the
 * immutable counts and this list is labelled as current state — the two
 * disagreeing is information, not a bug to hide.
 */
export async function listRunFindings(runId: string): Promise<RunFinding[]> {
  const { data, error } = await supabase
    .from('findings_history')
    .select(FINDING_SELECT)
    .eq('run_id', runId)
    // Critical before Monitor, then worst score first.
    .order('confidence', { ascending: true })
    .order('risk_score', { ascending: false })
    .limit(200);
  if (error) throw new Error(`listRunFindings: ${error.message}`);
  return (data as unknown as RunFinding[]) || [];
}

// ── Derived, with no thresholds baked into the database ──────────────────────

export function hoursSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return (Date.now() - t) / 3_600_000;
}

export function isStale(h: CountryHealth): boolean {
  const hours = hoursSince(h.last_success_at);
  // Never having succeeded counts as stale. The first thing to notice about a
  // runner installed last week is that one of the three countries never
  // actually worked.
  return hours === null || hours > STALE_AFTER_HOURS;
}

/**
 * The next local hour this country is scheduled for.
 *
 * The rotation is stateless — `hour % len(ROTATION)` — so a missed slot never
 * shifts the schedule and this needs nothing stored. Cosmetic: if ROTATION
 * ever drifts from the Python, this shows a wrong next-slot while staleness,
 * which is the load-bearing number, stays correct because it is measured in
 * elapsed hours.
 */
export function nextSlotHour(countryCode: string, now = new Date()): number | null {
  const idx = ROTATION.indexOf(countryCode);
  if (idx < 0) return null;
  const current = now.getHours();
  for (let ahead = 1; ahead <= 24; ahead++) {
    const hour = (current + ahead) % 24;
    if (hour % SLOT_HOURS === idx) return hour;
  }
  return null;
}

export function daysUntil(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return (t - Date.now()) / 86_400_000;
}

/** Total findings a run recorded at the time it ran. Immutable. */
export function recordedFindingCount(run: CycleRun | null): number | null {
  if (!run) return null;
  const parts = [
    run.critical_findings_count,
    run.monitor_findings_count,
    run.zero_settlement_findings_count,
  ];
  if (parts.every(p => p == null)) return null;
  // The three groups are disjoint in build_findings_rows: exposure/Critical,
  // exposure/Monitor and zero_settlement, so summing them is correct and not
  // double-counting.
  return parts.reduce((sum: number, p) => sum + (p || 0), 0);
}
