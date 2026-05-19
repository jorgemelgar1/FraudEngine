import { supabase } from './supabase';
import {
  enqueueSync,
  getSyncQueue,
  isNetworkError,
  removeFromQueue,
  updateQueueItem,
  type QueuedRun,
} from './offline';

// Shape of a single finding object inside the analyze.py output.
// Loosely typed on purpose; the analyzer's payload schema is rich and
// we only pluck a handful of fields for the audit row. Whatever extra
// fields are present pass through into `payload` (jsonb).
type Finding = Record<string, unknown> & {
  company_name?: string;
  company_id?: string;
  type?: string;
  confidence?: 'Critical' | 'Monitor';
  risk_score?: number;
  fingerprints?: string[];
  action_code?: string;
  estimated_chargeback_exposure?: number;
  currency?: string;
  description_es?: string;
};

type Findings = {
  summary?: {
    date_range?: { start: string | null; end: string | null };
    total_rows?: number;
    unique_transactions?: number;
    total_critical_findings?: number;
    total_monitor_findings?: number;
    estimated_chargeback_exposure?: number;
    currency?: string;
  };
  critical_findings?: Finding[];
  monitor_findings?: Finding[];
};

export type SyncResult = {
  run_id: string;
  critical_inserted: number;
  monitor_inserted: number;
};

// Mirror of api/analyze.py:insert_run_audit + insert_findings_history.
//
// Two-step write because findings need to reference run_id and PostgREST
// returns the generated UUID in the response of the first insert. We do
// the second insert in a single batch so all findings share one round-trip.
export async function syncFindings(
  userEmail: string,
  userId: string,
  csvFilename: string,
  findings: Findings,
): Promise<SyncResult> {
  const summary = findings.summary || {};
  const currency = summary.currency || 'USD';

  // 1. Run audit row
  const { data: runRows, error: runErr } = await supabase
    .from('analysis_runs')
    .insert({
      run_by_email:                 userEmail,
      run_by_user_id:               userId,
      csv_filename:                 csvFilename,
      csv_date_start:               summary.date_range?.start ?? null,
      csv_date_end:                 summary.date_range?.end ?? null,
      total_rows:                   summary.total_rows ?? null,
      unique_transactions:          summary.unique_transactions ?? null,
      critical_findings_count:      summary.total_critical_findings ?? null,
      monitor_findings_count:       summary.total_monitor_findings ?? null,
      chargeback_exposure_usd:      summary.estimated_chargeback_exposure ?? null,
      chargeback_exposure_currency: currency,
      summary:                      summary,
    })
    .select('id')
    .single();

  if (runErr || !runRows) {
    throw new Error(`No se pudo guardar el run en Supabase: ${runErr?.message || 'sin datos'}`);
  }
  const runId = runRows.id as string;

  // 2. All findings in one batched insert. Critical findings land as
  // 'pending' so they show up on the Vercel /pendientes screen for human
  // review (same review-status rule as api/analyze.py).
  const critical = findings.critical_findings || [];
  const monitor  = findings.monitor_findings  || [];
  const rows = [...critical, ...monitor].map((f) => ({
    run_id:                       runId,
    company_name:                 f.company_name ?? null,
    company_id:                   f.company_id   ?? null,
    finding_type:                 f.type         ?? null,
    confidence:                   f.confidence   ?? null,
    risk_score:                   f.risk_score   ?? null,
    fingerprints:                 f.fingerprints ?? [],
    action_code:                  f.action_code  ?? null,
    chargeback_exposure_usd:      f.estimated_chargeback_exposure ?? null,
    chargeback_exposure_currency: f.currency ?? currency,
    description_es:               f.description_es ?? null,
    review_status:                f.confidence === 'Critical' ? 'pending' : 'not_applicable',
    payload:                      f,
  }));

  let inserted = 0;
  if (rows.length > 0) {
    const { error: findErr, count } = await supabase
      .from('findings_history')
      .insert(rows, { count: 'exact' });
    if (findErr) {
      // The run row is already in the database; surfacing this lets the
      // user re-trigger sync from a future "retry" button if we add one.
      throw new Error(`Run guardado, pero falló al guardar findings: ${findErr.message}`);
    }
    inserted = count ?? rows.length;
  }

  return {
    run_id: runId,
    critical_inserted: critical.length,
    monitor_inserted:  Math.max(0, inserted - critical.length),
  };
}

// Network-tolerant wrapper around syncFindings. On a network failure
// (offline, DNS down), the run + findings get parked in the local sync
// queue and the caller is told the queue id. Anything else (RLS denial,
// schema mismatch, etc.) propagates as a real error so the user sees it.
//
// The queue is drained automatically when the network returns; see
// drainSyncQueue() below, which the App component calls on `online` events.
export type SyncOrQueueResult =
  | { status: 'synced'; result: SyncResult }
  | { status: 'queued'; queueId: string; queuedAt: string };

export async function syncOrQueue(
  userId: string,
  userEmail: string,
  csvFilename: string,
  findings: Findings,
): Promise<SyncOrQueueResult> {
  try {
    const result = await syncFindings(userEmail, userId, csvFilename, findings);
    return { status: 'synced', result };
  } catch (e) {
    if (!isNetworkError(e)) throw e;
    const queued = await enqueueSync({
      csvFilename,
      userId,
      userEmail,
      findings,
    });
    return { status: 'queued', queueId: queued.id, queuedAt: queued.queuedAt };
  }
}

// Drain whatever is in the sync queue. Called automatically when the
// browser fires an `online` event, and manually from the header's "Sync"
// button. Returns counts so the UI can show a toast/summary.
//
// Network failures stop the drain (no point hammering an offline server).
// Permanent failures (RLS, schema) keep the item in the queue but bump
// attempts + lastError so the UI can flag it.
export type DrainResult = { synced: number; remaining: number; permanent_errors: number };

export async function drainSyncQueue(): Promise<DrainResult> {
  const queue = await getSyncQueue();
  let synced = 0;
  let permanentErrors = 0;

  for (const item of queue) {
    try {
      await syncFindings(item.userEmail, item.userId, item.csvFilename, item.findings as Findings);
      await removeFromQueue(item.id);
      synced += 1;
    } catch (e) {
      if (isNetworkError(e)) {
        // Network dropped mid-drain — stop and let the next reconnect retry.
        break;
      }
      // Real failure (e.g., RLS, validation). Record it but keep the item
      // so the user can see the count and decide. Future improvement: a
      // "delete from queue" button once attempts > N.
      await updateQueueItem(item.id, {
        attempts: (item.attempts || 0) + 1,
        lastError: e instanceof Error ? e.message : String(e),
      });
      permanentErrors += 1;
    }
  }

  const remaining = (await getSyncQueue()).length;
  return { synced, remaining, permanent_errors: permanentErrors };
}

// Re-export so the App component can subscribe to the queue size for the
// header badge without importing offline.ts directly.
export type { QueuedRun };

