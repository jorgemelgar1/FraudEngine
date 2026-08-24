-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — persist the zero-settlement (card-testing) section
--
-- Why this migration exists
-- ─────────────────────────
-- `detect_suspicious_rejected_merchants` (analyze.py) shipped in desktop
-- v0.2.0 as a third report section: merchants that never settle a charge but
-- show card-testing behavior across their rejected attempts. Until now the
-- section was render-only — it appeared in the report screen and then
-- vanished, because neither /api/analyze nor the desktop sync wrote it to
-- `findings_history`. So those merchants never reached /pendientes or
-- /historial, and accepting one never added its tested cards to the
-- watchlist.
--
-- This migration makes the section a first-class citizen of the existing
-- review pipeline rather than building a parallel one:
--
--   findings_history.section  'exposure' | 'zero_settlement'
--
-- The two sections differ in what they mean, not in how they are reviewed:
--
--   exposure         — the legacy chargeback-exposure model (score_merchant).
--                      Scores SUCCEEDED charges, carries an exposure amount.
--   zero_settlement  — the card-testing detector. Settles $0 by definition,
--                      so `chargeback_exposure_usd` is NULL for these rows.
--                      The evidence cards are the cards being TESTED, which
--                      is exactly what belongs on the card watchlist.
--
-- Review semantics are unchanged and deliberately shared:
--   - Critical (either section) → 'pending', shows in /pendientes, and an
--     Accept upserts the merchant + evidence cards into the watchlist.
--   - Monitor  (either section) → 'not_applicable', persisted for the audit
--     trail but never enters the review queue.
--
-- Because the zero-settlement findings already carry `confidence`,
-- `company_name`, `risk_score`, `fingerprints`, and a `payload.evidence[]`
-- array with `card_bin` / `card_last_digits` / `timestamp`, the review RPCs
-- from 0004 (`_accept_one_finding`, `_reject_one_finding`,
-- `_undo_one_finding`) work on them unmodified. This migration adds no new
-- functions and changes no existing ones.
--
-- Paste this entire file into the Supabase SQL Editor and run it once
-- BEFORE deploying the code change — otherwise /api/analyze will fail with
-- a "column does not exist" error from PostgREST on the first upload.
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. findings_history.section ──────────────────────────────────────────────
-- Defaults to 'exposure' so every pre-existing row is correctly labelled as
-- coming from the legacy model without a separate backfill statement
-- (Postgres 11+ fills existing rows from the default on ADD COLUMN).

alter table findings_history
    add column if not exists section text not null default 'exposure';

-- Drop + recreate so a re-run converges even if an older expression exists.
alter table findings_history
    drop constraint if exists findings_history_section_check;
alter table findings_history
    add constraint findings_history_section_check
    check (section in ('exposure', 'zero_settlement'));

comment on column findings_history.section is
    'Which detector produced this finding: ''exposure'' = chargeback-exposure '
    'model (score_merchant), ''zero_settlement'' = card-testing detector '
    '(detect_suspicious_rejected_merchants). Zero-settlement rows always have '
    'a NULL chargeback_exposure_usd — nothing settled.';


-- ── 2. analysis_runs.zero_settlement_findings_count ──────────────────────────
-- Mirrors the existing critical_findings_count / monitor_findings_count
-- columns so /historial can show the section's size per run without
-- digging into the `summary` jsonb. Nullable: runs recorded before this
-- migration legitimately have no value (the section did not exist, or
-- existed but was not persisted).

alter table analysis_runs
    add column if not exists zero_settlement_findings_count integer;

comment on column analysis_runs.zero_settlement_findings_count is
    'Count of zero-settlement (card-testing) findings in this run, both '
    'tiers. NULL for runs predating migration 0007.';


-- ── 3. Indexes ───────────────────────────────────────────────────────────────
-- The 0004 partial index on (run_id) where review_status = 'pending' already
-- serves the pending queue. This one supports filtering that queue down to a
-- single section, which both review screens offer as a toggle.

create index if not exists findings_history_section_pending_idx
    on findings_history (section, run_id)
    where review_status = 'pending';

-- Section-scoped history lookups (the /historial screen's section filter).
create index if not exists findings_history_section_reviewed_idx
    on findings_history (section, reviewed_at desc)
    where review_status in ('accepted', 'rejected');


-- ── 4. Note on RLS ───────────────────────────────────────────────────────────
-- No policy changes are needed. The desktop insert policy from 0005
-- (`auth_insert_findings`) gates on the run's ownership and the caller's
-- email domain, not on a column allowlist, so it accepts rows carrying the
-- new `section` value as-is. The service-role path used by Vercel bypasses
-- RLS entirely and is likewise unaffected.
