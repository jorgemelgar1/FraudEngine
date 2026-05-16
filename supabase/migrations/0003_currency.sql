-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — multi-currency support
--
-- Original schema (0001) named the exposure columns *_usd because every
-- CSV was assumed to be Panama (USD). Cubo also operates in Guatemala
-- (GTQ), so each row now carries its currency ISO code separately. The
-- *_usd column name is retained for compatibility; treat the suffix as
-- historical, not authoritative.
--
-- Paste this entire file into the Supabase SQL Editor and run it once
-- before deploying the code change that writes the new column.
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────

alter table analysis_runs
    add column if not exists chargeback_exposure_currency text default 'USD';

alter table findings_history
    add column if not exists chargeback_exposure_currency text default 'USD';

-- Backfill: every pre-migration row was implicitly USD.
update analysis_runs
    set chargeback_exposure_currency = 'USD'
    where chargeback_exposure_currency is null;

update findings_history
    set chargeback_exposure_currency = 'USD'
    where chargeback_exposure_currency is null;
