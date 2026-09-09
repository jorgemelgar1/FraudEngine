-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — mark pre-fix currency values as UNKNOWN
--
-- Why this migration exists
-- ─────────────────────────
-- Multi-currency shipped 2026-05-15 and never worked. analyze.py defined
-- `_normalize_country` twice — the currency helper (lower-case, accent-folded)
-- and, 500 lines below, a foreign-card comparison helper (UPPER-case). Python
-- keeps the last definition, so every COUNTRY_TO_CURRENCY lookup received an
-- uppercase string, missed the lower-case keys, and fell through to 'USD'.
--
-- Result: every row written between 2026-05-15 and the fix says USD,
-- regardless of the country the CSV came from. Guatemalan runs are wrong;
-- Panama and El Salvador happen to be right by coincidence, which is exactly
-- why nobody noticed for four months.
--
-- The country is NOT recoverable from what we stored. It never reached the
-- database: it was read from the CSV, collapsed to a currency code, and only
-- the code was written. Neither `payload` nor its `evidence` rows carry a
-- country field. Ops inferring currency from "which analyst ran the file"
-- genuinely was the only signal left.
--
-- So: mark them unknown rather than guess. An explicit gap is honest; a
-- fabricated exchange rate or an assumed country is not.
--
-- The cutoff is the DEPLOY TIMESTAMP of the fix, not 2026-05-15 — rows
-- written between those dates are equally untrustworthy.
--
-- ⚠ THIS MIGRATION MODIFIES EXISTING DATA. Read the cutoff line below and
--   set it before running. Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Provenance column ─────────────────────────────────────────────────────
-- The country the currency was derived from. analyze.py now writes this into
-- the run summary; the column makes it queryable. Had it existed in May, the
-- bug would have been a one-query diagnosis instead of a four-month mystery.

alter table analysis_runs
    add column if not exists currency_source text;

comment on column analysis_runs.currency_source is
    'Normalized country_name the currency code was derived from. NULL for '
    'runs predating the 2026-09 currency fix.';


-- ── 2. Mark pre-fix rows unknown ─────────────────────────────────────────────
--
-- ⚠ EDIT v_cutoff BELOW BEFORE RUNNING. ⚠
--
-- Set it to the moment the currency fix actually reached production - the
-- deploy timestamp, NOT 2026-05-15. Rows written between those dates are
-- equally untrustworthy.
--
-- Everything written strictly BEFORE v_cutoff is marked UNKNOWN.
--
-- One DO block rather than psql variables: the Supabase SQL Editor is a plain
-- query runner and does not support \set or :'variable' interpolation.

do $$
declare
    -- ▼▼▼ THE ONE LINE TO EDIT ▼▼▼
    v_cutoff constant timestamptz := '2026-09-09T00:00:00Z';
    -- ▲▲▲ THE ONE LINE TO EDIT ▲▲▲

    v_runs_marked     integer;
    v_findings_marked integer;
    v_runs_after      integer;
begin
    update analysis_runs
       set chargeback_exposure_currency = 'UNKNOWN'
     where run_at < v_cutoff
       and coalesce(chargeback_exposure_currency, '') <> 'UNKNOWN';
    get diagnostics v_runs_marked = row_count;

    -- Findings inherit through their run: a finding's currency is only ever
    -- the currency of the file it came from.
    update findings_history fh
       set chargeback_exposure_currency = 'UNKNOWN'
      from analysis_runs ar
     where fh.run_id = ar.id
       and ar.run_at < v_cutoff
       and coalesce(fh.chargeback_exposure_currency, '') <> 'UNKNOWN';
    get diagnostics v_findings_marked = row_count;

    select count(*) into v_runs_after
      from analysis_runs where run_at >= v_cutoff;

    raise notice '─────────────────────────────────────────────';
    raise notice 'cutoff              : %', v_cutoff;
    raise notice 'runs marked UNKNOWN : %', v_runs_marked;
    raise notice 'findings marked     : %', v_findings_marked;
    raise notice 'runs AFTER cutoff   : %  <- these keep their currency', v_runs_after;
    raise notice '─────────────────────────────────────────────';

    if v_runs_after > 0 then
        raise notice 'Those % run(s) keep their currency and are trusted as', v_runs_after;
        raise notice 'correct. That is only true if the currency fix was deployed';
        raise notice 'before they ran. A desktop app older than the fix carries';
        raise notice 'the OLD engine in its frozen sidecar and still writes USD';
        raise notice 'for Guatemala regardless of what the server does.';
    end if;
end $$;


-- ── 3. Note for the UI ───────────────────────────────────────────────────────
-- Both frontends already tolerate an unrecognized ISO code: fmtCurrency()
-- catches the Intl.NumberFormat exception and falls back to "UNKNOWN 1,234.56"
-- rather than crashing. No frontend change is required for this migration,
-- though rendering it as "sin moneda registrada" would read better than a
-- literal UNKNOWN next to a number.
