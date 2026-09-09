-- ─────────────────────────────────────────────────────────────────────────────
-- Verification for migrations 0009 + 0010. READ-ONLY - changes nothing.
--
-- Paste into the Supabase SQL Editor after running both. Every row should say
-- OK. Anything else means the runner will misbehave in a way that is hard to
-- notice later, so it is worth thirty seconds now.
-- ─────────────────────────────────────────────────────────────────────────────

with expected_columns as (
    select * from (values
        ('analysis_runs',    'currency_source'),
        ('analysis_runs',    'source'),
        ('findings_history', 'finding_key'),
        ('findings_history', 'first_seen_at'),
        ('findings_history', 'last_seen_at'),
        ('findings_history', 'times_seen'),
        ('findings_history', 'suppressed_until')
    ) as t(tbl, col)
),
column_check as (
    select
        'column' as kind,
        e.tbl || '.' || e.col as item,
        case when c.column_name is null then 'MISSING' else 'OK' end as status
    from expected_columns e
    left join information_schema.columns c
           on c.table_name = e.tbl
          and c.column_name = e.col
          and c.table_schema = 'public'
),
expected_functions as (
    select * from (values
        ('lookup_open_finding'), ('touch_finding'), ('reopen_finding')
    ) as t(fn)
),
function_check as (
    select
        'function' as kind,
        e.fn as item,
        case when p.proname is null then 'MISSING' else 'OK' end as status
    from expected_functions e
    left join pg_proc p on p.proname = e.fn
),
-- Every finding must have a key, or the runner cannot recognise it as a prior
-- sighting and will raise it again as new.
key_check as (
    select
        'backfill' as kind,
        'findings_history.finding_key populated' as item,
        case when count(*) filter (where finding_key is null
                                     and company_name is not null) = 0
             then 'OK' else 'INCOMPLETE - ' ||
                  count(*) filter (where finding_key is null
                                     and company_name is not null)::text ||
                  ' rows missing a key'
        end as status
    from findings_history
),
-- The Python key must equal the SQL backfill expression exactly. If these
-- ever diverge every existing finding becomes invisible to the runner.
key_format_check as (
    select
        'backfill' as kind,
        'finding_key format matches runner/dedup.py' as item,
        case when count(*) = 0 then 'OK'
             else 'MISMATCH on ' || count(*)::text || ' rows'
        end as status
    from findings_history
    where finding_key is not null
      and finding_key <> lower(trim(company_name)) || '|' || coalesce(section, 'exposure')
),
-- 0009 should have left no pre-cutoff row claiming a real currency.
currency_check as (
    select
        'currency' as kind,
        'pre-fix rows marked UNKNOWN' as item,
        'INFO: ' ||
        count(*) filter (where chargeback_exposure_currency = 'UNKNOWN')::text ||
        ' unknown, ' ||
        count(*) filter (where chargeback_exposure_currency <> 'UNKNOWN')::text ||
        ' still carry a currency' as status
    from analysis_runs
)
select kind, item, status from column_check
union all select kind, item, status from function_check
union all select kind, item, status from key_check
union all select kind, item, status from key_format_check
union all select kind, item, status from currency_check
order by
    case when status = 'OK' then 2 when status like 'INFO%' then 1 else 0 end,
    kind, item;


-- ── Runs that still carry a currency: are they trustworthy? ──────────────────
-- Any row here was written AFTER the 0009 cutoff, so it is being treated as
-- correct. That is only true if the currency fix was already deployed when it
-- ran - including on the desktop app, whose frozen sidecar carries its own
-- copy of the engine.

select
    run_at,
    source,
    csv_filename,
    chargeback_exposure_currency as currency,
    currency_source,
    case
        when currency_source is null
            then 'pre-fix engine (no provenance recorded)'
        else 'fixed engine'
    end as engine_version
from analysis_runs
where chargeback_exposure_currency <> 'UNKNOWN'
order by run_at desc
limit 20;
