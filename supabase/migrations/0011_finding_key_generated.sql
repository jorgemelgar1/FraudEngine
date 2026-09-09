-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — make de-duplication actually work for every writer
--
-- Migration 0010 added `finding_key` and backfilled it, but nothing POPULATES
-- it on insert. There are three writers today:
--
--   api/analyze.py        the web app (Vercel)
--   desktop/src/lib/sync.ts   the desktop app
--   runner/run.py         the automated runner (new)
--
-- None of them sends finding_key, so every finding created after 0010 ran has
-- finding_key = NULL. `lookup_open_finding` matches on that column, so it
-- would never find them — and the runner would raise a duplicate beside every
-- manually-uploaded finding. That is precisely the queue-flooding failure
-- de-duplication exists to prevent, arriving through the back door.
--
-- Fixing it in three clients means three chances to drift. Fixing it in the
-- column means it cannot drift: a GENERATED column is computed by Postgres on
-- every insert and update, and cannot be written to by any client at all.
--
-- Also here, for the same "one place, not three" reason:
--   * first_seen_at / last_seen_at default to now(), so manual uploads get
--     them without either app being changed.
--   * touch_finding refreshes the WHOLE finding rather than four columns of
--     it, so a re-detected finding never shows a mix of new score and stale
--     evidence.
--
-- Paste into the Supabase SQL Editor and run once. Idempotent: the DO block
-- detects a column that is already generated and does nothing.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. finding_key becomes a generated column ────────────────────────────────
-- The expression must agree EXACTLY with runner/dedup.py:finding_key(), or
-- pre-existing findings become invisible to the runner and every one of them
-- is re-raised as new. tests/test_dedup.py asserts the two agree.
--
-- `company_name` is NOT NULL (migration 0001), so the key is never null.
-- `section` may be null on rows predating migration 0007; coalesce gives them
-- 'exposure', which is what they are.

do $$
begin
    if exists (
        select 1
          from information_schema.columns
         where table_schema = 'public'
           and table_name   = 'findings_history'
           and column_name  = 'finding_key'
           and is_generated = 'ALWAYS'
    ) then
        raise notice 'finding_key is already a generated column - skipping.';
        return;
    end if;

    -- The indexes depend on the column, so they go first and come back below.
    drop index if exists findings_history_key_open_idx;
    drop index if exists findings_history_key_idx;

    -- Dropping loses 0010's backfilled values, which is harmless: the column
    -- is a pure function of two other columns in the same row, so re-adding
    -- it recomputes every row identically.
    alter table findings_history drop column if exists finding_key;

    alter table findings_history
        add column finding_key text
        generated always as (
            lower(trim(company_name)) || '|' ||
            lower(coalesce(trim(section), 'exposure'))
        ) stored;

    raise notice 'finding_key is now generated and recomputed for all rows.';
end $$;

comment on column findings_history.finding_key is
    'Stable identity across runs: lower(trim(company_name)) || ''|'' || section. '
    'GENERATED - Postgres computes it on every write, so no client can forget '
    'it or disagree about it. Must match runner/dedup.py:finding_key().';

create index if not exists findings_history_key_open_idx
    on findings_history (finding_key)
    where review_status in ('pending', 'not_applicable');

create index if not exists findings_history_key_idx
    on findings_history (finding_key, review_status);


-- ── 2. Sighting timestamps default themselves ────────────────────────────────
-- Without defaults, only the runner sets these and a manually-uploaded finding
-- has NULL first_seen_at - so the UI cannot say "detected N times since X" for
-- findings that came from a person, and lookup_open_finding's ordering falls
-- back to reviewed_at. Defaults fix both without touching either app.

alter table findings_history
    alter column first_seen_at set default now(),
    alter column last_seen_at  set default now();

-- Backfill the rows created between migration 0010 and this one, which have
-- neither the default nor 0010's backfill (that only covered rows existing
-- when 0010 ran).
update findings_history fh
   set first_seen_at = coalesce(fh.first_seen_at, ar.run_at),
       last_seen_at  = coalesce(fh.last_seen_at,  ar.run_at)
  from analysis_runs ar
 where fh.run_id = ar.id
   and (fh.first_seen_at is null or fh.last_seen_at is null);


-- ── 3. Run provenance for the runner ─────────────────────────────────────────
-- 0010 added analysis_runs.source. 0009 added analysis_runs.currency_source
-- but nothing writes it yet; the runner does, and the two apps are being
-- updated alongside. Nothing to change here - noted so the next reader of
-- this file does not go looking for it.


-- ── 4. touch_finding refreshes the whole finding ─────────────────────────────
-- The 0010 version updated risk_score, confidence, fingerprints and payload,
-- leaving chargeback_exposure_usd, description_es, action_code and run_id at
-- their first-detection values. A reviewer would see a current score beside a
-- two-day-old exposure figure and have no way to tell.
--
-- The new version takes the ENTIRE row the caller would have inserted - the
-- same dict api/analyze.py:build_findings_rows produces - so insert and
-- update can never write different fields. Adding a column to that function
-- automatically flows through both paths.
--
-- Dropped rather than replaced because the signature changes; `create or
-- replace` would leave a second overload behind and make calls ambiguous.
-- Safe to drop: the runner is its only caller and is not live yet.

drop function if exists touch_finding(uuid, integer, text, text[], jsonb, boolean);
drop function if exists touch_finding(uuid, jsonb, boolean);

create function touch_finding(
    p_id      uuid,
    p_row     jsonb,
    p_promote boolean default false
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row findings_history%rowtype;
begin
    select * into v_row from findings_history where id = p_id for update;
    if not found then
        raise exception 'Finding % not found', p_id;
    end if;

    update findings_history
       set -- Point at the run that most recently saw this. first_seen_at
           -- keeps the original detection date, so nothing is lost, and the
           -- review screens - which join analysis_runs for the date range -
           -- show the window the current score was computed from.
           run_id       = coalesce(nullif(p_row->>'run_id', '')::uuid, run_id),
           risk_score   = coalesce(nullif(p_row->>'risk_score', '')::integer,
                                   risk_score),
           confidence   = coalesce(nullif(p_row->>'confidence', ''), confidence),
           finding_type = coalesce(nullif(p_row->>'finding_type', ''),
                                   finding_type),
           company_id   = nullif(p_row->>'company_id', ''),
           action_code  = nullif(p_row->>'action_code', ''),
           fingerprints = coalesce(
               (select array_agg(x)
                  from jsonb_array_elements_text(p_row->'fingerprints') x),
               fingerprints),
           chargeback_exposure_usd =
               nullif(p_row->>'chargeback_exposure_usd', '')::numeric,
           chargeback_exposure_currency =
               coalesce(nullif(p_row->>'chargeback_exposure_currency', ''),
                        chargeback_exposure_currency),
           description_es = nullif(p_row->>'description_es', ''),
           payload      = coalesce(p_row->'payload', payload),

           times_seen    = times_seen + 1,
           last_seen_at  = now(),
           first_seen_at = coalesce(first_seen_at, now()),

           -- Promotion happens when a Monitor-tier finding reaches Critical:
           -- it must enter the review queue rather than stay informational.
           review_status = case
               when p_promote and review_status = 'not_applicable' then 'pending'
               else review_status
           end
     where id = p_id;

    return jsonb_build_object(
        'id',         p_id,
        'times_seen', v_row.times_seen + 1,
        'promoted',   p_promote and v_row.review_status = 'not_applicable'
    );
end;
$$;


-- ── 5. Watchlist sighting ────────────────────────────────────────────────────
-- When the runner re-detects a merchant that was already accepted, the alert
-- is suppressed (it has been actioned) but "still happening" is worth
-- recording. This refreshes last_flagged and the score.
--
-- flag_count is deliberately NOT bumped. It counts how many times a human
-- accepted this merchant onto the watchlist; letting an automated sighting
-- increment it every three hours would turn a meaningful number into a clock.

create or replace function touch_watchlist_merchant(
    p_company_name text,
    p_risk_score   integer,
    p_run_id       uuid default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_found boolean;
begin
    update watchlist_merchants
       set last_flagged    = now(),
           last_risk_score = coalesce(p_risk_score, last_risk_score),
           last_run_id     = coalesce(p_run_id, last_run_id),
           updated_at      = now()
     where company_name = p_company_name;

    get diagnostics v_found = row_count;
    return jsonb_build_object('company_name', p_company_name,
                              'updated', v_found > 0);
end;
$$;


-- ── 6. Verification ──────────────────────────────────────────────────────────
-- Expected: every row has a finding_key, and no two OPEN findings share one.
-- A non-zero duplicate count is not a failure of this migration - it means
-- repeated manual uploads already created duplicates, which the runner will
-- reconcile on its next pass over the same merchant.

do $$
declare
    v_null_keys  bigint;
    v_dupe_open  bigint;
begin
    select count(*) into v_null_keys
      from findings_history where finding_key is null;

    select count(*) into v_dupe_open from (
        select finding_key
          from findings_history
         where review_status in ('pending', 'not_applicable')
         group by finding_key
        having count(*) > 1
    ) d;

    raise notice 'findings with a null finding_key: % (expected 0)', v_null_keys;
    raise notice 'keys with more than one open finding: % (pre-existing duplicates from manual uploads; the runner collapses these)', v_dupe_open;
end $$;
