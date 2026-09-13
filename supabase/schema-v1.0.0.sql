-- Cubo Pago fraud engine - full schema baseline for v1.0.0
--
-- GENERATED FILE. Do not edit it by hand; edit the migrations and rebuild:
--   python scripts/build_schema_baseline.py
--
-- Every migration in supabase/migrations/ concatenated in order, so one
-- file recreates an empty database from nothing. The migrations remain the
-- source of truth - this exists so that recovering the schema does not
-- depend on having this repository checked out at the right tag.
--
-- There is NO DATA here, deliberately. This file is committed to a PUBLIC
-- repository. The data lives in an encrypted backup outside the repo - see
-- scripts/README.md.
--
-- Migrations included (17):
--   0001_init.sql
--   0002_watchlist_triggers.sql
--   0003_currency.sql
--   0004_findings_review.sql
--   0005_desktop_inserts.sql
--   0006_review_rpcs_security_definer.sql
--   0007_zero_settlement_persistence.sql
--   0008_fraud_indicators.sql
--   0009_currency_unknown_backfill.sql
--   0010_finding_dedup.sql
--   0011_finding_key_generated.sql
--   0012_runner_cycles.sql
--   0013_review_reasons.sql
--   0014_watchlist_and_decisions.sql
--   0015_explicit_grants.sql
--   0016_service_role_grants.sql
--   0017_authenticated_grants.sql


-- ==========================================================================
-- 0001_init.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — initial schema
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. analysis_runs — audit log: one row per CSV processed
create table if not exists analysis_runs (
    id                       uuid        primary key default gen_random_uuid(),
    run_at                   timestamptz not null    default now(),
    run_by_email             text,
    run_by_user_id           uuid        references auth.users(id),
    csv_filename             text,
    csv_date_start           date,
    csv_date_end             date,
    total_rows               integer,
    unique_transactions      integer,
    critical_findings_count  integer,
    monitor_findings_count   integer,
    chargeback_exposure_usd  numeric(12,2),
    summary                  jsonb
);

create index if not exists analysis_runs_run_at_idx on analysis_runs (run_at desc);
create index if not exists analysis_runs_user_idx   on analysis_runs (run_by_user_id);


-- 2. watchlist_merchants — permanent (never pruned)
create table if not exists watchlist_merchants (
    company_name      text        primary key,
    company_id        text,
    first_flagged     timestamptz not null,
    last_flagged      timestamptz not null,
    flag_count        integer     not null default 1,
    last_risk_score   integer,
    last_run_id       uuid        references analysis_runs(id),
    notes             text,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

create index if not exists watchlist_merchants_last_flagged_idx on watchlist_merchants (last_flagged desc);
create index if not exists watchlist_merchants_flag_count_idx   on watchlist_merchants (flag_count desc);


-- 3. watchlist_cards — permanent (never pruned, per policy)
create table if not exists watchlist_cards (
    bin               text        not null,
    last4             text        not null,
    card_key          text        generated always as (bin || '-' || last4) stored,
    first_flagged     timestamptz not null,
    last_flagged      timestamptz not null,
    flag_count        integer     not null default 1,
    last_run_id       uuid        references analysis_runs(id),
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    primary key (bin, last4)
);

create index if not exists watchlist_cards_last_flagged_idx on watchlist_cards (last_flagged desc);
create index if not exists watchlist_cards_bin_idx          on watchlist_cards (bin);


-- 4. findings_history — every Critical/Monitor finding ever produced
create table if not exists findings_history (
    id                       uuid        primary key default gen_random_uuid(),
    run_id                   uuid        not null references analysis_runs(id) on delete cascade,
    company_name             text        not null,
    company_id               text,
    finding_type             text        not null,
    confidence               text        not null,
    risk_score               integer     not null,
    fingerprints             text[]      not null,
    action_code              text,
    chargeback_exposure_usd  numeric(12,2),
    description_es           text,
    payload                  jsonb       not null
);

create index if not exists findings_history_company_idx      on findings_history (company_name);
create index if not exists findings_history_run_idx          on findings_history (run_id);
create index if not exists findings_history_fingerprints_gin on findings_history using gin (fingerprints);


-- ─────────────────────────────────────────────────────────────────────────────
-- Row Level Security
-- The Python function uses the SERVICE ROLE KEY which bypasses RLS entirely.
-- These policies govern what end users (browser sessions) can see.
-- ─────────────────────────────────────────────────────────────────────────────

alter table analysis_runs        enable row level security;
alter table watchlist_merchants  enable row level security;
alter table watchlist_cards      enable row level security;
alter table findings_history     enable row level security;

drop policy if exists "auth_read_runs"       on analysis_runs;
drop policy if exists "auth_read_merchants"  on watchlist_merchants;
drop policy if exists "auth_read_cards"      on watchlist_cards;
drop policy if exists "auth_read_findings"   on findings_history;

create policy "auth_read_runs"       on analysis_runs       for select to authenticated using (true);
create policy "auth_read_merchants"  on watchlist_merchants for select to authenticated using (true);
create policy "auth_read_cards"      on watchlist_cards     for select to authenticated using (true);
create policy "auth_read_findings"   on findings_history    for select to authenticated using (true);

-- ==========================================================================
-- 0002_watchlist_triggers.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — watchlist trigger hardening (run after 0001_init.sql)
--
-- Two correctness issues addressed by this migration:
--
--   1. flag_count race condition.  Two concurrent uploads both load
--      flag_count = N, both bump to N+1 in memory, both upsert N+1 →
--      final value is N+1 instead of N+2. Moving the increment into a
--      BEFORE UPDATE trigger makes it atomic at the SQL level.
--
--   2. updated_at and first_flagged drift.  The Python upsert payload
--      doesn't (and shouldn't) try to preserve these — first_flagged
--      should never change after the row's first INSERT, and updated_at
--      should advance on every mutation. Triggers handle both invariants
--      in one place.
--
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- It's idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────

-- Trigger function for watchlist_merchants.
create or replace function bump_watchlist_merchant() returns trigger as $$
begin
    -- Atomic increment regardless of what the upsert payload claimed.
    new.flag_count    = old.flag_count + 1;
    -- Preserve the original creation/first-flagged timestamps across upserts.
    new.first_flagged = old.first_flagged;
    new.created_at    = old.created_at;
    -- Always advance updated_at on any mutation.
    new.updated_at    = now();
    -- last_flagged, last_risk_score, last_run_id, company_id, notes are
    -- intentionally taken from NEW (i.e., the upsert payload).
    return new;
end;
$$ language plpgsql;

drop trigger if exists watchlist_merchants_bump on watchlist_merchants;
create trigger watchlist_merchants_bump
    before update on watchlist_merchants
    for each row execute function bump_watchlist_merchant();


-- Trigger function for watchlist_cards. Same logic, fewer columns.
create or replace function bump_watchlist_card() returns trigger as $$
begin
    new.flag_count    = old.flag_count + 1;
    new.first_flagged = old.first_flagged;
    new.created_at    = old.created_at;
    new.updated_at    = now();
    -- last_flagged, last_run_id come from NEW.
    return new;
end;
$$ language plpgsql;

drop trigger if exists watchlist_cards_bump on watchlist_cards;
create trigger watchlist_cards_bump
    before update on watchlist_cards
    for each row execute function bump_watchlist_card();

-- ==========================================================================
-- 0003_currency.sql
-- ==========================================================================

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

-- ==========================================================================
-- 0004_findings_review.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — human-in-the-loop watchlist review
--
-- Until this migration, every Critical finding immediately upserted its
-- merchant + evidence cards into the watchlist tables. False positives
-- therefore persisted forever and damaged merchants down the road. This
-- migration moves the watchlist write behind an explicit Accept action
-- performed by a team member after the analysis returns.
--
-- Schema:
--   findings_history.review_status  pending|accepted|rejected|not_applicable
--   findings_history.reviewed_at / reviewed_by_email / reviewed_by_user_id
--   findings_history.review_notes
--   findings_history.watchlist_delta  jsonb { merchant_was_new, new_cards[], existed_cards[] }
--                                     captured on Accept so Undo can roll back precisely
--
-- Logic:
--   - All Critical findings written by /api/analyze land as 'pending'.
--   - Monitor findings land as 'not_applicable' (they never updated the
--     watchlist before and don't need a decision).
--   - Existing rows are backfilled to 'accepted' so the audit trail is
--     coherent (they were auto-committed by the old code path).
--
-- Trigger change:
--   The 0002 BEFORE-UPDATE triggers unconditionally incremented flag_count
--   to keep concurrent uploads atomic. With the new RPC-driven workflow,
--   accept and undo need to set flag_count explicitly. We add a session
--   guard `app.skip_auto_bump` that callers (the RPC functions below) set
--   to 'true' so the trigger leaves flag_count alone for that call. Direct
--   upserts that don't set the guard still get the original auto-bump
--   behavior — so any future code path that bypasses the RPC still gets
--   race protection.
--
-- Paste this entire file into the Supabase SQL Editor and run it once
-- before deploying the code change. Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. findings_history columns ──────────────────────────────────────────────

alter table findings_history
    add column if not exists review_status text not null default 'pending';

-- The check constraint may already exist with an older expression; drop
-- and recreate so re-runs converge.
alter table findings_history
    drop constraint if exists findings_history_review_status_check;
alter table findings_history
    add constraint findings_history_review_status_check
    check (review_status in ('pending', 'accepted', 'rejected', 'not_applicable'));

alter table findings_history
    add column if not exists reviewed_at         timestamptz,
    add column if not exists reviewed_by_email   text,
    add column if not exists reviewed_by_user_id uuid references auth.users(id),
    add column if not exists review_notes        text,
    add column if not exists watchlist_delta     jsonb;


-- ── 2. Backfill ──────────────────────────────────────────────────────────────
-- Anything inserted by the old auto-commit code path is effectively
-- 'accepted' (the watchlist already reflects it). Only rows still labelled
-- 'pending' from a fresh install need backfilling.

update findings_history fh
    set review_status = 'accepted',
        reviewed_at   = ar.run_at
    from analysis_runs ar
    where fh.run_id = ar.id
      and fh.review_status = 'pending';


-- ── 3. Indexes ───────────────────────────────────────────────────────────────

create index if not exists findings_history_pending_idx
    on findings_history (run_id)
    where review_status = 'pending';

create index if not exists findings_history_reviewed_idx
    on findings_history (reviewed_at desc)
    where review_status in ('accepted', 'rejected');


-- ── 4. Trigger update — honor app.skip_auto_bump session guard ───────────────

create or replace function bump_watchlist_merchant() returns trigger as $$
begin
    if current_setting('app.skip_auto_bump', true) = 'true' then
        -- Caller is managing flag_count explicitly (accept/undo RPC).
        -- Still preserve creation-time invariants.
        new.first_flagged = old.first_flagged;
        new.created_at    = old.created_at;
        new.updated_at    = now();
        return new;
    end if;
    new.flag_count    = old.flag_count + 1;
    new.first_flagged = old.first_flagged;
    new.created_at    = old.created_at;
    new.updated_at    = now();
    return new;
end;
$$ language plpgsql;

create or replace function bump_watchlist_card() returns trigger as $$
begin
    if current_setting('app.skip_auto_bump', true) = 'true' then
        new.first_flagged = old.first_flagged;
        new.created_at    = old.created_at;
        new.updated_at    = now();
        return new;
    end if;
    new.flag_count    = old.flag_count + 1;
    new.first_flagged = old.first_flagged;
    new.created_at    = old.created_at;
    new.updated_at    = now();
    return new;
end;
$$ language plpgsql;


-- ── 5. RPC: accept / reject / undo (individual + bulk) ───────────────────────

-- Single-finding accept. Returns the watchlist_delta jsonb so callers can
-- log or surface it. Raises if the finding is not pending or not Critical.
create or replace function _accept_one_finding(
    p_finding_id uuid,
    p_user_id    uuid,
    p_user_email text
) returns jsonb as $$
declare
    v_finding         findings_history%rowtype;
    v_evidence        jsonb;
    v_bin             text;
    v_last4           text;
    v_merchant_was_new boolean := false;
    v_new_cards       text[]   := array[]::text[];
    v_existed_cards   text[]   := array[]::text[];
    v_card_was_new    boolean;
    v_delta           jsonb;
    v_first_flagged   timestamptz;
begin
    select * into v_finding
    from findings_history
    where id = p_finding_id
    for update;

    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_finding.review_status <> 'pending' then
        raise exception 'Finding % already reviewed (status=%)',
            p_finding_id, v_finding.review_status;
    end if;
    if v_finding.confidence <> 'Critical' then
        raise exception 'Only Critical findings can be accepted (got %)',
            v_finding.confidence;
    end if;

    -- Suppress the auto-bump trigger for the rest of this transaction.
    perform set_config('app.skip_auto_bump', 'true', true);

    -- Earliest evidence timestamp, falls back to the run's now.
    select min((e->>'timestamp')::timestamptz)
        into v_first_flagged
        from jsonb_array_elements(coalesce(v_finding.payload->'evidence', '[]'::jsonb)) as e;
    v_first_flagged := coalesce(v_first_flagged, now());

    -- Upsert merchant. Returns whether this was an INSERT (xmax = 0) or UPDATE.
    with upsert as (
        insert into watchlist_merchants (
            company_name, company_id, first_flagged, last_flagged,
            flag_count, last_risk_score, last_run_id
        ) values (
            v_finding.company_name,
            nullif(v_finding.company_id, ''),
            v_first_flagged,
            now(),
            1,
            v_finding.risk_score,
            v_finding.run_id
        )
        on conflict (company_name) do update set
            flag_count      = watchlist_merchants.flag_count + 1,
            last_flagged    = now(),
            last_run_id     = excluded.last_run_id,
            last_risk_score = excluded.last_risk_score,
            company_id      = coalesce(excluded.company_id, watchlist_merchants.company_id)
        returning (xmax = 0) as was_inserted
    )
    select was_inserted into v_merchant_was_new from upsert;

    -- Upsert each card from evidence.
    for v_evidence in
        select * from jsonb_array_elements(coalesce(v_finding.payload->'evidence', '[]'::jsonb))
    loop
        v_bin   := v_evidence->>'card_bin';
        v_last4 := v_evidence->>'card_last_digits';
        if v_bin is null or v_last4 is null or v_bin = '' or v_last4 = '' then
            continue;
        end if;

        with upsert as (
            insert into watchlist_cards (
                bin, last4, first_flagged, last_flagged, flag_count, last_run_id
            ) values (
                v_bin, v_last4, v_first_flagged, now(), 1, v_finding.run_id
            )
            on conflict (bin, last4) do update set
                flag_count   = watchlist_cards.flag_count + 1,
                last_flagged = now(),
                last_run_id  = excluded.last_run_id
            returning (xmax = 0) as was_inserted
        )
        select was_inserted into v_card_was_new from upsert;

        if v_card_was_new then
            v_new_cards := array_append(v_new_cards, v_bin || '-' || v_last4);
        else
            v_existed_cards := array_append(v_existed_cards, v_bin || '-' || v_last4);
        end if;
    end loop;

    v_delta := jsonb_build_object(
        'merchant_was_new', v_merchant_was_new,
        'new_cards',        to_jsonb(v_new_cards),
        'existed_cards',    to_jsonb(v_existed_cards)
    );

    update findings_history set
        review_status        = 'accepted',
        reviewed_at          = now(),
        reviewed_by_email    = p_user_email,
        reviewed_by_user_id  = p_user_id,
        watchlist_delta      = v_delta
    where id = p_finding_id;

    return v_delta;
end;
$$ language plpgsql;


create or replace function _reject_one_finding(
    p_finding_id uuid,
    p_user_id    uuid,
    p_user_email text
) returns jsonb as $$
declare
    v_status text;
begin
    select review_status into v_status
        from findings_history
        where id = p_finding_id
        for update;
    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_status <> 'pending' then
        raise exception 'Finding % already reviewed (status=%)', p_finding_id, v_status;
    end if;

    update findings_history set
        review_status       = 'rejected',
        reviewed_at         = now(),
        reviewed_by_email   = p_user_email,
        reviewed_by_user_id = p_user_id
    where id = p_finding_id;

    return jsonb_build_object('status', 'rejected');
end;
$$ language plpgsql;


-- Undo a previous accept or reject. Enforces a 24h window so older decisions
-- can't be silently reversed. Restores watchlist_delta when undoing an accept.
create or replace function _undo_one_finding(
    p_finding_id uuid,
    p_user_id    uuid,
    p_user_email text
) returns jsonb as $$
declare
    v_finding findings_history%rowtype;
    v_delta   jsonb;
    v_card_key text;
    v_bin     text;
    v_last4   text;
    v_age_hours numeric;
begin
    select * into v_finding
    from findings_history
    where id = p_finding_id
    for update;

    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_finding.review_status not in ('accepted', 'rejected') then
        raise exception 'Cannot undo finding in status %', v_finding.review_status;
    end if;

    v_age_hours := extract(epoch from (now() - v_finding.reviewed_at)) / 3600.0;
    if v_age_hours > 24 then
        raise exception 'Undo window expired (% hours since review, limit 24)',
            round(v_age_hours, 1);
    end if;

    if v_finding.review_status = 'accepted' then
        perform set_config('app.skip_auto_bump', 'true', true);
        v_delta := coalesce(v_finding.watchlist_delta, '{}'::jsonb);

        -- Roll back merchant.
        if (v_delta->>'merchant_was_new')::boolean then
            -- We created the row; remove it only if our increment is the
            -- only one outstanding (flag_count still 1).
            delete from watchlist_merchants
                where company_name = v_finding.company_name
                  and flag_count = 1;
            -- If flag_count > 1, another accept landed since. Decrement.
            update watchlist_merchants
                set flag_count = flag_count - 1
                where company_name = v_finding.company_name
                  and flag_count > 1;
        else
            update watchlist_merchants
                set flag_count = greatest(flag_count - 1, 0)
                where company_name = v_finding.company_name;
        end if;

        -- Roll back cards added new.
        for v_card_key in select jsonb_array_elements_text(coalesce(v_delta->'new_cards', '[]'::jsonb))
        loop
            v_bin   := split_part(v_card_key, '-', 1);
            v_last4 := split_part(v_card_key, '-', 2);
            delete from watchlist_cards
                where bin = v_bin and last4 = v_last4 and flag_count = 1;
            update watchlist_cards
                set flag_count = flag_count - 1
                where bin = v_bin and last4 = v_last4 and flag_count > 1;
        end loop;

        -- Roll back cards we only bumped.
        for v_card_key in select jsonb_array_elements_text(coalesce(v_delta->'existed_cards', '[]'::jsonb))
        loop
            v_bin   := split_part(v_card_key, '-', 1);
            v_last4 := split_part(v_card_key, '-', 2);
            update watchlist_cards
                set flag_count = greatest(flag_count - 1, 0)
                where bin = v_bin and last4 = v_last4;
        end loop;
    end if;
    -- Reject undo has no watchlist side effects.

    update findings_history set
        review_status       = 'pending',
        reviewed_at         = null,
        reviewed_by_email   = null,
        reviewed_by_user_id = null,
        watchlist_delta     = null,
        -- Record who triggered the undo in review_notes so it's auditable.
        review_notes        = concat(
            'Undone by ', p_user_email, ' at ',
            to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI:SS'), ' UTC'
        )
    where id = p_finding_id;

    return jsonb_build_object('status', 'pending', 'undone_by', p_user_email);
end;
$$ language plpgsql;


-- Public bulk entry point. Wraps the three primitives above so the API
-- only needs to call one RPC regardless of action or count.
create or replace function review_findings(
    p_finding_ids uuid[],
    p_action      text,
    p_user_id     uuid,
    p_user_email  text
) returns jsonb as $$
declare
    v_results jsonb := '[]'::jsonb;
    v_id      uuid;
    v_one     jsonb;
begin
    if p_action not in ('accept', 'reject', 'undo') then
        raise exception 'Invalid action: %', p_action;
    end if;
    if p_finding_ids is null or array_length(p_finding_ids, 1) is null then
        raise exception 'No finding ids provided';
    end if;

    foreach v_id in array p_finding_ids loop
        begin
            if p_action = 'accept' then
                v_one := _accept_one_finding(v_id, p_user_id, p_user_email);
            elsif p_action = 'reject' then
                v_one := _reject_one_finding(v_id, p_user_id, p_user_email);
            else
                v_one := _undo_one_finding(v_id, p_user_id, p_user_email);
            end if;
            v_results := v_results || jsonb_build_array(
                jsonb_build_object('id', v_id, 'ok', true, 'result', v_one)
            );
        exception when others then
            v_results := v_results || jsonb_build_array(
                jsonb_build_object('id', v_id, 'ok', false, 'error', sqlerrm)
            );
        end;
    end loop;

    return v_results;
end;
$$ language plpgsql;

-- ==========================================================================
-- 0005_desktop_inserts.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — desktop client write permissions
--
-- Why this migration exists
-- ─────────────────────────
-- The Vercel function uses the SUPABASE_SERVICE_ROLE_KEY (an admin key that
-- bypasses RLS) to insert into analysis_runs and findings_history. That key
-- can never be shipped inside a desktop .exe — anyone with the binary could
-- extract it and bypass all access control.
--
-- The desktop client authenticates each user with their own @cubopago.com
-- Google OAuth session and inserts under that user's JWT. The policies
-- below allow those inserts while still gating them on:
--   - the JWT belonging to an authenticated user
--   - the email-domain matching @cubopago.com (defense-in-depth)
--   - the inserted run being owned by the inserting user
--
-- This is ADDITIVE — it does not change any existing SELECT policies,
-- does not touch the watchlist tables (which the desktop never writes
-- directly), and does not affect the Vercel function's service-role
-- writes (those bypass RLS entirely and remain authoritative).
-- ─────────────────────────────────────────────────────────────────────────────

-- Drop prior versions of these policies so this migration is re-runnable.
drop policy if exists "auth_insert_runs"     on analysis_runs;
drop policy if exists "auth_insert_findings" on findings_history;

-- analysis_runs: authenticated Cubo users can insert audit rows for their
-- OWN runs only (run_by_user_id must equal their auth.uid()). Prevents one
-- user from forging runs attributed to a teammate.
create policy "auth_insert_runs" on analysis_runs
  for insert to authenticated
  with check (
    run_by_user_id = auth.uid()
    and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
  );

-- findings_history: authenticated users can insert findings linked to a
-- run they themselves created. The exists() join enforces that.
create policy "auth_insert_findings" on findings_history
  for insert to authenticated
  with check (
    auth.uid() is not null
    and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
    and exists (
      select 1 from analysis_runs r
      where r.id = run_id and r.run_by_user_id = auth.uid()
    )
  );

-- ==========================================================================
-- 0006_review_rpcs_security_definer.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — let authenticated end-users call review RPCs
--
-- Why this migration exists
-- ─────────────────────────
-- The internal review functions defined in 0004_findings_review.sql
-- (_accept_one_finding, _reject_one_finding, _undo_one_finding) were
-- written WITHOUT `security definer`, so they default to SECURITY
-- INVOKER — they run with the caller's privileges.
--
-- The Vercel function gets away with that because it authenticates via
-- the service-role key, which bypasses RLS. The desktop app authenticates
-- with the user's own JWT and is subject to RLS. The functions all do:
--
--     select ... from findings_history where id = $1 for update;
--
-- `FOR UPDATE` requires UPDATE privilege on the row, not just SELECT. We
-- only have a SELECT policy on findings_history (`auth_read_findings`)
-- and no UPDATE policy, so the lock acquisition silently returns zero
-- rows and the function raises "Finding % not found".
--
-- Two fix paths:
--   1. Add an UPDATE policy that whitelists the state transitions the
--      review flow needs. Complex — requires policies on findings_history,
--      watchlist_merchants, watchlist_cards, plus careful USING / WITH
--      CHECK clauses to prevent abuse.
--   2. Make the functions SECURITY DEFINER so they run as the owner
--      (postgres) and bypass RLS, just like the service-role path. This
--      matches the original design intent (the functions already have
--      pendency / confidence guards inside).
--
-- This migration takes path 2. It's purely additive — Vercel's existing
-- service-role calls keep working unchanged.
--
-- `set search_path = public, pg_temp` is the standard hardening for any
-- SECURITY DEFINER function: it prevents a caller from manipulating
-- search_path to redirect catalog lookups inside the function body.
--
-- Idempotent: ALTER FUNCTION ... SECURITY DEFINER is safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────

alter function _accept_one_finding(uuid, uuid, text)
    security definer
    set search_path = public, pg_temp;

alter function _reject_one_finding(uuid, uuid, text)
    security definer
    set search_path = public, pg_temp;

alter function _undo_one_finding(uuid, uuid, text)
    security definer
    set search_path = public, pg_temp;

-- ==========================================================================
-- 0007_zero_settlement_persistence.sql
-- ==========================================================================

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

-- ==========================================================================
-- 0008_fraud_indicators.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — confirmed-fraud indicators
--
-- Why this migration exists
-- ─────────────────────────
-- The engine has two persistent memory surfaces today: watchlist_merchants
-- (by company name) and watchlist_cards (by BIN + last4). Both are populated
-- only as a side effect of accepting a finding, and both key on things the
-- engine itself discovered.
--
-- What ops actually has, and what the engine cannot use, is confirmed fraud
-- data from OUTSIDE a run: a chargeback report naming an email, a bank notice
-- naming a cardholder, a case where a phone number turned up again. The
-- valuable pattern is cross-merchant — the same payer identity settling at a
-- new merchant after being confirmed as fraud at another one.
--
-- This table is where the team writes those values directly.
--
-- Design notes
-- ────────────
-- * `value_norm` is a COARSE de-duplication key — lower(btrim(value_raw)) —
--   computed by a trigger, never by a client. It exists so "Fraude@X.com"
--   and "fraude@x.com " cannot become two rows.
--
--   It is deliberately NOT the precise normalization used for matching. That
--   lives in analyze.py (normalize_indicator_value: +tag stripping, Gmail dot
--   folding, token-sorted names, phone tails) and is re-derived from
--   `value_raw` every run, so the engine's rules are always current even for
--   rows written before a normalizer changed.
--
--   Why a trigger rather than letting each client compute it: the Vercel
--   function has analyze.py in-process and could normalize precisely, but the
--   desktop client talks to PostgREST directly and cannot. Two clients
--   computing the same unique key differently would silently split one
--   indicator into two rows. Postgres owning the column makes that
--   impossible.
--
-- * `source_company_name` records WHERE the value was confirmed. A hit at a
--   different merchant is the strongest signal this feature produces, and it
--   is only distinguishable if we remember the origin.
--
-- * `match_mode` is per indicator, not global. A cardholder name wants fuzzy
--   matching; a card_key never does. 'exact' is the safe default.
--
-- * `hit_count` / `last_hit_at` are how the list stays healthy. Indicators
--   that never fire are dead weight; ones that fire constantly are too broad.
--   Without these columns a deny-list only ever grows.
--
-- * `expires_at` exists because indicator types age differently. An IP is
--   meaningful for weeks; a confirmed-fraud cardholder name does not expire.
--
-- PRIVACY NOTE — read before running this
-- ───────────────────────────────────────
-- This table stores personal data (emails, phone numbers, cardholder and
-- payer names, IP addresses) that the system has deliberately never persisted
-- before. README.md's privacy table is updated in the same change; if any
-- commitment about retention has been made to the team or to compliance on
-- the strength of the old wording, it needs revisiting.
--
-- Paste this entire file into the Supabase SQL Editor and run it once BEFORE
-- deploying the code change. Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Table ─────────────────────────────────────────────────────────────────

create table if not exists fraud_indicators (
    id                  uuid        primary key default gen_random_uuid(),

    indicator_type      text        not null,
    value_raw           text        not null,   -- as the analyst typed it
    value_norm          text        not null,   -- set by trigger; see header
    match_mode          text        not null default 'exact',

    -- Provenance. Every hit surfaces these back to the reviewer, so a match
    -- can always be traced to who confirmed it and why.
    source              text,                   -- chargeback | ops review | bank report | other
    source_company_name text,                   -- merchant where it was confirmed
    notes               text,
    added_by_email      text        not null,
    added_at            timestamptz not null default now(),

    active              boolean     not null default true,
    expires_at          timestamptz,

    hit_count           integer     not null default 0,
    last_hit_at         timestamptz,
    last_hit_company    text,

    -- 'card_key' is BIN + last 4 together. There is deliberately no
    -- 'card_bin' or 'card_last4': a BIN is a whole issuing bank and last-4
    -- is one in ten thousand, so either alone would fire constantly.
    constraint fraud_indicators_type_check check (indicator_type in (
        'card_key', 'email', 'email_domain',
        'phone', 'ip', 'person_name', 'company_name', 'company_id'
    )),
    constraint fraud_indicators_mode_check check (match_mode in ('exact', 'fuzzy', 'both')),
    constraint fraud_indicators_value_norm_len check (char_length(value_norm) between 2 and 256),

    -- One row per (type, normalized value). Re-adding a value that already
    -- exists should update the existing row, not create a duplicate.
    unique (indicator_type, value_norm)
);

comment on column fraud_indicators.value_norm is
    'Coarse de-duplication key, lower(btrim(value_raw)), set by trigger and '
    'ignored if a client supplies one. Matching uses the precise normalizers '
    'in analyze.py, re-derived from value_raw at run time.';

comment on table fraud_indicators is
    'Analyst-entered values confirmed to be linked to fraud. Matched against '
    'every analyzed CSV. Contains personal data — see migration header.';

comment on column fraud_indicators.source_company_name is
    'Merchant where this value was confirmed as fraud. A match at a DIFFERENT '
    'merchant is the cross-merchant signal this feature exists to catch.';


-- ── 1b. value_norm is server-owned ───────────────────────────────────────────
-- Overwrites whatever the client sent. Both the Vercel function and the
-- desktop app can therefore insert without knowing the rule, and neither can
-- split one indicator into two rows by normalizing differently.

create or replace function set_indicator_value_norm() returns trigger as $$
begin
    new.value_norm := lower(btrim(new.value_raw));
    if new.value_norm is null or char_length(new.value_norm) < 2 then
        raise exception 'Indicator value is too short to be usable: %', new.value_raw;
    end if;
    return new;
end;
$$ language plpgsql;

drop trigger if exists fraud_indicators_norm on fraud_indicators;
create trigger fraud_indicators_norm
    before insert or update of value_raw on fraud_indicators
    for each row execute function set_indicator_value_norm();


-- ── 2. Indexes ───────────────────────────────────────────────────────────────
-- The engine loads the full active set once per run, so the hot path is a
-- single filtered scan rather than per-value lookups.

create index if not exists fraud_indicators_active_idx
    on fraud_indicators (indicator_type, value_norm)
    where active;

create index if not exists fraud_indicators_added_idx
    on fraud_indicators (added_at desc);

create index if not exists fraud_indicators_hits_idx
    on fraud_indicators (hit_count desc, last_hit_at desc);


-- ── 3. Row Level Security ────────────────────────────────────────────────────
-- Same model as the rest of the schema: any authenticated @cubopago.com user
-- can read and write; the Vercel service-role key bypasses RLS entirely.
--
-- Deliberately no DELETE policy. Indicators are deactivated (active = false),
-- never removed, so the audit trail of what was matched against survives.

alter table fraud_indicators enable row level security;

drop policy if exists "auth_read_indicators"   on fraud_indicators;
drop policy if exists "auth_insert_indicators" on fraud_indicators;
drop policy if exists "auth_update_indicators" on fraud_indicators;

create policy "auth_read_indicators" on fraud_indicators
    for select to authenticated using (true);

create policy "auth_insert_indicators" on fraud_indicators
    for insert to authenticated
    with check (
        auth.uid() is not null
        and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
        and lower(added_by_email) = lower(coalesce(auth.jwt() ->> 'email', ''))
    );

-- Update is limited to the review/lifecycle columns. The USING clause gates
-- who may act; WITH CHECK stops a caller rewriting an indicator's identity
-- (its type or normalized value) into something else after the fact.
create policy "auth_update_indicators" on fraud_indicators
    for update to authenticated
    using (
        auth.uid() is not null
        and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
    )
    with check (
        auth.uid() is not null
        and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
    );


-- ── 4. Hit recording ─────────────────────────────────────────────────────────
-- Called once per run with the ids that fired. Bulk, so a run with 30 hits
-- is one round trip. SECURITY DEFINER for the same reason as migration 0006:
-- the desktop client calls under a user JWT and must not need broad UPDATE
-- rights on the table to record a hit.

create or replace function record_indicator_hits(
    p_indicator_ids uuid[],
    p_company_name  text
) returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_count integer;
begin
    if p_indicator_ids is null or array_length(p_indicator_ids, 1) is null then
        return 0;
    end if;

    update fraud_indicators
       set hit_count        = hit_count + 1,
           last_hit_at      = now(),
           last_hit_company = coalesce(p_company_name, last_hit_company)
     where id = any(p_indicator_ids);

    get diagnostics v_count = row_count;
    return v_count;
end;
$$;


-- ── 5. Deactivate helper ─────────────────────────────────────────────────────
-- Kept as an RPC rather than a raw UPDATE so the reason is always recorded.

create or replace function deactivate_indicator(
    p_indicator_id uuid,
    p_user_email   text,
    p_reason       text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row fraud_indicators%rowtype;
begin
    select * into v_row from fraud_indicators where id = p_indicator_id for update;
    if not found then
        raise exception 'Indicator % not found', p_indicator_id;
    end if;

    update fraud_indicators
       set active = false,
           notes  = concat_ws(' | ',
                        nullif(notes, ''),
                        concat('Desactivado por ', p_user_email,
                               case when p_reason is not null and p_reason <> ''
                                    then concat(': ', p_reason) else '' end))
     where id = p_indicator_id;

    return jsonb_build_object('id', p_indicator_id, 'active', false);
end;
$$;

-- ==========================================================================
-- 0009_currency_unknown_backfill.sql
-- ==========================================================================

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

-- ==========================================================================
-- 0010_finding_dedup.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — finding de-duplication for the automated runner
--
-- Why this migration exists
-- ─────────────────────────
-- The runner analyses a today+yesterday window, one country per hour on a
-- three-country rotation. A merchant flagged at 10:00 therefore stays inside
-- the window until end of tomorrow and will be re-detected roughly 16 times
-- (48 hours / 3-hour cycle) before it ages out.
--
-- Without de-duplication the review queue receives sixteen copies of every
-- finding within two days. The review queue IS the product — flooding it does
-- not degrade the tool, it ends it.
--
-- Identity is (company_name, section): one open finding per merchant per
-- detector. Ops reasons about "is this merchant a problem?", not "is this
-- merchant's Tuesday-afternoon pattern a problem?". A new pattern at a known
-- merchant refreshes the existing finding's fingerprints rather than raising
-- a second one.
--
-- Decision table (implemented in runner/dedup.py, which is unit-tested):
--
--   none              -> insert as 'pending'
--   pending           -> UPDATE in place; bump times_seen, refresh the score
--   accepted          -> suppress (already actioned and on the watchlist)
--   rejected          -> suppress for 48 h, UNLESS the score escalates
--   not_applicable    -> update; promote to 'pending' if it reaches Critical
--
-- Escalation (overrides the 48 h cooloff):
--   new_score >= rejected_score + 15, OR
--   the finding crosses into Critical having been rejected at Monitor
--
-- Paste this entire file into the Supabase SQL Editor and run it once BEFORE
-- the runner's first scheduled execution. Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. findings_history columns ──────────────────────────────────────────────

alter table findings_history
    add column if not exists finding_key      text,
    add column if not exists first_seen_at    timestamptz,
    add column if not exists last_seen_at     timestamptz,
    add column if not exists times_seen       integer not null default 1,
    add column if not exists suppressed_until timestamptz;

comment on column findings_history.finding_key is
    'Stable identity across runs: lower(company_name) || ''|'' || section. '
    'One OPEN finding per key; re-detection updates rather than inserts.';

comment on column findings_history.times_seen is
    'How many runs have detected this finding. A merchant seen once may be '
    'noise; one seen on sixteen consecutive runs is not - the reviewer needs '
    'that distinction to prioritise.';

comment on column findings_history.suppressed_until is
    'Set when a finding is rejected: re-detections are ignored until this '
    'passes, unless the score escalates. Stops a dismissed false positive '
    'from nagging every three hours without making it invisible forever.';


-- ── 2. Backfill ──────────────────────────────────────────────────────────────
-- Existing rows get a key and sensible timestamps so the runner treats them
-- as prior sightings rather than raising duplicates on its first pass.

update findings_history fh
   set finding_key = lower(trim(fh.company_name)) || '|' || coalesce(fh.section, 'exposure')
 where fh.finding_key is null
   and fh.company_name is not null;

update findings_history fh
   set first_seen_at = coalesce(fh.first_seen_at, ar.run_at),
       last_seen_at  = coalesce(fh.last_seen_at,  ar.run_at)
  from analysis_runs ar
 where fh.run_id = ar.id
   and (fh.first_seen_at is null or fh.last_seen_at is null);


-- ── 3. Indexes ───────────────────────────────────────────────────────────────
-- The runner's hot path is "is there an open finding for this key?", once per
-- merchant per run.

create index if not exists findings_history_key_open_idx
    on findings_history (finding_key)
    where review_status in ('pending', 'not_applicable');

create index if not exists findings_history_key_idx
    on findings_history (finding_key, review_status);

-- Deliberately NOT a unique index on (finding_key) where pending.
--
-- Live data may already contain several pending rows for one merchant from
-- repeated manual uploads, and a unique index would make this migration fail
-- on exactly the databases that need it most. Uniqueness is enforced by
-- lookup_open_finding + the runner instead. The residual race (a manual
-- upload and a runner cycle writing the same merchant within milliseconds)
-- resolves itself: the overlapping analysis window means the next run
-- reconciles whatever the collision produced.


-- ── 4. Run provenance ────────────────────────────────────────────────────────
-- When a number looks wrong, "was this my upload or the robot's?" is the
-- first debugging question. Default 'manual' so existing rows are correct.

alter table analysis_runs
    add column if not exists source text not null default 'manual';

alter table analysis_runs
    drop constraint if exists analysis_runs_source_check;
alter table analysis_runs
    add constraint analysis_runs_source_check
    check (source in ('manual', 'auto'));

create index if not exists analysis_runs_source_idx
    on analysis_runs (source, run_at desc);


-- ── 5. Lookup used by the runner ─────────────────────────────────────────────
-- Returns the current open finding for a key, or nothing. SECURITY DEFINER
-- for the same reason as migration 0006: the desktop client calls under a
-- user JWT and must not need broad table rights.

create or replace function lookup_open_finding(p_finding_key text)
returns table (
    id               uuid,
    review_status    text,
    confidence       text,
    risk_score       integer,
    times_seen       integer,
    first_seen_at    timestamptz,
    last_seen_at     timestamptz,
    suppressed_until timestamptz,
    reviewed_at      timestamptz
)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    -- Most recent row for this key regardless of status: the runner needs to
    -- know about accepted and rejected ones too, in order to suppress.
    select fh.id, fh.review_status, fh.confidence, fh.risk_score,
           fh.times_seen, fh.first_seen_at, fh.last_seen_at,
           fh.suppressed_until, fh.reviewed_at
      from findings_history fh
     where fh.finding_key = p_finding_key
     order by
       -- An open finding always wins over a closed one.
       case fh.review_status
            when 'pending' then 0
            when 'not_applicable' then 1
            else 2
       end,
       coalesce(fh.last_seen_at, fh.reviewed_at) desc nulls last
     limit 1;
$$;


-- ── 6. Touch an existing finding ─────────────────────────────────────────────
-- Called when a run re-detects something already open. Refreshes the score
-- and evidence so the reviewer sees CURRENT state, not first-detection state.

create or replace function touch_finding(
    p_id           uuid,
    p_risk_score   integer,
    p_confidence   text,
    p_fingerprints text[],
    p_payload      jsonb,
    p_promote      boolean default false
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
       set risk_score    = p_risk_score,
           confidence    = p_confidence,
           fingerprints  = p_fingerprints,
           payload       = p_payload,
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
        'id', p_id,
        'times_seen', v_row.times_seen + 1,
        'promoted', p_promote and v_row.review_status = 'not_applicable'
    );
end;
$$;


-- ── 7. Re-open a rejected finding ────────────────────────────────────────────
-- Used when a dismissed false positive escalates. The previous rejection stays
-- in the audit trail via review_notes rather than being erased.

create or replace function reopen_finding(
    p_id         uuid,
    p_risk_score integer,
    p_confidence text,
    p_reason     text
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
       set review_status    = 'pending',
           risk_score       = p_risk_score,
           confidence       = p_confidence,
           times_seen       = times_seen + 1,
           last_seen_at     = now(),
           suppressed_until = null,
           review_notes     = concat_ws(' | ',
               nullif(review_notes, ''),
               concat('Reabierto automáticamente ',
                      to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI'),
                      ' UTC: ', p_reason,
                      ' (puntaje anterior ', v_row.risk_score,
                      ', ahora ', p_risk_score, ')'))
     where id = p_id;

    return jsonb_build_object('id', p_id, 'reopened', true, 'reason', p_reason);
end;
$$;

-- ==========================================================================
-- 0011_finding_key_generated.sql
-- ==========================================================================

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

-- ==========================================================================
-- 0012_runner_cycles.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — make the runner's health visible from the app
--
-- Why this migration exists
-- ─────────────────────────
-- The runner already knows whether it is healthy. `cycle.py --health` reads
-- runner/state.py, which is a JSON file on the Pi's SD card — so the only way
-- to answer "is the robot working?" is to SSH into the Pi.
--
-- Worse: `analysis_runs` only ever gets a row when a cycle SUCCEEDS. Every
-- interesting failure — the report email never arrived, the CMS returned 403,
-- the token expired — writes nothing to the database at all. cycle.py even
-- returns exit 0 on the email timeout, deliberately, because a cron job that
-- mails you about every slow report is a cron job you stop reading.
--
-- The consequence is that these three states are indistinguishable from the
-- app's side, and they need completely different responses:
--
--   the Pi is off
--   the Pi is on but cron is not firing
--   cron fires every hour and every single cycle fails
--
-- All three are silence. Making a silently-broken runner distinguishable from
-- a quiet fraud week is the entire reason the runner records anything at all
-- (see the header of runner/state.py) — and without this table that property
-- is lost the moment you look at the system through the UI instead of SSH.
--
-- So: one row per SCHEDULED CYCLE, written whatever the outcome.
--
-- A cycle is not a run
-- ────────────────────
-- `analysis_runs` = an analysis happened. `runner_cycles` = the runner woke up
-- and tried. Every successful cycle has exactly one run (linked by run_id);
-- a failed cycle has none. This is precisely why a list built on analysis_runs
-- alone is the list that hides the failures.
--
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. The table ─────────────────────────────────────────────────────────────

create table if not exists runner_cycles (
    id               uuid        primary key default gen_random_uuid(),

    -- Written at the START of the cycle, updated at the end. A row with a
    -- started_at and no finished_at is a cycle that began and never came
    -- back: the Pi lost power mid-cycle, or the process was killed. That is
    -- a completely different diagnosis from "no row at all" (cron never
    -- fired), and recording only on completion could not tell them apart.
    started_at       timestamptz not null default now(),
    finished_at      timestamptz,

    -- The country this slot ASKED for. Deliberately distinct from the
    -- country of the resulting analysis: every CSV is attributed by the
    -- `country_name` column inside the file, never by the id requested, so
    -- comparing this against analysis_runs.currency_source is a real check
    -- and not a tautology.
    country_code     text        not null,

    outcome          text        not null default 'running',
    detail           text,

    -- Null for every outcome except 'ok'. `on delete set null` rather than
    -- cascade: if a run row is ever deleted the fact that the cycle happened
    -- is still true and still worth showing.
    run_id           uuid        references analysis_runs(id) on delete set null,

    -- The dates requested from the CMS. The CMS reads these in each
    -- country's LOCAL time, and a bug that computed them in UTC shipped
    -- once already (2026-09) — it produced perfectly successful-looking runs
    -- over a 19-hour window instead of the 24+ the card fan-out detector
    -- needs. Storing the window is what would have made that visible.
    window_start     date,
    window_end       date,

    -- Read out of the CMS JWT at cycle start. Put here so the token countdown
    -- can appear in the app: today it exists only as a WARNING line in a log
    -- file on the Pi, which is not a place anyone looks before it expires.
    token_expires_at timestamptz,

    -- Which machine. One Pi today, but "it works on my laptop" is exactly
    -- how a second writer appears without anyone deciding it should.
    host             text
);

comment on table runner_cycles is
    'One row per scheduled runner cycle, written whatever the outcome. '
    'analysis_runs records that an analysis happened; this records that the '
    'runner TRIED. Failed cycles produce a row here and none there.';

comment on column runner_cycles.outcome is
    'running = started and not yet finished (a stuck row means the process '
    'died mid-cycle). ok = analyzed and synced. no_email = the report never '
    'arrived inside the timeout, which is designed behaviour and not an '
    'error. The rest are failures named after what broke.';


-- ── 2. The outcome vocabulary ────────────────────────────────────────────────
-- These map one-to-one onto the branches that already exist in
-- runner/run.py:report_failure and runner/cycle.py. Keeping them in a check
-- constraint means a typo in the runner fails loudly at write time instead of
-- creating a category the dashboard silently cannot render.

alter table runner_cycles
    drop constraint if exists runner_cycles_outcome_check;
alter table runner_cycles
    add constraint runner_cycles_outcome_check
    check (outcome in (
        'running',         -- in flight, or died before finishing
        'ok',              -- analyzed and synced
        'no_email',        -- the 15-minute timeout expired. NOT a failure.
        'cms_error',       -- the report request was refused (403 = headers)
        'token_error',     -- the CMS token is missing or expired
        'gmail_error',     -- the mailbox could not be read (authorization)
        'supabase_error',  -- could not read or write the database
        'config_error',    -- runner/.env is incomplete
        'unexpected'       -- anything else; detail carries only the type name
    ));


-- ── 3. Indexes ───────────────────────────────────────────────────────────────
-- Two access patterns, both from the dashboard: the newest cycles regardless
-- of country (the timeline), and the newest cycles for one country (the
-- per-country tiles).

create index if not exists runner_cycles_started_idx
    on runner_cycles (started_at desc);

create index if not exists runner_cycles_country_started_idx
    on runner_cycles (country_code, started_at desc);

-- Finding the last SUCCESS for a country has to stay cheap even when that
-- country has been failing for a week — which is exactly the situation where
-- the answer matters most, and exactly when a scan of recent rows misses it.
create index if not exists runner_cycles_country_ok_idx
    on runner_cycles (country_code, started_at desc)
    where outcome = 'ok';


-- ── 4. Row Level Security ────────────────────────────────────────────────────
-- Same shape as migration 0001: the runner writes with the service-role key,
-- which bypasses RLS entirely. Browser and desktop sessions get read-only
-- access. Nothing here is sensitive — no merchant names, no URLs, no token,
-- only the token's expiry date — but read-only is still the correct grant:
-- nothing outside the runner has any business writing its own health record.

alter table runner_cycles enable row level security;

drop policy if exists "auth_read_runner_cycles" on runner_cycles;
create policy "auth_read_runner_cycles" on runner_cycles
    for select to authenticated using (true);


-- ── 5. Closing a cycle ───────────────────────────────────────────────────────
-- An RPC rather than a PATCH purely so that `finished_at` is stamped by the
-- DATABASE clock, the same one that stamped started_at. Sending a timestamp
-- from the Pi instead would mean the two ends of a cycle come from different
-- clocks, and any skew between them shows up as a negative duration in the
-- UI - a number that is impossible, unexplainable, and would be read as a
-- bug in the dashboard rather than as clock drift on the Pi.
--
-- Also refuses to re-close an already-closed cycle, so a retry cannot
-- overwrite the first (and more informative) outcome with a later one.
--
-- Deliberately NOT security definer, unlike runner_health() below. Its only
-- caller is the runner, which holds the service-role key and already bypasses
-- RLS - so definer rights would buy nothing and would let any signed-in user
-- rewrite the runner's own health record. The grants below make the split
-- explicit rather than leaving it to Postgres' default of EXECUTE-to-public.

create or replace function finish_runner_cycle(
    p_id      uuid,
    p_outcome text,
    p_detail  text default null
) returns jsonb
language plpgsql
set search_path = public, pg_temp
as $$
declare
    v_prev text;
begin
    select outcome into v_prev from runner_cycles where id = p_id for update;
    if not found then
        return jsonb_build_object('id', p_id, 'closed', false,
                                  'reason', 'no such cycle');
    end if;
    if v_prev <> 'running' then
        return jsonb_build_object('id', p_id, 'closed', false,
                                  'reason', 'already closed as ' || v_prev);
    end if;

    update runner_cycles
       set outcome     = p_outcome,
           detail      = nullif(p_detail, ''),
           finished_at = now()
     where id = p_id;

    return jsonb_build_object('id', p_id, 'closed', true, 'outcome', p_outcome);
end;
$$;

revoke all on function finish_runner_cycle(uuid, text, text) from public;
revoke all on function finish_runner_cycle(uuid, text, text) from anon;
revoke all on function finish_runner_cycle(uuid, text, text) from authenticated;
grant execute on function finish_runner_cycle(uuid, text, text) to service_role;


-- ── 6. runner_health() — one call, exact answers ─────────────────────────────
-- The dashboard needs "when did each country last succeed?". Deriving that
-- client-side from the most recent N cycles is wrong in the one case that
-- matters: a country failing for three days has its last success outside any
-- reasonable window, and the tile would say "never" — turning a three-day
-- outage into a display bug nobody trusts.
--
-- SECURITY DEFINER for the same reason as migration 0006: the desktop client
-- calls this under a user JWT and should not need broad table rights. It
-- reads only aggregates and returns no merchant data.
--
-- Deliberately returns raw facts and NO thresholds. "Is 13 hours stale?" is a
-- product question that belongs next to the code that renders it, and
-- runner/state.py:STALE_AFTER is already the one place it is defined.

create or replace function runner_health()
returns table (
    country_code         text,
    last_success_at      timestamptz,
    last_success_run_id  uuid,
    last_cycle_at        timestamptz,
    last_outcome         text,
    last_detail          text,
    consecutive_failures integer,
    cycles_24h           integer,
    ok_24h               integer,
    token_expires_at     timestamptz
)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    with countries as (
        -- Every country that has ever run, so a fourth one appearing in the
        -- runner's rotation shows up here without this function changing.
        select distinct rc.country_code from runner_cycles rc
    ),
    last_ok as (
        select distinct on (rc.country_code)
               rc.country_code, rc.started_at, rc.run_id
          from runner_cycles rc
         where rc.outcome = 'ok'
         order by rc.country_code, rc.started_at desc
    ),
    last_any as (
        select distinct on (rc.country_code)
               rc.country_code, rc.started_at, rc.outcome, rc.detail,
               rc.token_expires_at
          from runner_cycles rc
         order by rc.country_code, rc.started_at desc
    )
    select c.country_code,
           lo.started_at as last_success_at,
           lo.run_id     as last_success_run_id,
           la.started_at as last_cycle_at,
           la.outcome    as last_outcome,
           la.detail     as last_detail,
           -- Failures since the last success. 'running' is excluded: a cycle
           -- in flight right now is not yet a failure, and counting it as one
           -- would make the dashboard flicker every hour on the hour.
           (select count(*)
              from runner_cycles f
             where f.country_code = c.country_code
               and f.outcome not in ('ok', 'running')
               and (lo.started_at is null or f.started_at > lo.started_at)
           )::integer as consecutive_failures,
           (select count(*)
              from runner_cycles h
             where h.country_code = c.country_code
               and h.started_at > now() - interval '24 hours'
           )::integer as cycles_24h,
           (select count(*)
              from runner_cycles h
             where h.country_code = c.country_code
               and h.started_at > now() - interval '24 hours'
               and h.outcome = 'ok'
           )::integer as ok_24h,
           la.token_expires_at
      from countries c
      left join last_ok  lo on lo.country_code = c.country_code
      left join last_any la on la.country_code = c.country_code
     order by c.country_code;
$$;

comment on function runner_health() is
    'Per-country runner health: last success, last attempt, consecutive '
    'failures and 24-hour counts. Exact rather than derived from a window, '
    'because a country that has been failing for days is precisely when the '
    'last success falls outside any window the client would fetch.';

-- This one IS for the app, so signed-in users need it. It reads aggregates
-- only - no merchant names, no URLs, no token, just the token's expiry date.
grant execute on function runner_health() to authenticated;


-- ── 7. Verification ──────────────────────────────────────────────────────────
-- Expected on a fresh install: the table exists and is empty, and
-- runner_health() returns no rows (no cycle has been recorded yet). The first
-- rows appear on the Pi's next scheduled cycle.

do $$
declare
    v_cycles bigint;
begin
    select count(*) into v_cycles from runner_cycles;
    raise notice 'runner_cycles rows: % (0 is expected before the next cycle)',
        v_cycles;
    raise notice 'runner_health() rows: %',
        (select count(*) from runner_health());
end $$;

-- ==========================================================================
-- 0013_review_reasons.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — why a finding was dismissed
--
-- Why this migration exists
-- ─────────────────────────
-- Today a dismissal records WHO and WHEN and nothing else. That is enough for
-- an audit trail and useless for everything else, because the two questions
-- worth asking both need the reason:
--
--   "Is the engine any good?"      needs "the detector was wrong" separated
--                                  from "the detector was right and we are
--                                  fine with this merchant"
--   "Which detector wastes time?"  needs the reason joined to the fingerprints
--
-- A free-text box cannot answer either. Notes are unaggregatable by
-- construction: five analysts write "es cliente de siempre", "cliente
-- conocido", "ya lo conocemos" and no query can count them. A short fixed list
-- can, and the optional note still catches whatever the list does not.
--
-- The list is deliberately five items. Long taxonomies get answered with
-- whichever option is first, which is worse than no taxonomy at all.
--
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. The column ────────────────────────────────────────────────────────────

alter table findings_history
    add column if not exists review_reason text;

comment on column findings_history.review_reason is
    'Why a Critical finding was dismissed, from a fixed list. Null for '
    'findings that were confirmed as fraud, never reviewed, or reviewed '
    'before this migration existed.';

alter table findings_history
    drop constraint if exists findings_history_review_reason_check;
alter table findings_history
    add constraint findings_history_review_reason_check
    check (review_reason is null or review_reason in (
        'cliente_conocido',   -- legitimate merchant we already know
        'campana_legitima',   -- a real promotion or seasonal spike
        'prueba_interna',     -- our own testing produced the pattern
        'error_detector',     -- the engine was simply wrong  <- the useful one
        'ya_gestionado'       -- already handled outside the tool
    ));

-- Reporting reads "dismissals grouped by reason over a period", so the index
-- matches that shape rather than the column alone.
create index if not exists findings_history_review_reason_idx
    on findings_history (review_reason, reviewed_at desc)
    where review_status = 'rejected';


-- ── 2. Reject, with a reason ─────────────────────────────────────────────────
-- Internal helper; review_findings below is its only caller.

create or replace function _reject_one_finding(
    p_finding_id uuid,
    p_user_id    uuid,
    p_user_email text,
    p_reason     text default null,
    p_note       text default null
) returns jsonb as $$
declare
    v_status text;
begin
    select review_status into v_status
        from findings_history
        where id = p_finding_id
        for update;
    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_status <> 'pending' then
        raise exception 'Finding % already reviewed (status=%)', p_finding_id, v_status;
    end if;

    update findings_history set
        review_status       = 'rejected',
        reviewed_at         = now(),
        reviewed_by_email   = p_user_email,
        reviewed_by_user_id = p_user_id,
        review_reason       = nullif(p_reason, ''),
        -- Appended, never replacing: a finding that was re-opened carries the
        -- runner's explanation of why it came back, and that is exactly the
        -- context someone needs when reading this decision later.
        review_notes        = concat_ws(' | ',
            nullif(review_notes, ''),
            nullif(p_note, ''))
    where id = p_finding_id;

    return jsonb_build_object('status', 'rejected', 'reason', p_reason);
end;
$$ language plpgsql;

alter function _reject_one_finding(uuid, uuid, text, text, text)
    security definer
    set search_path = public, pg_temp;

-- The old four-argument helper is now unreachable. Dropping it keeps the
-- overload set unambiguous — two candidates that differ only by defaulted
-- arguments make PostgREST refuse to choose.
drop function if exists _reject_one_finding(uuid, uuid, text);


-- ── 3. The public entry point ────────────────────────────────────────────────
-- Dropped and recreated rather than replaced, because the signature grows.
--
-- Deployed desktop apps (v0.6.0 and earlier) call this with four named
-- arguments and know nothing about reasons. `p_reason` and `p_note` default to
-- null, so those calls keep resolving to this function and keep working — an
-- old client dismisses without a reason instead of erroring. That matters:
-- the team updates on their own schedule, and a migration that breaks every
-- installed copy until everyone updates is not a migration anyone can run on
-- a Tuesday.

drop function if exists review_findings(uuid[], text, uuid, text);
drop function if exists review_findings(uuid[], text, uuid, text, text, text);

create function review_findings(
    p_finding_ids uuid[],
    p_action      text,
    p_user_id     uuid,
    p_user_email  text,
    p_reason      text default null,
    p_note        text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_id      uuid;
    v_one     jsonb;
    v_results jsonb := '[]'::jsonb;
begin
    if p_action not in ('accept', 'reject', 'undo') then
        raise exception 'Unknown action: %', p_action;
    end if;

    foreach v_id in array p_finding_ids
    loop
        begin
            if p_action = 'accept' then
                v_one := _accept_one_finding(v_id, p_user_id, p_user_email);
            elsif p_action = 'reject' then
                v_one := _reject_one_finding(v_id, p_user_id, p_user_email,
                                             p_reason, p_note);
            else
                v_one := _undo_one_finding(v_id, p_user_id, p_user_email);
            end if;
            v_results := v_results || jsonb_build_array(
                jsonb_build_object('id', v_id, 'ok', true, 'result', v_one)
            );
        -- Per-finding, so one bad id cannot lose the whole batch. The caller
        -- gets a row per id saying which succeeded.
        exception when others then
            v_results := v_results || jsonb_build_array(
                jsonb_build_object('id', v_id, 'ok', false, 'error', sqlerrm)
            );
        end;
    end loop;

    return v_results;
end;
$$;


-- ── 4. What the reasons say, in one place ────────────────────────────────────
-- Returns the dismissal breakdown for a period, and the number that actually
-- matters: of the Critical findings a human has ruled on, how many were real.
--
-- Kept server-side rather than assembled in the app so both clients, and
-- anyone querying by hand, get the same arithmetic. Precision counts only
-- findings a human DECIDED — pending ones are not evidence either way, and
-- including them would make the engine look worse every time the queue grew.

create or replace function review_stats(p_since timestamptz default null)
returns jsonb
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    with decided as (
        select review_status, review_reason
          from findings_history
         where confidence = 'Critical'
           and review_status in ('accepted', 'rejected')
           and (p_since is null or reviewed_at >= p_since)
    )
    select jsonb_build_object(
        'decided',   (select count(*) from decided),
        'confirmed', (select count(*) from decided where review_status = 'accepted'),
        'dismissed', (select count(*) from decided where review_status = 'rejected'),
        'precision', (
            select case when count(*) = 0 then null
                        else round(
                            count(*) filter (where review_status = 'accepted')
                            * 100.0 / count(*), 1)
                   end
              from decided
        ),
        'by_reason', coalesce((
            select jsonb_object_agg(coalesce(review_reason, 'sin_motivo'), n)
              from (select review_reason, count(*) as n
                      from decided
                     where review_status = 'rejected'
                     group by review_reason) r
        ), '{}'::jsonb),
        'pending',   (select count(*) from findings_history
                       where confidence = 'Critical' and review_status = 'pending')
    );
$$;

grant execute on function review_stats(timestamptz) to authenticated;


-- ── 5. Verification ──────────────────────────────────────────────────────────

do $$
begin
    raise notice 'review_findings arity: % (expected 6)',
        (select count(*) from information_schema.parameters
          where specific_schema = 'public'
            and specific_name = (select specific_name
                                   from information_schema.routines
                                  where routine_schema = 'public'
                                    and routine_name = 'review_findings'
                                  limit 1));
    raise notice 'review_stats today: %', review_stats(now() - interval '1 day');
end $$;

-- ==========================================================================
-- 0014_watchlist_and_decisions.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — make the watchlist visible, and decisions changeable
--
-- Why this migration exists
-- ─────────────────────────
-- Accepting a finding writes a merchant and its cards to watchlist_merchants /
-- watchlist_cards. Migration 0001 describes those tables as PERMANENT, NEVER
-- PRUNED. Every analysis reads them. No screen has ever shown them.
--
-- So the most durable consequence of an ops decision is also the only one
-- nobody can audit: you cannot see who is on the list, since when, or why, and
-- you cannot take anyone off. The only escape hatch is Historial's Undo, which
-- expires after 24 hours.
--
-- Two changes, and one deliberate refusal.
--
--   1. Soft removal. Getting off the list must be possible, because a merchant
--      wrongly frozen stays frozen forever otherwise.
--
--   2. Changing a decision after the 24-hour window, with a written
--      explanation. "We were wrong in August" is a normal thing to discover.
--
--   REFUSED: hard deletes. The watchlist row IS the evidence that justified
--   freezing a merchant. Deleting it destroys the record for a decision
--   somebody may have to defend later — to the CTO, to the card networks, in a
--   chargeback dispute. Removal marks the row and stops the engine matching
--   it. Same operational outcome, nothing lost.
--
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Removal columns ───────────────────────────────────────────────────────

alter table watchlist_merchants
    add column if not exists removed_at     timestamptz,
    add column if not exists removed_by     text,
    add column if not exists removed_reason text;

alter table watchlist_cards
    add column if not exists removed_at     timestamptz,
    add column if not exists removed_by     text,
    add column if not exists removed_reason text;

comment on column watchlist_merchants.removed_at is
    'Set when a human takes this merchant off the watchlist. The row stays: it '
    'is the evidence for the original decision. Loaders must filter on this — '
    'a removed merchant must stop matching, or removal means nothing.';

-- Every read of the watchlist is "the active list", so the index matches that.
create index if not exists watchlist_merchants_active_idx
    on watchlist_merchants (company_name) where removed_at is null;
create index if not exists watchlist_cards_active_idx
    on watchlist_cards (bin, last4) where removed_at is null;


-- ── 2. Removing and restoring ────────────────────────────────────────────────
-- A reason is required, not optional. An unexplained removal is exactly the
-- record that will be useless in six months, and the moment of removal is the
-- only time anyone knows why.

create or replace function set_watchlist_merchant_removed(
    p_company_name text,
    p_removed      boolean,
    p_user_email   text,
    p_reason       text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_found boolean;
begin
    if p_removed and coalesce(btrim(p_reason), '') = '' then
        raise exception 'Se requiere un motivo para retirar un comercio de la watchlist';
    end if;

    -- The 0002 triggers bump flag_count on any UPDATE. flag_count counts how
    -- many times a human accepted this merchant; removing one is not another
    -- acceptance, so the guard stays on.
    perform set_config('app.skip_auto_bump', 'true', true);

    update watchlist_merchants set
        removed_at     = case when p_removed then now() else null end,
        removed_by     = case when p_removed then p_user_email else null end,
        removed_reason = case when p_removed then btrim(p_reason) else null end,
        updated_at     = now()
    where company_name = p_company_name;

    get diagnostics v_found = row_count;
    if not v_found then
        raise exception 'Merchant % is not on the watchlist', p_company_name;
    end if;

    return jsonb_build_object('company_name', p_company_name,
                              'removed', p_removed);
end;
$$;

create or replace function set_watchlist_card_removed(
    p_bin        text,
    p_last4      text,
    p_removed    boolean,
    p_user_email text,
    p_reason     text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_found boolean;
begin
    if p_removed and coalesce(btrim(p_reason), '') = '' then
        raise exception 'Se requiere un motivo para retirar una tarjeta';
    end if;

    perform set_config('app.skip_auto_bump', 'true', true);

    update watchlist_cards set
        removed_at     = case when p_removed then now() else null end,
        removed_by     = case when p_removed then p_user_email else null end,
        removed_reason = case when p_removed then btrim(p_reason) else null end,
        updated_at     = now()
    where bin = p_bin and last4 = p_last4;

    get diagnostics v_found = row_count;
    if not v_found then
        raise exception 'Card %-% is not on the watchlist', p_bin, p_last4;
    end if;

    return jsonb_build_object('card', p_bin || '-' || p_last4,
                              'removed', p_removed);
end;
$$;

grant execute on function set_watchlist_merchant_removed(text, boolean, text, text)
    to authenticated;
grant execute on function set_watchlist_card_removed(text, text, boolean, text, text)
    to authenticated;


-- ── 3. Undo stops destroying the audit trail ─────────────────────────────────
-- The 0004 version REPLACED review_notes with "Undone by …", discarding
-- whatever was there — including the runner's explanation of why a finding had
-- been re-opened. It also hard-capped at 24 hours with no way past it, which
-- is why changing an older decision was impossible.
--
-- `p_force` skips the age check. Nothing calls it with true except
-- change_review_decision below, which demands a written explanation first.

create or replace function _undo_one_finding(
    p_finding_id uuid,
    p_user_id    uuid,
    p_user_email text,
    p_force      boolean default false,
    p_note       text default null
) returns jsonb as $$
declare
    v_finding findings_history%rowtype;
    v_delta   jsonb;
    v_card_key text;
    v_bin     text;
    v_last4   text;
    v_age_hours numeric;
begin
    select * into v_finding from findings_history where id = p_finding_id for update;

    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_finding.review_status not in ('accepted', 'rejected') then
        raise exception 'Cannot undo finding in status %', v_finding.review_status;
    end if;

    v_age_hours := extract(epoch from (now() - v_finding.reviewed_at)) / 3600.0;
    if not p_force and v_age_hours > 24 then
        raise exception 'Undo window expired (% hours since review, limit 24)',
            round(v_age_hours, 1);
    end if;

    if v_finding.review_status = 'accepted' then
        perform set_config('app.skip_auto_bump', 'true', true);
        v_delta := coalesce(v_finding.watchlist_delta, '{}'::jsonb);

        if (v_delta->>'merchant_was_new')::boolean then
            delete from watchlist_merchants
                where company_name = v_finding.company_name and flag_count = 1;
            update watchlist_merchants
                set flag_count = flag_count - 1
                where company_name = v_finding.company_name and flag_count > 1;
        else
            update watchlist_merchants
                set flag_count = greatest(flag_count - 1, 0)
                where company_name = v_finding.company_name;
        end if;

        for v_card_key in
            select jsonb_array_elements_text(coalesce(v_delta->'new_cards', '[]'::jsonb))
        loop
            v_bin   := split_part(v_card_key, '-', 1);
            v_last4 := split_part(v_card_key, '-', 2);
            delete from watchlist_cards
                where bin = v_bin and last4 = v_last4 and flag_count = 1;
            update watchlist_cards
                set flag_count = flag_count - 1
                where bin = v_bin and last4 = v_last4 and flag_count > 1;
        end loop;

        for v_card_key in
            select jsonb_array_elements_text(coalesce(v_delta->'existed_cards', '[]'::jsonb))
        loop
            v_bin   := split_part(v_card_key, '-', 1);
            v_last4 := split_part(v_card_key, '-', 2);
            update watchlist_cards
                set flag_count = greatest(flag_count - 1, 0)
                where bin = v_bin and last4 = v_last4;
        end loop;
    end if;

    update findings_history set
        review_status       = 'pending',
        reviewed_at         = null,
        reviewed_by_email   = null,
        reviewed_by_user_id = null,
        review_reason       = null,
        watchlist_delta     = null,
        -- APPENDED, not replaced. The previous version erased the runner's
        -- re-open explanation, which is precisely the context someone needs
        -- when reading this row later.
        review_notes        = concat_ws(' | ',
            nullif(review_notes, ''),
            coalesce(nullif(p_note, ''),
                     concat('Deshecho por ', p_user_email, ' el ',
                            to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI'),
                            ' UTC')))
    where id = p_finding_id;

    return jsonb_build_object('status', 'pending', 'undone_by', p_user_email);
end;
$$ language plpgsql;

alter function _undo_one_finding(uuid, uuid, text, boolean, text)
    security definer
    set search_path = public, pg_temp;

drop function if exists _undo_one_finding(uuid, uuid, text);


-- ── 4. Changing a decision, with an explanation ──────────────────────────────
-- "We were wrong in August" is a normal thing to discover, and today it is
-- impossible after 24 hours. The explanation is mandatory: this rewrites a
-- record someone else made, and the only useful moment to say why is now.

create or replace function change_review_decision(
    p_finding_id  uuid,
    p_new_status  text,
    p_user_id     uuid,
    p_user_email  text,
    p_explanation text,
    p_reason      text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_old   text;
    v_note  text;
begin
    if p_new_status not in ('accepted', 'rejected') then
        raise exception 'Unknown status: %', p_new_status;
    end if;
    if coalesce(btrim(p_explanation), '') = '' then
        raise exception 'Se requiere una explicación para cambiar una decisión';
    end if;

    select review_status into v_old from findings_history
     where id = p_finding_id for update;
    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_old = p_new_status then
        raise exception 'La decisión ya es %', p_new_status;
    end if;

    v_note := concat('Cambiado de ', v_old, ' a ', p_new_status, ' por ',
                     p_user_email, ' el ',
                     to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI'),
                     ' UTC: ', btrim(p_explanation));

    -- Back to pending first so the watchlist side effects of the old decision
    -- are properly rolled back, then apply the new one. Doing it in one step
    -- would mean duplicating the rollback logic, which is the part most likely
    -- to drift out of agreement with itself.
    if v_old in ('accepted', 'rejected') then
        perform _undo_one_finding(p_finding_id, p_user_id, p_user_email,
                                  true, v_note);
    end if;

    if p_new_status = 'accepted' then
        perform _accept_one_finding(p_finding_id, p_user_id, p_user_email);
    else
        perform _reject_one_finding(p_finding_id, p_user_id, p_user_email,
                                    p_reason, null);
    end if;

    return jsonb_build_object('id', p_finding_id, 'from', v_old,
                              'to', p_new_status);
end;
$$;

grant execute on function change_review_decision(uuid, text, uuid, text, text, text)
    to authenticated;


-- ── 5. Verification ──────────────────────────────────────────────────────────
-- The important one: nothing should already be removed, and the active
-- counts should equal the totals on a database that has never used this.

do $$
declare
    v_m bigint; v_m_active bigint; v_c bigint; v_c_active bigint;
begin
    select count(*), count(*) filter (where removed_at is null)
      into v_m, v_m_active from watchlist_merchants;
    select count(*), count(*) filter (where removed_at is null)
      into v_c, v_c_active from watchlist_cards;
    raise notice 'comercios en watchlist: % (% activos)', v_m, v_m_active;
    raise notice 'tarjetas en watchlist: % (% activas)', v_c, v_c_active;
    raise notice 'Recuerda: los tres cargadores del motor ahora filtran '
                 'removed_at is null (runner, api y desktop).';
end $$;

-- ==========================================================================
-- 0015_explicit_grants.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- 0015 — access control hardening
--
-- Closes three findings from the 2026-09-09 audit. They are ONE change, not
-- three: fix 2 (identity from the JWT) depends on fix 1 (anon cannot call the
-- RPCs at all), because the JWT fallback for the runner is what an anonymous
-- caller would otherwise ride in on.
--
-- Read before running. Section 3 changes who can SELECT; if anyone signs in
-- with a non-cubopago.com address today, they lose access the moment this
-- lands. That is the point, but know it before you paste it.
--
-- Idempotent. Safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. RPCs stop being callable without a login ──────────────────────────────
-- Postgres grants EXECUTE to PUBLIC on every new function, and Supabase's
-- default privileges additionally grant it to anon. Neither was revoked, so
-- every SECURITY DEFINER function in this schema — including the ones that
-- WRITE — has been callable with nothing but the anon key, which ships inside
-- the published .exe. finish_runner_cycle (migration 0012) is the only one
-- that revoked, and it is the only one an anonymous caller cannot reach.
--
-- Revoke from everyone, then grant back deliberately.

do $$
declare r record;
begin
    for r in
        select p.oid::regprocedure as sig
          from pg_proc p
          join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public'
           and p.prokind = 'f'
    loop
        execute format('revoke all on function %s from public', r.sig);
        execute format('revoke all on function %s from anon', r.sig);
    end loop;
end $$;

do $$
declare
    r record;
    -- Called by the desktop app and the web app under a user's JWT.
    app_fns text[] := array[
        'review_findings',
        'review_stats',
        'change_review_decision',
        'set_watchlist_merchant_removed',
        'set_watchlist_card_removed',
        'deactivate_indicator',
        'record_indicator_hits',
        'runner_health'
    ];
    -- Called by the runner on the Pi with the service-role key.
    runner_fns text[] := array[
        'lookup_open_finding',
        'touch_finding',
        'reopen_finding',
        'record_indicator_hits',
        'finish_runner_cycle',
        'review_findings'
    ];
begin
    for r in
        select p.oid::regprocedure as sig
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.proname = any(app_fns)
    loop
        execute format('grant execute on function %s to authenticated', r.sig);
    end loop;

    for r in
        select p.oid::regprocedure as sig
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.proname = any(runner_fns)
    loop
        execute format('grant execute on function %s to service_role', r.sig);
    end loop;
end $$;

-- The _accept/_reject/_undo helpers are deliberately absent from both lists.
-- They are only ever called from inside the SECURITY DEFINER entry points,
-- which run as the function owner, so the owner's own rights cover them. No
-- client needs to reach them directly, and until now every client could.


-- ── 2. Who did it comes from the token, not from the caller ──────────────────
-- Every write RPC took p_user_id and p_user_email as arguments and wrote them
-- into the audit columns verbatim. Any caller could therefore attribute a
-- decision to any colleague. The columns are the record that backs a fraud
-- call if it is ever questioned, so they have to come from the session.
--
-- auth.uid() is null when the runner calls in with the service-role key, so
-- the passed-in value stays as the fallback for exactly that case. With
-- section 1 applied, no anonymous caller can reach this fallback.

create or replace function review_findings(
    p_finding_ids uuid[],
    p_action      text,
    p_user_id     uuid,
    p_user_email  text,
    p_reason      text default null,
    p_note        text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_id      uuid;
    v_one     jsonb;
    v_results jsonb := '[]'::jsonb;
    v_uid     uuid;
    v_email   text;
begin
    if p_action not in ('accept', 'reject', 'undo') then
        raise exception 'Unknown action: %', p_action;
    end if;

    v_uid   := coalesce(auth.uid(), p_user_id);
    v_email := coalesce(nullif(lower(auth.jwt() ->> 'email'), ''), p_user_email);

    if auth.uid() is not null
       and split_part(lower(coalesce(auth.jwt() ->> 'email', '')), '@', 2)
           <> 'cubopago.com' then
        raise exception 'Dominio de correo no autorizado';
    end if;

    foreach v_id in array p_finding_ids
    loop
        begin
            if p_action = 'accept' then
                v_one := _accept_one_finding(v_id, v_uid, v_email);
            elsif p_action = 'reject' then
                v_one := _reject_one_finding(v_id, v_uid, v_email,
                                             p_reason, p_note);
            else
                v_one := _undo_one_finding(v_id, v_uid, v_email);
            end if;
            v_results := v_results || jsonb_build_array(
                jsonb_build_object('id', v_id, 'ok', true, 'result', v_one)
            );
        exception when others then
            v_results := v_results || jsonb_build_array(
                jsonb_build_object('id', v_id, 'ok', false, 'error', sqlerrm)
            );
        end;
    end loop;

    return v_results;
end;
$$;

create or replace function change_review_decision(
    p_finding_id  uuid,
    p_new_status  text,
    p_user_id     uuid,
    p_user_email  text,
    p_explanation text,
    p_reason      text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_old   text;
    v_note  text;
    v_uid   uuid;
    v_email text;
begin
    if p_new_status not in ('accepted', 'rejected') then
        raise exception 'Unknown status: %', p_new_status;
    end if;
    if coalesce(btrim(p_explanation), '') = '' then
        raise exception 'Se requiere una explicación para cambiar una decisión';
    end if;

    v_uid   := coalesce(auth.uid(), p_user_id);
    v_email := coalesce(nullif(lower(auth.jwt() ->> 'email'), ''), p_user_email);

    select review_status into v_old from findings_history
     where id = p_finding_id for update;
    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_old = p_new_status then
        raise exception 'La decisión ya es %', p_new_status;
    end if;

    v_note := concat('Cambiado de ', v_old, ' a ', p_new_status, ' por ',
                     v_email, ' el ',
                     to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI'),
                     ' UTC: ', btrim(p_explanation));

    if v_old in ('accepted', 'rejected') then
        perform _undo_one_finding(p_finding_id, v_uid, v_email, true, v_note);
    end if;

    if p_new_status = 'accepted' then
        perform _accept_one_finding(p_finding_id, v_uid, v_email);
    else
        perform _reject_one_finding(p_finding_id, v_uid, v_email, p_reason, null);
    end if;

    return jsonb_build_object('id', p_finding_id, 'from', v_old,
                              'to', p_new_status);
end;
$$;

create or replace function set_watchlist_merchant_removed(
    p_company_name text,
    p_removed      boolean,
    p_user_email   text,
    p_reason       text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_found boolean;
    v_email text;
begin
    if p_removed and coalesce(btrim(p_reason), '') = '' then
        raise exception 'Se requiere un motivo para retirar un comercio de la watchlist';
    end if;

    v_email := coalesce(nullif(lower(auth.jwt() ->> 'email'), ''), p_user_email);

    perform set_config('app.skip_auto_bump', 'true', true);

    update watchlist_merchants set
        removed_at     = case when p_removed then now() else null end,
        removed_by     = case when p_removed then v_email else null end,
        removed_reason = case when p_removed then btrim(p_reason) else null end,
        updated_at     = now()
    where company_name = p_company_name;

    get diagnostics v_found = row_count;
    if not v_found then
        raise exception 'Merchant % is not on the watchlist', p_company_name;
    end if;

    return jsonb_build_object('company_name', p_company_name,
                              'removed', p_removed);
end;
$$;

create or replace function set_watchlist_card_removed(
    p_bin        text,
    p_last4      text,
    p_removed    boolean,
    p_user_email text,
    p_reason     text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_found boolean;
    v_email text;
begin
    if p_removed and coalesce(btrim(p_reason), '') = '' then
        raise exception 'Se requiere un motivo para retirar una tarjeta';
    end if;

    v_email := coalesce(nullif(lower(auth.jwt() ->> 'email'), ''), p_user_email);

    perform set_config('app.skip_auto_bump', 'true', true);

    update watchlist_cards set
        removed_at     = case when p_removed then now() else null end,
        removed_by     = case when p_removed then v_email else null end,
        removed_reason = case when p_removed then btrim(p_reason) else null end,
        updated_at     = now()
    where bin = p_bin and last4 = p_last4;

    get diagnostics v_found = row_count;
    if not v_found then
        raise exception 'Card %-% is not on the watchlist', p_bin, p_last4;
    end if;

    return jsonb_build_object('card', p_bin || '-' || p_last4,
                              'removed', p_removed);
end;
$$;

create or replace function deactivate_indicator(
    p_indicator_id uuid,
    p_user_email   text,
    p_reason       text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row   fraud_indicators%rowtype;
    v_email text;
begin
    v_email := coalesce(nullif(lower(auth.jwt() ->> 'email'), ''), p_user_email);

    select * into v_row from fraud_indicators where id = p_indicator_id for update;
    if not found then
        raise exception 'Indicator % not found', p_indicator_id;
    end if;

    update fraud_indicators
       set active = false,
           notes  = concat_ws(' | ',
                        nullif(notes, ''),
                        concat('Desactivado por ', v_email,
                               case when p_reason is not null and p_reason <> ''
                                    then concat(': ', p_reason) else '' end))
     where id = p_indicator_id;

    return jsonb_build_object('id', p_indicator_id, 'active', false);
end;
$$;

-- Re-grant: create or replace on an existing function keeps its ACL, but a
-- signature that was dropped and recreated would not. Cheap to be sure.
grant execute on function review_findings(uuid[], text, uuid, text, text, text)
    to authenticated, service_role;
grant execute on function change_review_decision(uuid, text, uuid, text, text, text)
    to authenticated;
grant execute on function set_watchlist_merchant_removed(text, boolean, text, text)
    to authenticated;
grant execute on function set_watchlist_card_removed(text, text, boolean, text, text)
    to authenticated;
grant execute on function deactivate_indicator(uuid, text, text)
    to authenticated;


-- ── 3. Reading the data requires a cubopago.com address ──────────────────────
-- The SELECT policies were `using (true)` for any authenticated role, so the
-- @cubopago.com restriction existed only in the desktop app, the Next.js
-- middleware and the Python API — all of which run after Supabase has already
-- minted the session. Migration 0005 already applies this predicate to the
-- INSERT policies; the SELECT side never got it.

do $$
declare
    t text;
    tables text[] := array['analysis_runs', 'findings_history',
                           'watchlist_merchants', 'watchlist_cards',
                           'fraud_indicators', 'runner_cycles'];
    pol text;
begin
    foreach t in array tables loop
        for pol in
            select policyname from pg_policies
             where schemaname = 'public' and tablename = t and cmd = 'SELECT'
        loop
            execute format('drop policy %I on %I', pol, t);
        end loop;

        execute format($f$
            create policy "cubo_read_%1$s" on %1$I
                for select to authenticated
                using (split_part(lower(coalesce(auth.jwt() ->> 'email', '')),
                                  '@', 2) = 'cubopago.com')
        $f$, t);
    end loop;
end $$;


-- ── 4. Verification ──────────────────────────────────────────────────────────
-- Every row should read "no". If any says "yes", the revoke above missed it.

select p.proname,
       case when has_function_privilege('anon', p.oid, 'execute')
            then 'yes — STILL OPEN' else 'no' end as anon_can_execute
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and p.prokind = 'f'
 order by 2 desc, 1;

-- ==========================================================================
-- 0016_service_role_grants.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- 0015b — top-up grants for service_role
--
-- 0015 revoked EXECUTE from public and anon across the schema, then granted
-- back from a list built off the migrations. Three functions the runner and
-- the Vercel API actually call were not on that list:
--
--   runner_health             called by the runner AND the desktop app
--   touch_watchlist_merchant  called by the runner, on neither list
--   deactivate_indicator      called by the app AND the Vercel API
--
-- Whether they are actually broken depends on whether service_role held its
-- own grant or was riding on PUBLIC. Section 2 below answers that. Either
-- way these grants are correct and idempotent, so run this first and read
-- the diagnostic afterwards.
--
-- Safe to re-run. Grants only — nothing is revoked here.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Grant every function its real callers need ────────────────────────────
-- Derived from the call sites this time, not from the migrations:
--   runner/supabase_io.py   sb_rpc(...)      → service_role
--   api/*.py                'rpc/...'        → service_role
--   desktop/src, app/       supabase.rpc(...) → authenticated

do $$
declare
    r record;
    -- Everything reached with the service-role key: the Pi runner and the
    -- three Vercel Python functions.
    service_fns text[] := array[
        'lookup_open_finding',
        'touch_finding',
        'touch_watchlist_merchant',
        'reopen_finding',
        'record_indicator_hits',
        'finish_runner_cycle',
        'runner_health',
        'review_findings',
        'deactivate_indicator'
    ];
    -- Everything reached under a user's JWT from either client.
    app_fns text[] := array[
        'review_findings',
        'review_stats',
        'change_review_decision',
        'set_watchlist_merchant_removed',
        'set_watchlist_card_removed',
        'deactivate_indicator',
        'record_indicator_hits',
        'runner_health'
    ];
begin
    for r in
        select p.oid::regprocedure as sig
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.proname = any(service_fns)
    loop
        execute format('grant execute on function %s to service_role', r.sig);
    end loop;

    for r in
        select p.oid::regprocedure as sig
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.proname = any(app_fns)
    loop
        execute format('grant execute on function %s to authenticated', r.sig);
    end loop;
end $$;


-- ── 2. Diagnostic ────────────────────────────────────────────────────────────
-- What to look for, in order of importance:
--
--   anon        must be false on EVERY row. This is the critical fix holding.
--   service_role must be true on the nine functions listed above.
--   authenticated must be true on the eight the apps call.
--
-- Anything else in this list — the _accept/_reject/_undo helpers, the bump_*
-- and set_indicator_value_norm trigger functions — should read false for all
-- three roles. That is correct: the helpers run inside SECURITY DEFINER
-- entry points as the function owner, and trigger functions are privilege-
-- checked when the trigger is created, not each time it fires.

select p.proname                                              as function,
       has_function_privilege('anon',          p.oid, 'execute') as anon,
       has_function_privilege('authenticated', p.oid, 'execute') as authenticated,
       has_function_privilege('service_role',  p.oid, 'execute') as service_role
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public'
   and p.prokind = 'f'
 order by anon desc, p.proname;

-- ==========================================================================
-- 0017_authenticated_grants.sql
-- ==========================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- 0015c — close the same hole for `authenticated`
--
-- 0015 revoked EXECUTE from public and anon. It did not revoke from
-- authenticated, and Supabase's default privileges grant that role EXECUTE
-- explicitly, so it kept access to everything — including the internal
-- helpers and the runner-only functions.
--
-- Why that matters: PostgREST exposes every function in the `public` schema.
-- A leading underscore is not privacy. So a signed-in analyst could bypass
-- the identity hardening in 0015 by calling the helper directly:
--
--     POST /rest/v1/rpc/_reject_one_finding
--     {"p_finding_id":"…","p_user_id":"<colleague>","p_user_email":"<colleague>"}
--
-- and _reject_one_finding writes those straight into the audit columns.
-- touch_finding is worse: it takes p_payload, so any authenticated user
-- could rewrite the evidence and risk score of any finding.
--
-- After this, `authenticated` can execute exactly the eight functions the
-- desktop and web apps call, and nothing else.
--
-- Idempotent. Safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Revoke from authenticated, then grant back the eight ──────────────────

do $$
declare
    r record;
    app_fns text[] := array[
        'review_findings',
        'review_stats',
        'change_review_decision',
        'set_watchlist_merchant_removed',
        'set_watchlist_card_removed',
        'deactivate_indicator',
        'record_indicator_hits',
        'runner_health'
    ];
begin
    for r in
        select p.oid::regprocedure as sig
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.prokind = 'f'
    loop
        execute format('revoke all on function %s from authenticated', r.sig);
    end loop;

    for r in
        select p.oid::regprocedure as sig
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.proname = any(app_fns)
    loop
        execute format('grant execute on function %s to authenticated', r.sig);
    end loop;
end $$;

-- The helpers stay revoked from every client role and still work: they are
-- called from inside SECURITY DEFINER entry points, which execute as the
-- function owner. Same for the trigger functions — PostgreSQL checks EXECUTE
-- when a trigger is CREATED, not each time it fires.


-- ── 2. Belt and braces on the helpers themselves ─────────────────────────────
-- Even reached directly, they should not accept a caller's word for who is
-- acting. A JWT identity overrides the argument; the argument survives only
-- for the runner, which has no JWT.

create or replace function _reject_one_finding(
    p_finding_id uuid,
    p_user_id    uuid,
    p_user_email text,
    p_reason     text default null,
    p_note       text default null
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_status text;
    v_uid    uuid;
    v_email  text;
begin
    v_uid   := coalesce(auth.uid(), p_user_id);
    v_email := coalesce(nullif(lower(auth.jwt() ->> 'email'), ''), p_user_email);

    select review_status into v_status
        from findings_history
        where id = p_finding_id
        for update;
    if not found then
        raise exception 'Finding % not found', p_finding_id;
    end if;
    if v_status <> 'pending' then
        raise exception 'Finding % already reviewed (status=%)', p_finding_id, v_status;
    end if;

    update findings_history set
        review_status       = 'rejected',
        reviewed_at         = now(),
        reviewed_by_email   = v_email,
        reviewed_by_user_id = v_uid,
        review_reason       = nullif(p_reason, ''),
        review_notes        = concat_ws(' | ',
            nullif(review_notes, ''),
            nullif(p_note, ''))
    where id = p_finding_id;

    return jsonb_build_object('status', 'rejected', 'reason', p_reason);
end;
$$;


-- ── 3. Diagnostic ────────────────────────────────────────────────────────────
-- Expected: anon false everywhere; authenticated true on EXACTLY the eight
-- app functions; service_role true on the nine the runner and the Vercel
-- functions call. Everything else false for all three.

select p.proname                                                 as function,
       has_function_privilege('anon',          p.oid, 'execute') as anon,
       has_function_privilege('authenticated', p.oid, 'execute') as authenticated,
       has_function_privilege('service_role',  p.oid, 'execute') as service_role
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public'
   and p.prokind = 'f'
 order by authenticated desc, p.proname;
