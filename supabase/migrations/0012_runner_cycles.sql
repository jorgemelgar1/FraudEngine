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
