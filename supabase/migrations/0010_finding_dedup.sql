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
