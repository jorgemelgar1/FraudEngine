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
