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
