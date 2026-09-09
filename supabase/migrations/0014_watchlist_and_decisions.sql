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
