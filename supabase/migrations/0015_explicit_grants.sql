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
