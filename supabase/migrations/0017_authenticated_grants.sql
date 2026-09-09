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
