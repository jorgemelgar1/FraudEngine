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
