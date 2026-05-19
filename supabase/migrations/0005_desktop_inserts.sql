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
