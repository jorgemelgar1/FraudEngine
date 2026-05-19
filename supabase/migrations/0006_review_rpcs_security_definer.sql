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
