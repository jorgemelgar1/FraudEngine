-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — watchlist trigger hardening (run after 0001_init.sql)
--
-- Two correctness issues addressed by this migration:
--
--   1. flag_count race condition.  Two concurrent uploads both load
--      flag_count = N, both bump to N+1 in memory, both upsert N+1 →
--      final value is N+1 instead of N+2. Moving the increment into a
--      BEFORE UPDATE trigger makes it atomic at the SQL level.
--
--   2. updated_at and first_flagged drift.  The Python upsert payload
--      doesn't (and shouldn't) try to preserve these — first_flagged
--      should never change after the row's first INSERT, and updated_at
--      should advance on every mutation. Triggers handle both invariants
--      in one place.
--
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- It's idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────

-- Trigger function for watchlist_merchants.
create or replace function bump_watchlist_merchant() returns trigger as $$
begin
    -- Atomic increment regardless of what the upsert payload claimed.
    new.flag_count    = old.flag_count + 1;
    -- Preserve the original creation/first-flagged timestamps across upserts.
    new.first_flagged = old.first_flagged;
    new.created_at    = old.created_at;
    -- Always advance updated_at on any mutation.
    new.updated_at    = now();
    -- last_flagged, last_risk_score, last_run_id, company_id, notes are
    -- intentionally taken from NEW (i.e., the upsert payload).
    return new;
end;
$$ language plpgsql;

drop trigger if exists watchlist_merchants_bump on watchlist_merchants;
create trigger watchlist_merchants_bump
    before update on watchlist_merchants
    for each row execute function bump_watchlist_merchant();


-- Trigger function for watchlist_cards. Same logic, fewer columns.
create or replace function bump_watchlist_card() returns trigger as $$
begin
    new.flag_count    = old.flag_count + 1;
    new.first_flagged = old.first_flagged;
    new.created_at    = old.created_at;
    new.updated_at    = now();
    -- last_flagged, last_run_id come from NEW.
    return new;
end;
$$ language plpgsql;

drop trigger if exists watchlist_cards_bump on watchlist_cards;
create trigger watchlist_cards_bump
    before update on watchlist_cards
    for each row execute function bump_watchlist_card();
