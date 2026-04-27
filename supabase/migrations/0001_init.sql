-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — initial schema
-- Paste this entire file into the Supabase SQL Editor and run it once.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. analysis_runs — audit log: one row per CSV processed
create table if not exists analysis_runs (
    id                       uuid        primary key default gen_random_uuid(),
    run_at                   timestamptz not null    default now(),
    run_by_email             text,
    run_by_user_id           uuid        references auth.users(id),
    csv_filename             text,
    csv_date_start           date,
    csv_date_end             date,
    total_rows               integer,
    unique_transactions      integer,
    critical_findings_count  integer,
    monitor_findings_count   integer,
    chargeback_exposure_usd  numeric(12,2),
    summary                  jsonb
);

create index if not exists analysis_runs_run_at_idx on analysis_runs (run_at desc);
create index if not exists analysis_runs_user_idx   on analysis_runs (run_by_user_id);


-- 2. watchlist_merchants — permanent (never pruned)
create table if not exists watchlist_merchants (
    company_name      text        primary key,
    company_id        text,
    first_flagged     timestamptz not null,
    last_flagged      timestamptz not null,
    flag_count        integer     not null default 1,
    last_risk_score   integer,
    last_run_id       uuid        references analysis_runs(id),
    notes             text,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

create index if not exists watchlist_merchants_last_flagged_idx on watchlist_merchants (last_flagged desc);
create index if not exists watchlist_merchants_flag_count_idx   on watchlist_merchants (flag_count desc);


-- 3. watchlist_cards — permanent (never pruned, per policy)
create table if not exists watchlist_cards (
    bin               text        not null,
    last4             text        not null,
    card_key          text        generated always as (bin || '-' || last4) stored,
    first_flagged     timestamptz not null,
    last_flagged      timestamptz not null,
    flag_count        integer     not null default 1,
    last_run_id       uuid        references analysis_runs(id),
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    primary key (bin, last4)
);

create index if not exists watchlist_cards_last_flagged_idx on watchlist_cards (last_flagged desc);
create index if not exists watchlist_cards_bin_idx          on watchlist_cards (bin);


-- 4. findings_history — every Critical/Monitor finding ever produced
create table if not exists findings_history (
    id                       uuid        primary key default gen_random_uuid(),
    run_id                   uuid        not null references analysis_runs(id) on delete cascade,
    company_name             text        not null,
    company_id               text,
    finding_type             text        not null,
    confidence               text        not null,
    risk_score               integer     not null,
    fingerprints             text[]      not null,
    action_code              text,
    chargeback_exposure_usd  numeric(12,2),
    description_es           text,
    payload                  jsonb       not null
);

create index if not exists findings_history_company_idx      on findings_history (company_name);
create index if not exists findings_history_run_idx          on findings_history (run_id);
create index if not exists findings_history_fingerprints_gin on findings_history using gin (fingerprints);


-- ─────────────────────────────────────────────────────────────────────────────
-- Row Level Security
-- The Python function uses the SERVICE ROLE KEY which bypasses RLS entirely.
-- These policies govern what end users (browser sessions) can see.
-- ─────────────────────────────────────────────────────────────────────────────

alter table analysis_runs        enable row level security;
alter table watchlist_merchants  enable row level security;
alter table watchlist_cards      enable row level security;
alter table findings_history     enable row level security;

drop policy if exists "auth_read_runs"       on analysis_runs;
drop policy if exists "auth_read_merchants"  on watchlist_merchants;
drop policy if exists "auth_read_cards"      on watchlist_cards;
drop policy if exists "auth_read_findings"   on findings_history;

create policy "auth_read_runs"       on analysis_runs       for select to authenticated using (true);
create policy "auth_read_merchants"  on watchlist_merchants for select to authenticated using (true);
create policy "auth_read_cards"      on watchlist_cards     for select to authenticated using (true);
create policy "auth_read_findings"   on findings_history    for select to authenticated using (true);
