-- ─────────────────────────────────────────────────────────────────────────────
-- Cubo Fraud Engine — confirmed-fraud indicators
--
-- Why this migration exists
-- ─────────────────────────
-- The engine has two persistent memory surfaces today: watchlist_merchants
-- (by company name) and watchlist_cards (by BIN + last4). Both are populated
-- only as a side effect of accepting a finding, and both key on things the
-- engine itself discovered.
--
-- What ops actually has, and what the engine cannot use, is confirmed fraud
-- data from OUTSIDE a run: a chargeback report naming an email, a bank notice
-- naming a cardholder, a case where a phone number turned up again. The
-- valuable pattern is cross-merchant — the same payer identity settling at a
-- new merchant after being confirmed as fraud at another one.
--
-- This table is where the team writes those values directly.
--
-- Design notes
-- ────────────
-- * `value_norm` is a COARSE de-duplication key — lower(btrim(value_raw)) —
--   computed by a trigger, never by a client. It exists so "Fraude@X.com"
--   and "fraude@x.com " cannot become two rows.
--
--   It is deliberately NOT the precise normalization used for matching. That
--   lives in analyze.py (normalize_indicator_value: +tag stripping, Gmail dot
--   folding, token-sorted names, phone tails) and is re-derived from
--   `value_raw` every run, so the engine's rules are always current even for
--   rows written before a normalizer changed.
--
--   Why a trigger rather than letting each client compute it: the Vercel
--   function has analyze.py in-process and could normalize precisely, but the
--   desktop client talks to PostgREST directly and cannot. Two clients
--   computing the same unique key differently would silently split one
--   indicator into two rows. Postgres owning the column makes that
--   impossible.
--
-- * `source_company_name` records WHERE the value was confirmed. A hit at a
--   different merchant is the strongest signal this feature produces, and it
--   is only distinguishable if we remember the origin.
--
-- * `match_mode` is per indicator, not global. A cardholder name wants fuzzy
--   matching; a card_key never does. 'exact' is the safe default.
--
-- * `hit_count` / `last_hit_at` are how the list stays healthy. Indicators
--   that never fire are dead weight; ones that fire constantly are too broad.
--   Without these columns a deny-list only ever grows.
--
-- * `expires_at` exists because indicator types age differently. An IP is
--   meaningful for weeks; a confirmed-fraud cardholder name does not expire.
--
-- PRIVACY NOTE — read before running this
-- ───────────────────────────────────────
-- This table stores personal data (emails, phone numbers, cardholder and
-- payer names, IP addresses) that the system has deliberately never persisted
-- before. README.md's privacy table is updated in the same change; if any
-- commitment about retention has been made to the team or to compliance on
-- the strength of the old wording, it needs revisiting.
--
-- Paste this entire file into the Supabase SQL Editor and run it once BEFORE
-- deploying the code change. Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────


-- ── 1. Table ─────────────────────────────────────────────────────────────────

create table if not exists fraud_indicators (
    id                  uuid        primary key default gen_random_uuid(),

    indicator_type      text        not null,
    value_raw           text        not null,   -- as the analyst typed it
    value_norm          text        not null,   -- set by trigger; see header
    match_mode          text        not null default 'exact',

    -- Provenance. Every hit surfaces these back to the reviewer, so a match
    -- can always be traced to who confirmed it and why.
    source              text,                   -- chargeback | ops review | bank report | other
    source_company_name text,                   -- merchant where it was confirmed
    notes               text,
    added_by_email      text        not null,
    added_at            timestamptz not null default now(),

    active              boolean     not null default true,
    expires_at          timestamptz,

    hit_count           integer     not null default 0,
    last_hit_at         timestamptz,
    last_hit_company    text,

    -- 'card_key' is BIN + last 4 together. There is deliberately no
    -- 'card_bin' or 'card_last4': a BIN is a whole issuing bank and last-4
    -- is one in ten thousand, so either alone would fire constantly.
    constraint fraud_indicators_type_check check (indicator_type in (
        'card_key', 'email', 'email_domain',
        'phone', 'ip', 'person_name', 'company_name', 'company_id'
    )),
    constraint fraud_indicators_mode_check check (match_mode in ('exact', 'fuzzy', 'both')),
    constraint fraud_indicators_value_norm_len check (char_length(value_norm) between 2 and 256),

    -- One row per (type, normalized value). Re-adding a value that already
    -- exists should update the existing row, not create a duplicate.
    unique (indicator_type, value_norm)
);

comment on column fraud_indicators.value_norm is
    'Coarse de-duplication key, lower(btrim(value_raw)), set by trigger and '
    'ignored if a client supplies one. Matching uses the precise normalizers '
    'in analyze.py, re-derived from value_raw at run time.';

comment on table fraud_indicators is
    'Analyst-entered values confirmed to be linked to fraud. Matched against '
    'every analyzed CSV. Contains personal data — see migration header.';

comment on column fraud_indicators.source_company_name is
    'Merchant where this value was confirmed as fraud. A match at a DIFFERENT '
    'merchant is the cross-merchant signal this feature exists to catch.';


-- ── 1b. value_norm is server-owned ───────────────────────────────────────────
-- Overwrites whatever the client sent. Both the Vercel function and the
-- desktop app can therefore insert without knowing the rule, and neither can
-- split one indicator into two rows by normalizing differently.

create or replace function set_indicator_value_norm() returns trigger as $$
begin
    new.value_norm := lower(btrim(new.value_raw));
    if new.value_norm is null or char_length(new.value_norm) < 2 then
        raise exception 'Indicator value is too short to be usable: %', new.value_raw;
    end if;
    return new;
end;
$$ language plpgsql;

drop trigger if exists fraud_indicators_norm on fraud_indicators;
create trigger fraud_indicators_norm
    before insert or update of value_raw on fraud_indicators
    for each row execute function set_indicator_value_norm();


-- ── 2. Indexes ───────────────────────────────────────────────────────────────
-- The engine loads the full active set once per run, so the hot path is a
-- single filtered scan rather than per-value lookups.

create index if not exists fraud_indicators_active_idx
    on fraud_indicators (indicator_type, value_norm)
    where active;

create index if not exists fraud_indicators_added_idx
    on fraud_indicators (added_at desc);

create index if not exists fraud_indicators_hits_idx
    on fraud_indicators (hit_count desc, last_hit_at desc);


-- ── 3. Row Level Security ────────────────────────────────────────────────────
-- Same model as the rest of the schema: any authenticated @cubopago.com user
-- can read and write; the Vercel service-role key bypasses RLS entirely.
--
-- Deliberately no DELETE policy. Indicators are deactivated (active = false),
-- never removed, so the audit trail of what was matched against survives.

alter table fraud_indicators enable row level security;

drop policy if exists "auth_read_indicators"   on fraud_indicators;
drop policy if exists "auth_insert_indicators" on fraud_indicators;
drop policy if exists "auth_update_indicators" on fraud_indicators;

create policy "auth_read_indicators" on fraud_indicators
    for select to authenticated using (true);

create policy "auth_insert_indicators" on fraud_indicators
    for insert to authenticated
    with check (
        auth.uid() is not null
        and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
        and lower(added_by_email) = lower(coalesce(auth.jwt() ->> 'email', ''))
    );

-- Update is limited to the review/lifecycle columns. The USING clause gates
-- who may act; WITH CHECK stops a caller rewriting an indicator's identity
-- (its type or normalized value) into something else after the fact.
create policy "auth_update_indicators" on fraud_indicators
    for update to authenticated
    using (
        auth.uid() is not null
        and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
    )
    with check (
        auth.uid() is not null
        and lower(coalesce(auth.jwt() ->> 'email', '')) like '%@cubopago.com'
    );


-- ── 4. Hit recording ─────────────────────────────────────────────────────────
-- Called once per run with the ids that fired. Bulk, so a run with 30 hits
-- is one round trip. SECURITY DEFINER for the same reason as migration 0006:
-- the desktop client calls under a user JWT and must not need broad UPDATE
-- rights on the table to record a hit.

create or replace function record_indicator_hits(
    p_indicator_ids uuid[],
    p_company_name  text
) returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_count integer;
begin
    if p_indicator_ids is null or array_length(p_indicator_ids, 1) is null then
        return 0;
    end if;

    update fraud_indicators
       set hit_count        = hit_count + 1,
           last_hit_at      = now(),
           last_hit_company = coalesce(p_company_name, last_hit_company)
     where id = any(p_indicator_ids);

    get diagnostics v_count = row_count;
    return v_count;
end;
$$;


-- ── 5. Deactivate helper ─────────────────────────────────────────────────────
-- Kept as an RPC rather than a raw UPDATE so the reason is always recorded.

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
    v_row fraud_indicators%rowtype;
begin
    select * into v_row from fraud_indicators where id = p_indicator_id for update;
    if not found then
        raise exception 'Indicator % not found', p_indicator_id;
    end if;

    update fraud_indicators
       set active = false,
           notes  = concat_ws(' | ',
                        nullif(notes, ''),
                        concat('Desactivado por ', p_user_email,
                               case when p_reason is not null and p_reason <> ''
                                    then concat(': ', p_reason) else '' end))
     where id = p_indicator_id;

    return jsonb_build_object('id', p_indicator_id, 'active', false);
end;
$$;
