#!/usr/bin/env python3
"""
Cubo Pago Fraud Analysis — core analysis script.

Reads a Cubo transaction CSV export, detects the five fraud fingerprints,
scores findings, and emits a structured JSON report.

Usage:
  python analyze.py <csv_path>
  python analyze.py <csv_path> --watchlist assets/watchlist.json --output /tmp/findings.json
  python analyze.py <csv_path> --validate-only
  python analyze.py <csv_path> --update-watchlist assets/watchlist.json

Design notes:
- All rejection-code and fingerprint logic lives in the REJECTION_CODES and
  fingerprint functions.
- The script is tolerant of schema drift: it warns but does not fail on
  missing optional columns. Required columns are enforced.
- The analysis is deterministic — the same CSV produces the same findings.
"""

import argparse
import difflib
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import pandas as pd
import numpy as np


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = [
    'transaction_id', 'company_name', 'company_id', 'amount', 'status',
    'transaction_type', 'transaction_created_at', 'last_intent_at',
    'card_last_digits', 'bin_card_number', 'card_holder', 'card_brand',
    'rejection_reason', 'gateway_message', 'ip', 'authentication_type',
    'client_name', 'client_email', 'client_phone', 'country_name',
    'risk_score', 'ip_risk_score', 'card_country_mind_fraud',
]

OPTIONAL_COLUMNS = []

# ---------------------------------------------------------------------------
# Risk policy thresholds
# ---------------------------------------------------------------------------

# Any per-merchant or per-window rejection rate at or above this level is
# considered anomalous. Used by both the per-merchant high_reject_rate signal
# and the BIN-diversity burst detector so policy stays consistent.
REJECT_RATE_THRESHOLD = 0.30

# risk_score / ip_risk_score above this are escalated as highlights in the
# final report, independent of merchant-level scoring.
HIGH_RISK_SCORE_THRESHOLD = 90

# A merchant passing this many unique foreign cards within FOREIGN_CARD_WINDOW_HOURS
# is flagged as a foreign-card-velocity fraud indicator.
FOREIGN_CARD_COUNT_THRESHOLD = 5
FOREIGN_CARD_WINDOW_HOURS = 1


# ---------------------------------------------------------------------------
# Suspicious all-rejected merchants (no successful transactions)
# ---------------------------------------------------------------------------
#
# A dedicated, self-contained detector for merchants that NEVER settle a charge
# but show card-testing / stolen-card behavior across many rejected attempts.
#
# The legacy per-merchant risk model (score_merchant) is exposure-centric: it
# scores SUCCEEDED charges and estimates chargeback exposure. A merchant whose
# every attempt is rejected settles $0, so it scores ~0 and is invisible to the
# Critical/Monitor tiers — even when it is an obvious card-testing session
# (one device cycling many stolen cards under one or two identities).
#
# This detector runs INDEPENDENTLY. It has its own scoring, writes to its own
# report section ('suspicious_rejected_merchants'), and deliberately does NOT
# touch df_u, score_merchant, identify_test_transactions, the global rejection-
# code sets, the watchlist update, or the existing critical/monitor findings.
# Everything below is additive.
#
# It operates on an ATTEMPT-level view rebuilt locally from the raw CSV (one row
# per transaction_id + last_intent_at + card) so that bursts of distinct cards
# that the transaction_id-level dedupe collapses are visible here — without
# changing the global dedupe every other detector relies on.

# Terminal-status priority used to collapse a single attempt's
# DRAFT→PENDING→REJECTED/SUCCEEDED rows down to its final state.
_STATUS_RANK = {'SUCCEEDED': 4, 'REJECTED': 3, 'PENDING': 2, 'DRAFT': 1}

# Channels where the `ip` column is the cardholder's own device (LINK / QR /
# subscription / etc.). On POS the `ip` is the merchant's terminal, so per-IP
# card fan-out is normal retail and must NOT trigger the IP-based signals.
POS_CHANNELS = {'POS', 'POS-MSI'}

# Entry gate: a merchant only enters this section if it has at least this many
# attempts, settles at or below this success rate ("zero-settlement"), AND
# touches at least this many distinct cards. The distinct-card floor keeps a
# single customer retrying one blocked card out of the section (that is not
# card testing).
ZERO_SETTLEMENT_MIN_ATTEMPTS = 6
ZERO_SETTLEMENT_MAX_SUCCESS_RATE = 0.05
ZERO_SETTLEMENT_MIN_DISTINCT_CARDS = 2

# Card fan-out tiers: distinct cards within a rolling window, cardholder-side.
FANOUT_BURST_CARDS = 5                          # BIN-attack burst
FANOUT_BURST_WINDOW = np.timedelta64(5, 'm')
FANOUT_SESSION_CARDS = 3
FANOUT_SESSION_WINDOW = np.timedelta64(60, 'm')
FANOUT_SLOW_WINDOW = np.timedelta64(24, 'h')
FANOUT_PAIR_CARDS = 2
FANOUT_PAIR_WINDOW = np.timedelta64(30, 'm')

# Single IP submitting many distinct cards (cardholder-side channels only).
IP_MULTI_CARD_STRONG = 3
IP_MULTI_CARD_WEAK = 2

# Identity rotation: distinct cardholder names per payer (email), or distinct
# cards per cardholder name.
IDENTITY_ROTATION_COUNT = 3
# Near-duplicate cardholder-name similarity (difflib ratio) — catches hand-keyed
# variants like "Estuardo Corzo" / "Eduardo Cosa". Capped to keep the O(n²)
# pairwise comparison cheap (the per-merchant name set is tiny in practice).
NAME_SIMILARITY_RATIO = 0.80
NAME_SIMILARITY_MAX_NAMES = 50
# Near-duplicate BIN: same last4 + same holder, BINs differing by <= this many
# characters — a hallmark of hand-keyed card re-entry (e.g. 439093 / 409393).
BIN_NEAR_DUPLICATE_MAX_DIFF = 2

# Same rejection code repeated on a single card (card-not-present probing).
REPEAT_CODE_THRESHOLD = 4

# Distinct cards across the whole all-fail session (card / BIN diversity).
SESSION_CARD_DIVERSITY = 4

# Section score weights (capped at 100). Independent of score_merchant.
W_ZERO_SETTLEMENT    = 25   # base: passing the entry gate is itself a signal
W_FANOUT_BURST       = 40
W_FANOUT_SESSION     = 30
W_FANOUT_SLOW        = 20
W_FANOUT_PAIR        = 10
W_IP_MULTI_STRONG    = 25
W_IP_MULTI_WEAK      = 10
W_IDENTITY_ROTATION  = 20
W_NEAR_DUPLICATE     = 15
W_REPEAT_CODE        = 20
W_CARD_DIVERSITY     = 15
W_WATCHLIST_MERCHANT = 20
W_WATCHLIST_CARD     = 10

# Tiering within the section (mirrors the engine's >=70/>=40 idea but tuned to
# this section's weights). Zero-settlement alone (25) lands at Monitor; one
# strong escalation pushes it to Critical.
SECTION_CRITICAL_THRESHOLD = 50
SECTION_MONITOR_THRESHOLD = 25


# ---------------------------------------------------------------------------
# Rejection code severity
# ---------------------------------------------------------------------------

CRITICAL_CODES = {
    '05 - SOSPECHA DE FRAUDE',
    '63 - VIOLACIÓN DE SEGURIDAD',
    '43 - LLAMAR AL EMISOR',
    'SM - SOSPECHA DE FRAUDE',
    'SH - TRANSACCION NO PERMITIDA',
}

# Substring checks for MinFraud rules
MINFRAUD_SUBSTRING = 'MF: custom_rule'

# Monitor codes — mean nothing alone but escalate when combined
MONITOR_CODES = {
    '34 - LLAMAR AL EMISOR',
    '41 - LLAMAR AL EMISOR',
}

# Contactless placeholders — name rotation between these is NOT a signal
CONTACTLESS_PLACEHOLDERS = {
    'no-name', 'PAYWAVE/VISA', 'CARDHOLDER/VISA',
    'INNOMINADAS/VISA', 'INNOMINADAS/MASTERCARD',
    'KARTENINHABER/', '/', '',
}


# ---------------------------------------------------------------------------
# Currency
# ---------------------------------------------------------------------------
#
# Cubo CSVs are country-specific (one country per export), so the currency
# is a single value per file derived from the `country_name` column. There's
# no dedicated currency column in the export schema today; if one is added
# later, prefer that and treat this table as a fallback.
#
# Numeric format is the same en-US convention for every supported currency
# (comma thousands, dot decimals), so only the prefix changes between USD
# and GTQ. New countries are easy to add — keep the keys lowercased and
# accent-folded.

DEFAULT_CURRENCY = 'USD'

COUNTRY_TO_CURRENCY = {
    'panama':       'USD',
    'el salvador':  'USD',
    'guatemala':    'GTQ',
}


def _normalize_country(name: str) -> str:
    """Lower-case + accent-fold a country name for table lookup."""
    if not name:
        return ''
    name = name.lower().strip()
    for a, b in (('á', 'a'), ('é', 'e'), ('í', 'i'), ('ó', 'o'), ('ú', 'u')):
        name = name.replace(a, b)
    return name


def detect_currency(df_u, default: str = DEFAULT_CURRENCY) -> str:
    """Return the ISO currency code for this CSV. Uses the most-common
    non-null country_name value. Unknown country falls back to `default`."""
    if 'country_name' not in df_u.columns:
        return default
    countries = df_u['country_name'].dropna().astype(str).map(_normalize_country)
    countries = countries[countries != '']
    if countries.empty:
        return default
    top = countries.mode()
    if len(top) == 0:
        return default
    return COUNTRY_TO_CURRENCY.get(top.iloc[0], default)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def is_real_name(name):
    """True if card_holder looks like an actual embossed name, not a placeholder."""
    if pd.isna(name):
        return False
    s = str(name).strip()
    if s in CONTACTLESS_PLACEHOLDERS:
        return False
    # "JON/GUERRERO", "BISHOP/NANCY S", "Marianna Kuttothara" all count as real
    if len(s) < 3:
        return False
    # Treat things like "/" or just slashes as placeholders
    if set(s) <= {'/', ' '}:
        return False
    return True


def is_critical_code(reason):
    if pd.isna(reason):
        return False
    s = str(reason)
    if s in CRITICAL_CODES:
        return True
    return False


def is_minfraud_blocked(reason):
    if pd.isna(reason):
        return False
    return MINFRAUD_SUBSTRING in str(reason)


def is_monitor_code(reason):
    if pd.isna(reason):
        return False
    return str(reason) in MONITOR_CODES


def card_key(bin_num, last4):
    """Canonical identifier for a card (BIN + last 4)."""
    if pd.isna(bin_num) or pd.isna(last4):
        return None
    try:
        return f"{int(bin_num):06d}-{int(last4):04d}"
    except (ValueError, TypeError):
        return None


def velocity_ceiling(avg_ticket):
    """Return the tx/minute ceiling above which velocity is flagged."""
    if avg_ticket < 10:
        return 8
    elif avg_ticket < 50:
        return 5
    elif avg_ticket < 200:
        return 2
    else:
        return 1  # anything more than 1/min on >$200 tickets is suspicious


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def validate_schema(df):
    """Return (is_valid, missing_required, missing_optional)."""
    cols = set(df.columns)
    missing_required = [c for c in REQUIRED_COLUMNS if c not in cols]
    missing_optional = [c for c in OPTIONAL_COLUMNS if c not in cols]
    return len(missing_required) == 0, missing_required, missing_optional


# ---------------------------------------------------------------------------
# Load and dedupe
# ---------------------------------------------------------------------------

def _compute_card_keys(df):
    """Vectorized card_key computation. Returns a list aligned to df.index."""
    bins = pd.to_numeric(df['bin_card_number'], errors='coerce')
    last4s = pd.to_numeric(df['card_last_digits'], errors='coerce')
    return [
        f"{int(b):06d}-{int(l):04d}" if pd.notna(b) and pd.notna(l) else None
        for b, l in zip(bins, last4s)
    ]


def _read_csv_with_encoding_fallback(csv_path, **kwargs):
    # Excel-on-Windows saves CSV as cp1252 by default, not UTF-8. Retry on
    # UnicodeDecodeError so users don't have to re-export as "CSV UTF-8".
    try:
        return pd.read_csv(csv_path, **kwargs)
    except UnicodeDecodeError:
        return pd.read_csv(csv_path, encoding='cp1252', **kwargs)


def load_and_dedupe(csv_path):
    """
    Load the CSV and deduplicate to one row per transaction_id
    (keeping the final status transition).

    Schema is validated immediately after the CSV is parsed and before any
    columns are touched — otherwise a missing required column raises
    KeyError from inside pd.to_datetime instead of the friendly
    "Missing required columns" error.
    """
    df = _read_csv_with_encoding_fallback(csv_path, low_memory=False)
    ok, missing_req, _ = validate_schema(df)
    if not ok:
        raise ValueError(f"Missing required columns: {missing_req}")
    df['last_intent_at'] = pd.to_datetime(df['last_intent_at'], errors='coerce')
    df['transaction_created_at'] = pd.to_datetime(df['transaction_created_at'], errors='coerce')
    df = df.sort_values(['transaction_id', 'last_intent_at'])
    df_u = df.groupby('transaction_id').tail(1)
    # Sort globally by timestamp once so downstream detectors can skip re-sorting.
    df_u = df_u.sort_values('transaction_created_at', kind='stable').reset_index(drop=True)
    df_u['card_key'] = _compute_card_keys(df_u)
    return df, df_u


# ---------------------------------------------------------------------------
# Test transactions (≤ $1)
# ---------------------------------------------------------------------------

def identify_test_transactions(df_u):
    """
    Per Cubo policy:
    - Single ≤$1 transaction at a merchant → legitimate self-check, ignore.
    - 2+ ≤$1 transactions → treat as card testing (return True for all of them).
    - ≤$1 tx followed by larger charges within 10 min at same merchant → test-then-charge, suspicious
    Returns a Series (bool) indicating whether each row should be treated as suspicious test activity.
    """
    suspicious_tests = pd.Series(False, index=df_u.index)

    small = df_u[df_u['amount'] <= 1.0].copy()
    if len(small) == 0:
        return suspicious_tests

    # Count small tx per merchant
    per_merchant = small.groupby('company_name').size()
    merchants_with_multi = per_merchant[per_merchant >= 2].index.tolist()

    # Flag all small tx at merchants with 2+ tests
    mask_multi = (df_u['amount'] <= 1.0) & (df_u['company_name'].isin(merchants_with_multi))
    suspicious_tests = suspicious_tests | mask_multi

    # Test-then-charge within 10 minutes
    for mname, group in df_u.groupby('company_name'):
        group = group.sort_values('transaction_created_at')
        small_tx = group[group['amount'] <= 1.0]
        for _, test_row in small_tx.iterrows():
            t0 = test_row['transaction_created_at']
            if pd.isna(t0):
                continue
            followup = group[
                (group['amount'] > 1.0) &
                (group['transaction_created_at'] > t0) &
                (group['transaction_created_at'] <= t0 + timedelta(minutes=10))
            ]
            if len(followup) > 0:
                suspicious_tests.loc[test_row.name] = True

    return suspicious_tests


# ---------------------------------------------------------------------------
# Fingerprint detectors
# ---------------------------------------------------------------------------

def detect_amount_ladder(group):
    """
    Return True if any SINGLE card (same BIN + last4) at this merchant shows
    3+ consecutive monotonic attempts (ascending or descending) within 20 min.

    Scoping by card is what makes the signal specific: unrelated customers
    producing a coincidentally-monotonic amount sequence at the same merchant
    is normal business noise. The same card being probed up or down the
    amount axis is card-testing behavior.

    Rejections are not required — an all-SUCCEEDED ladder on one card is
    still a strong card-testing indicator.
    """
    # Only consider rows with an identifiable card_key
    g = group[group['card_key'].notna()] if 'card_key' in group.columns else group
    if len(g) < 3:
        return False

    for _, card_group in g.groupby('card_key'):
        if len(card_group) < 3:
            continue
        card_group = card_group.sort_values('transaction_created_at').reset_index(drop=True)
        amounts = card_group['amount'].tolist()
        times = card_group['transaction_created_at'].tolist()
        for i in range(len(amounts) - 2):
            window = amounts[i:i + 3]
            tw = times[i:i + 3]
            if any(pd.isna(t) for t in tw):
                continue
            if (tw[-1] - tw[0]).total_seconds() > 20 * 60:
                continue
            is_desc = all(window[j] >= window[j + 1] for j in range(2))
            is_asc = all(window[j] <= window[j + 1] for j in range(2))
            if (is_desc or is_asc) and len(set(window)) > 1:
                return True
    return False


def detect_real_name_rotation(df_u):
    """
    Return dict {card_key: {names, emails, phones}} for cards exhibiting
    identity rotation: 3+ distinct real cardholder names, 3+ distinct
    client emails, or 3+ distinct client phone numbers on the same card.
    """
    hits = {}
    df = df_u[df_u['card_key'].notna()]

    for ck, group in df.groupby('card_key'):
        distinct_names = {
            str(n).strip().upper() for n in group['card_holder'] if is_real_name(n)
        }
        distinct_emails = {
            str(e).strip().lower()
            for e in group.get('client_email', pd.Series(dtype=object))
            if pd.notna(e) and str(e).strip() != ''
        }
        distinct_phones = {
            ''.join(ch for ch in str(p) if ch.isdigit())
            for p in group.get('client_phone', pd.Series(dtype=object))
            if pd.notna(p) and str(p).strip() != ''
        }
        distinct_phones.discard('')

        if (len(distinct_names) >= 3
                or len(distinct_emails) >= 3
                or len(distinct_phones) >= 3):
            hits[ck] = {
                'names': list(distinct_names),
                'emails': list(distinct_emails),
                'phones': list(distinct_phones),
            }
    return hits


def detect_cross_merchant_reuse(df_u):
    """
    Return list of dicts describing cards used at 2+ merchants within 30 min
    where at least one attempt was rejected.

    O(N) per card: a two-pointer scan maintains a merchant-count map and a
    rejection counter over the 30-minute sliding window. `df_u` is assumed
    sorted by transaction_created_at.
    """
    df = df_u[df_u['card_key'].notna() & df_u['transaction_created_at'].notna()]
    window_delta = np.timedelta64(30, 'm')

    hits = []
    for ck, group in df.groupby('card_key', sort=False):
        if group['company_name'].nunique() < 2:
            continue
        times = group['transaction_created_at'].values
        merchants_arr = group['company_name'].values
        statuses = group['status'].values
        ips = group['ip'].values
        tx_ids = group['transaction_id'].values
        n = len(group)

        merchant_counts = {}
        rej_count = 0
        j = 0  # exclusive right edge
        for i in range(n):
            limit = times[i] + window_delta
            while j < n and times[j] <= limit:
                m = merchants_arr[j]
                merchant_counts[m] = merchant_counts.get(m, 0) + 1
                if statuses[j] == 'REJECTED':
                    rej_count += 1
                j += 1
            if len(merchant_counts) >= 2 and rej_count > 0:
                # Record the current window and stop — one hit per card.
                win_times = times[i:j]
                win_statuses = statuses[i:j]
                hits.append({
                    'card_key': ck,
                    'merchants': list(dict.fromkeys(merchants_arr[i:j])),
                    'n_attempts': int(j - i),
                    'rejected': int((win_statuses == 'REJECTED').sum()),
                    'succeeded': int((win_statuses == 'SUCCEEDED').sum()),
                    'timespan_minutes': float(
                        (win_times.max() - win_times.min()) / np.timedelta64(1, 'm')
                    ),
                    'ips': list(pd.unique(pd.Series(ips[i:j]).dropna())),
                    'transaction_ids': list(tx_ids[i:j]),
                })
                break
            # Shrink: drop index i before the next iteration advances it.
            m_out = merchants_arr[i]
            merchant_counts[m_out] -= 1
            if merchant_counts[m_out] == 0:
                del merchant_counts[m_out]
            if statuses[i] == 'REJECTED':
                rej_count -= 1
    return hits


def detect_channel_switch(df_u):
    """
    Return list of hits: same card rejected via POS with fraud code, then retried
    via another channel (LINK/QR) for similar amount within 5 min and succeeded.
    """
    df = df_u[df_u['card_key'].notna()]

    hits = []
    for ck, group in df.groupby('card_key', sort=False):
        if group['transaction_type'].nunique() < 2:
            continue
        # df_u is already globally sorted by transaction_created_at; reset
        # index so the positional comparison `group.index > i` in the filter
        # below works on a 0..N-1 range.
        group = group.reset_index(drop=True)
        for i, row in group.iterrows():
            if row['status'] != 'REJECTED':
                continue
            if not (is_critical_code(row['rejection_reason']) or is_minfraud_blocked(row['rejection_reason'])):
                continue
            t0 = row['transaction_created_at']
            if pd.isna(t0):
                continue
            base_amount = row['amount']
            if pd.isna(base_amount) or base_amount == 0:
                continue
            followup = group[
                (group.index > i) &
                (group['transaction_created_at'] <= t0 + timedelta(minutes=5)) &
                (group['status'] == 'SUCCEEDED') &
                (group['transaction_type'] != row['transaction_type']) &
                (np.abs(group['amount'] - base_amount) / base_amount <= 0.05)
            ]
            if len(followup) > 0:
                hit_row = followup.iloc[0]
                hits.append({
                    'card_key': ck,
                    'rejected_tx_id': row['transaction_id'],
                    'rejected_channel': row['transaction_type'],
                    'rejected_reason': row['rejection_reason'],
                    'succeeded_tx_id': hit_row['transaction_id'],
                    'succeeded_channel': hit_row['transaction_type'],
                    'amount': float(row['amount']),
                    'company_name': row['company_name'],
                    'company_id': row['company_id'],
                    'delta_seconds': (hit_row['transaction_created_at'] - t0).total_seconds(),
                })
    return hits


def detect_velocity_burst(df_u):
    """
    Return dict {company_name: burst_info} for merchants exceeding their tier ceiling.

    O(N) per merchant via two-pointer scan over a 1-minute sliding window.
    """
    hits = {}
    window_delta = np.timedelta64(60, 's')
    for mname, group in df_u.groupby('company_name', sort=False):
        if len(group) < 3:
            continue
        avg_ticket = group['amount'].mean()
        ceiling = velocity_ceiling(avg_ticket)

        g_valid = group[group['transaction_created_at'].notna()]
        times = g_valid['transaction_created_at'].values
        n = len(times)
        max_in_window = 0
        j = 0
        for i in range(n):
            limit = times[i] + window_delta
            if j < i:
                j = i
            while j < n and times[j] <= limit:
                j += 1
            count = j - i
            if count > max_in_window:
                max_in_window = count

        if max_in_window > ceiling:
            # Round-number repetition: 3 consecutive identical whole-dollar
            # amounts ≥ $10 — a hallmark of automated card testing.
            round_rep = False
            amts = group['amount'].values
            for i in range(len(amts) - 2):
                a = amts[i]
                if (pd.notna(a)
                        and a == amts[i + 1] == amts[i + 2]
                        and a == int(a)
                        and a >= 10):
                    round_rep = True
                    break
            hits[mname] = {
                'max_tx_per_minute': int(max_in_window),
                'ceiling': ceiling,
                'avg_ticket': round(float(avg_ticket), 2),
                'round_number_repetition': round_rep,
            }
    return hits


def _bin_diversity_scan(times, bins_arr, is_rej, delta, min_bins):
    """
    Two-pointer sweep: find any sliding window of size <= delta with at least
    min_bins unique BINs and rejection rate >= REJECT_RATE_THRESHOLD.
    Returns (unique_bins, reject_rate) for the triggering window, else (0, 0).
    """
    n = len(times)
    counter = {}
    rej_count = 0
    total = 0
    j = 0
    for i in range(n):
        limit = times[i] + delta
        while j < n and times[j] <= limit:
            b = bins_arr[j]
            counter[b] = counter.get(b, 0) + 1
            if is_rej[j]:
                rej_count += 1
            total += 1
            j += 1
        rate = rej_count / total if total > 0 else 0.0
        unique = len(counter)
        if unique >= min_bins and rate >= REJECT_RATE_THRESHOLD:
            return unique, rate
        # Shrink before next i
        b_out = bins_arr[i]
        counter[b_out] -= 1
        if counter[b_out] == 0:
            del counter[b_out]
        if is_rej[i]:
            rej_count -= 1
        total -= 1
    return 0, 0.0


def detect_bin_diversity_burst(df_u):
    """
    Detect merchants with unusually high BIN diversity in a short window,
    which is the hallmark of card testing even when velocity isn't above ceiling.

    Threshold: 10+ unique BINs at a single merchant in a 4-hour window,
    OR 6+ unique BINs in a 1-hour window, AND reject rate >= REJECT_RATE_THRESHOLD
    in that window.

    O(N) per merchant via two-pointer scan.
    """
    hits = {}
    delta_1h = np.timedelta64(1, 'h')
    delta_4h = np.timedelta64(4, 'h')
    for mname, group in df_u.groupby('company_name', sort=False):
        if len(group) < 6:
            continue
        g_valid = group[
            group['transaction_created_at'].notna()
            & group['bin_card_number'].notna()
        ]
        if len(g_valid) < 6:
            continue
        times = g_valid['transaction_created_at'].values
        bins_arr = g_valid['bin_card_number'].values
        is_rej = (g_valid['status'] == 'REJECTED').values

        bins_1h, rate_1h = _bin_diversity_scan(times, bins_arr, is_rej, delta_1h, 6)
        bins_4h, rate_4h = _bin_diversity_scan(times, bins_arr, is_rej, delta_4h, 10)

        if bins_1h > 0 or bins_4h > 0:
            hits[mname] = {
                'bins_in_window': int(max(bins_1h, bins_4h)),
                'reject_rate_in_window': round(float(max(rate_1h, rate_4h)), 2),
                'window_hours': 1 if bins_1h > 0 else 4,
            }
    return hits


# ---------------------------------------------------------------------------
# Foreign-card velocity
# ---------------------------------------------------------------------------

def _normalize_country(val):
    """Uppercase + strip country strings; treat blanks / 'nan' as missing."""
    if pd.isna(val):
        return None
    s = str(val).strip().upper()
    if s == '' or s == 'NAN':
        return None
    return s


def detect_foreign_card_velocity(df_u):
    """
    Flag merchants passing an unusually high volume of foreign cards quickly.

    A transaction is 'foreign' when card_country_mind_fraud differs from the
    merchant's country_name (the country where the transaction took place).

    Signal: FOREIGN_CARD_COUNT_THRESHOLD+ unique foreign cards within any
    FOREIGN_CARD_WINDOW_HOURS window at the same merchant.
    """
    hits = {}
    df = df_u.copy()
    df['_merchant_country'] = df['country_name'].apply(_normalize_country)
    df['_card_country'] = df['card_country_mind_fraud'].apply(_normalize_country)
    df['_is_foreign'] = (
        df['_merchant_country'].notna()
        & df['_card_country'].notna()
        & (df['_merchant_country'] != df['_card_country'])
    )

    window_delta = np.timedelta64(FOREIGN_CARD_WINDOW_HOURS, 'h')
    for mname, group in df.groupby('company_name', sort=False):
        foreign = group[
            group['_is_foreign']
            & group['card_key'].notna()
            & group['transaction_created_at'].notna()
        ]
        if len(foreign) < FOREIGN_CARD_COUNT_THRESHOLD:
            continue

        times = foreign['transaction_created_at'].values
        card_keys = foreign['card_key'].values
        countries = foreign['_card_country'].values
        n = len(foreign)

        card_counts = {}
        j = 0
        max_unique = 0
        best_start = 0
        best_end = 0
        for i in range(n):
            limit = times[i] + window_delta
            while j < n and times[j] <= limit:
                ck = card_keys[j]
                card_counts[ck] = card_counts.get(ck, 0) + 1
                j += 1
            unique = len(card_counts)
            if unique > max_unique:
                max_unique = unique
                best_start = i
                best_end = j
            # Shrink before next i
            ck_out = card_keys[i]
            card_counts[ck_out] -= 1
            if card_counts[ck_out] == 0:
                del card_counts[ck_out]

        best_countries = set(c for c in countries[best_start:best_end] if c is not None)
        best_window_size = best_end - best_start

        if max_unique >= FOREIGN_CARD_COUNT_THRESHOLD:
            merchant_country_mode = group['_merchant_country'].dropna()
            merchant_country = (
                merchant_country_mode.mode().iloc[0]
                if not merchant_country_mode.empty else None
            )
            hits[mname] = {
                'unique_foreign_cards_in_window': int(max_unique),
                'window_hours': FOREIGN_CARD_WINDOW_HOURS,
                'window_transaction_count': int(best_window_size),
                'merchant_country': merchant_country,
                'foreign_card_countries': sorted(best_countries),
                'total_foreign_transactions': int(len(foreign)),
            }
    return hits


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------

def detect_duplicates(df_u, fraud_card_keys=None, fraud_merchants=None):
    """
    Same card, same exact amount, same merchant, within 5 minutes, both SUCCEEDED,
    and no fraud flags on either the card, the merchant, or the transactions themselves.

    `fraud_card_keys` and `fraud_merchants` are sets of cards/merchants already
    implicated by other detectors — duplicates from these are treated as fraud
    residue, not billing errors.
    """
    fraud_card_keys = fraud_card_keys or set()
    fraud_merchants = fraud_merchants or set()

    df = df_u[(df_u['status'] == 'SUCCEEDED') & df_u['card_key'].notna()]

    # Exclude transactions with critical codes or MinFraud blocks on the row
    # itself. Uses the precomputed `_is_critical_code` / `_is_minfraud_blocked`
    # columns added at the top of analyze() — equivalent to the prior
    # `.apply(is_critical_code)` but vectorized.
    tainted_row = df['_is_critical_code'] | df['_is_minfraud_blocked']
    df = df[~tainted_row]

    # Exclude cards / merchants implicated by other detectors
    df = df[~df['card_key'].isin(fraud_card_keys)]
    df = df[~df['company_name'].isin(fraud_merchants)]

    hits = []
    for (mname, ck, amt), group in df.groupby(['company_name', 'card_key', 'amount'], sort=False):
        if len(group) < 2:
            continue
        # df_u is already globally time-sorted; just reset index for .loc access.
        group = group.reset_index(drop=True)
        for i in range(len(group) - 1):
            t0 = group.loc[i, 'transaction_created_at']
            t1 = group.loc[i + 1, 'transaction_created_at']
            if pd.isna(t0) or pd.isna(t1):
                continue
            delta = (t1 - t0).total_seconds()
            if delta <= 300:  # 5 minutes
                hits.append({
                    'company_name': mname,
                    'company_id': group.loc[i, 'company_id'],
                    'card_bin': ck.split('-')[0],
                    'card_last_digits': ck.split('-')[1],
                    'amount': float(amt),
                    'transaction_ids': [group.loc[i, 'transaction_id'], group.loc[i + 1, 'transaction_id']],
                    'timestamps': [str(t0), str(t1)],
                    'delta_seconds': int(delta),
                })
    return hits


# ---------------------------------------------------------------------------
# Abandoned (3DS PENDING) detection
# ---------------------------------------------------------------------------

def detect_abandoned_suspicious(df_u):
    """
    Flag merchants with 5+ abandoned/PENDING (3DS) transactions within a
    20-minute window. O(N) per merchant via two-pointer scan.
    """
    pending = df_u[
        (df_u['status'] == 'PENDING')
        & df_u['transaction_created_at'].notna()
    ]
    if len(pending) == 0:
        return []
    hits = []
    window_delta = np.timedelta64(20, 'm')
    for mname, group in pending.groupby('company_name', sort=False):
        if len(group) < 5:
            continue
        times = group['transaction_created_at'].values
        n = len(times)
        j = 0
        for i in range(n):
            limit = times[i] + window_delta
            if j < i:
                j = i
            while j < n and times[j] <= limit:
                j += 1
            count = j - i
            if count >= 5:
                hits.append({
                    'company_name': mname,
                    'count': int(count),
                    'timespan_minutes': 20,
                })
                break
    return hits


# ---------------------------------------------------------------------------
# Suspicious all-rejected-merchant detector (self-contained)
# ---------------------------------------------------------------------------

def _rejection_code(reason):
    """Extract the stable code prefix from a rejection_reason string.

    The description text after the code is inconsistent in the data (the same
    numeric code carries different / misspelled descriptions, e.g. '14 - LLAMAR
    EL EMISOR' vs '14 - LLAMAR AL EMISOR'), so we key off the prefix only.
    MinFraud custom rules are normalized to a single 'MF: custom_rule' bucket.
    """
    if pd.isna(reason):
        return None
    s = str(reason).strip()
    if not s:
        return None
    if s.startswith('MF: custom_rule'):
        return 'MF: custom_rule'
    if ' - ' in s:
        return s.split(' - ', 1)[0].strip()
    return s


def _build_attempts(df_raw):
    """Rebuild an ATTEMPT-level view from the raw (pre-dedupe) CSV.

    One row per (transaction_id + last_intent_at + card), collapsing only a
    single attempt's DRAFT→PENDING→REJECTED/SUCCEEDED status transitions down
    to its terminal status. Distinct card attempts that the global
    transaction_id-level dedupe would merge are preserved here.

    Local to this detector — does not mutate df_raw or df_u.
    """
    df = df_raw.copy()
    df['_card_key'] = _compute_card_keys(df)
    # Composite, NaN-safe attempt id (string) so rows with a missing card_key
    # are not silently dropped by a groupby on NaN keys.
    txid = df['transaction_id'].astype('string').fillna('')
    li = df['last_intent_at'].astype('string').fillna('')
    ck = df['_card_key'].astype('string').fillna('')
    df['_attempt_id'] = txid + '|' + li + '|' + ck
    df['_rank'] = df['status'].map(_STATUS_RANK).fillna(0)
    # Keep the terminal (highest-rank) row per attempt.
    df = df.sort_values('_rank', kind='stable')
    attempts = df.groupby('_attempt_id', sort=False).tail(1).copy()
    return attempts


def _max_distinct_in_window(times, keys, delta):
    """Max number of distinct `keys` observed within any rolling `delta`
    window. `times` must be sorted ascending. Two-pointer, O(n)."""
    n = len(times)
    counts = {}
    j = 0
    best = 0
    for i in range(n):
        limit = times[i] + delta
        while j < n and times[j] <= limit:
            counts[keys[j]] = counts.get(keys[j], 0) + 1
            j += 1
        if len(counts) > best:
            best = len(counts)
        k_out = keys[i]
        counts[k_out] -= 1
        if counts[k_out] == 0:
            del counts[k_out]
    return best


def _has_near_duplicate_identity(ch):
    """True if the merchant's cardholder-side attempts show hand-keyed identity
    re-entry: near-duplicate holder names, or near-duplicate BINs sharing the
    same last4 + holder."""
    names = sorted({
        str(n).strip() for n in ch['card_holder'] if is_real_name(n)
    })[:NAME_SIMILARITY_MAX_NAMES]
    for i in range(len(names)):
        a = names[i].upper()
        for k in range(i + 1, len(names)):
            b = names[k].upper()
            if a == b:
                continue
            if difflib.SequenceMatcher(None, a, b).ratio() >= NAME_SIMILARITY_RATIO:
                return True

    # Near-duplicate BINs with identical last4 + holder.
    by_card = defaultdict(set)
    sub = ch[ch['_card_key'].notna()]
    for ck, holder in zip(sub['_card_key'], sub['card_holder']):
        if not is_real_name(holder):
            continue
        bin_, last4 = ck.split('-')
        by_card[(last4, str(holder).strip().upper())].add(bin_)
    for bins in by_card.values():
        bl = sorted(bins)
        for i in range(len(bl)):
            for k in range(i + 1, len(bl)):
                if len(bl[i]) == len(bl[k]) and sum(
                    c1 != c2 for c1, c2 in zip(bl[i], bl[k])
                ) <= BIN_NEAR_DUPLICATE_MAX_DIFF:
                    return True
    return False


def build_rejected_description_es(mname, fps, metrics, currency):
    """Spanish description for a suspicious all-rejected merchant finding.
    English DB field names are kept verbatim inside the Spanish prose, matching
    the rest of the engine's output convention."""
    pieces = [
        f"{metrics['attempts']} intentos, {metrics['distinct_cards']} tarjetas "
        f"distintas, {metrics['succeeded']} exitosas "
        f"(tasa de éxito {metrics['success_rate'] * 100:.1f}%). "
        f"Monto rechazado: {currency} {metrics['rejected_amount']:,.2f}."
    ]
    if 'card_fanout_burst' in fps:
        pieces.append(
            f"Ráfaga de BIN-attack: {metrics['max_cards_5min']} tarjetas distintas "
            f"en <5 min sobre canales del tarjetahabiente (LINK/QR)."
        )
    elif 'card_fanout_session' in fps or 'card_fanout_slow' in fps:
        pieces.append(
            f"Fan-out de tarjetas en una misma sesión del merchant "
            f"({metrics['max_cards_60min']} tarjetas distintas en la ventana)."
        )
    elif 'card_fanout_pair' in fps:
        pieces.append("Dos tarjetas distintas en <30 min sobre canales del tarjetahabiente.")
    if 'single_ip_multi_card' in fps:
        pieces.append(
            f"Una sola IP presentó {metrics['max_cards_per_ip']} tarjetas distintas "
            f"(LINK/QR: la IP es el tarjetahabiente, no el terminal)."
        )
    if 'payer_identity_rotation' in fps:
        pieces.append("Rotación de identidad: un pagador con múltiples nombres/tarjetas, o un mismo nombre sobre múltiples tarjetas.")
    if 'near_duplicate_identity' in fps:
        pieces.append("Nombres de tarjetahabiente o BINs casi idénticos — patrón de re-digitación manual de tarjetas.")
    if 'repeated_decline_code' in fps:
        pieces.append(
            f"Mismo código de rechazo repetido en una tarjeta "
            f"(código dominante '{metrics['top_code']}' ×{metrics['top_code_count']})."
        )
    if 'card_diversity' in fps:
        pieces.append(f"Alta diversidad de tarjetas/BINs en sesión sin liquidación ({metrics['distinct_bins']} BINs).")
    if 'watchlist_merchant' in fps:
        pieces.append("REPEAT OFFENDER: merchant ya en watchlist.")
    if 'watchlist_card' in fps:
        pieces.append("Tarjeta(s) ya en watchlist.")
    return " ".join(pieces)


def detect_suspicious_rejected_merchants(
    df_raw, watchlist_merchants, watchlist_cards, currency=DEFAULT_CURRENCY,
):
    """Return a list of findings for merchants with (near-)zero settlement that
    show card-testing behavior. Self-contained — see the module-level note."""
    attempts_all = _build_attempts(df_raw)
    # Drop never-progressed drafts; they are not real attempts.
    attempts_all = attempts_all[attempts_all['status'] != 'DRAFT']
    if len(attempts_all) == 0:
        return []

    findings = []
    for mname, m in attempts_all.groupby('company_name', sort=False):
        n_attempts = len(m)
        n_succ = int((m['status'] == 'SUCCEEDED').sum())
        success_rate = n_succ / n_attempts if n_attempts else 0.0
        distinct_cards = int(m['_card_key'].nunique())

        # Entry gate: zero-settlement session touching >= 2 distinct cards.
        if (n_attempts < ZERO_SETTLEMENT_MIN_ATTEMPTS
                or success_rate > ZERO_SETTLEMENT_MAX_SUCCESS_RATE
                or distinct_cards < ZERO_SETTLEMENT_MIN_DISTINCT_CARDS):
            continue

        score = W_ZERO_SETTLEMENT
        fps = ['zero_settlement_session']

        # Cardholder-side subset (exclude POS terminals) with valid card+time.
        ch = m[~m['transaction_type'].isin(POS_CHANNELS)]
        chc = ch[ch['_card_key'].notna() & ch['transaction_created_at'].notna()] \
            .sort_values('transaction_created_at')

        max_5 = max_60 = max_24 = max_30 = 0
        if len(chc):
            times = chc['transaction_created_at'].values
            keys = chc['_card_key'].values
            max_5 = _max_distinct_in_window(times, keys, FANOUT_BURST_WINDOW)
            max_60 = _max_distinct_in_window(times, keys, FANOUT_SESSION_WINDOW)
            max_24 = _max_distinct_in_window(times, keys, FANOUT_SLOW_WINDOW)
            max_30 = _max_distinct_in_window(times, keys, FANOUT_PAIR_WINDOW)

        # Card fan-out tier (highest matching tier only).
        if max_5 >= FANOUT_BURST_CARDS:
            score += W_FANOUT_BURST
            fps.append('card_fanout_burst')
        elif max_60 >= FANOUT_SESSION_CARDS:
            score += W_FANOUT_SESSION
            fps.append('card_fanout_session')
        elif max_24 >= FANOUT_SESSION_CARDS:
            score += W_FANOUT_SLOW
            fps.append('card_fanout_slow')
        elif max_30 >= FANOUT_PAIR_CARDS:
            score += W_FANOUT_PAIR
            fps.append('card_fanout_pair')

        # Distinct cards per IP (cardholder-side only).
        max_cards_per_ip = 0
        if len(chc):
            ip_cards = chc[chc['ip'].notna()].groupby('ip')['_card_key'].nunique()
            max_cards_per_ip = int(ip_cards.max()) if len(ip_cards) else 0
        if max_cards_per_ip >= IP_MULTI_CARD_STRONG:
            score += W_IP_MULTI_STRONG
            fps.append('single_ip_multi_card')
        elif max_cards_per_ip >= IP_MULTI_CARD_WEAK:
            score += W_IP_MULTI_WEAK
            fps.append('single_ip_multi_card')

        # Identity rotation (cardholder-side): distinct real names per payer
        # email, or distinct cards per cardholder name.
        rotated = False
        chr_named = ch[ch['card_holder'].apply(is_real_name)]
        if len(chr_named):
            emails = chr_named['client_email'].astype('string').str.strip().str.lower()
            has_email = emails.notna() & (emails != '')
            if has_email.any():
                names_per_email = chr_named[has_email].assign(_e=emails[has_email]) \
                    .groupby('_e')['card_holder'] \
                    .apply(lambda s: len({str(x).strip().upper() for x in s}))
                if (names_per_email >= IDENTITY_ROTATION_COUNT).any():
                    rotated = True
            holder_norm = chr_named['card_holder'].astype(str).str.strip().str.upper()
            cards_per_name = chr_named.assign(_h=holder_norm) \
                .groupby('_h')['_card_key'].nunique()
            if (cards_per_name >= IDENTITY_ROTATION_COUNT).any():
                rotated = True
        if rotated:
            score += W_IDENTITY_ROTATION
            fps.append('payer_identity_rotation')

        if len(ch) and _has_near_duplicate_identity(ch):
            score += W_NEAR_DUPLICATE
            fps.append('near_duplicate_identity')

        # Repeated same rejection code on a single card.
        top_code, top_code_count = None, 0
        rej = m[(m['status'] == 'REJECTED') & m['_card_key'].notna()].copy()
        if len(rej):
            rej['_code'] = rej['rejection_reason'].apply(_rejection_code)
            rej = rej[rej['_code'].notna()]
            if len(rej):
                per_card_code = rej.groupby(['_card_key', '_code']).size()
                if len(per_card_code) and int(per_card_code.max()) >= REPEAT_CODE_THRESHOLD:
                    score += W_REPEAT_CODE
                    fps.append('repeated_decline_code')
                code_totals = rej.groupby('_code').size().sort_values(ascending=False)
                top_code = str(code_totals.index[0])
                top_code_count = int(code_totals.iloc[0])

        distinct_bins = int(m['_card_key'].dropna().map(lambda k: k.split('-')[0]).nunique())
        if distinct_cards >= SESSION_CARD_DIVERSITY:
            score += W_CARD_DIVERSITY
            fps.append('card_diversity')

        if mname in watchlist_merchants:
            score += W_WATCHLIST_MERCHANT
            fps.append('watchlist_merchant')
        if any(k in watchlist_cards for k in m['_card_key'].dropna().unique()):
            score += W_WATCHLIST_CARD
            fps.append('watchlist_card')

        score = min(score, 100)
        if score >= SECTION_CRITICAL_THRESHOLD:
            confidence = 'Critical'
        elif score >= SECTION_MONITOR_THRESHOLD:
            confidence = 'Monitor'
        else:
            # Zero-settlement but no escalation signal — likely a blocked
            # customer, not card testing. Precision over recall.
            continue

        rejected_amount = float(m[m['status'] != 'SUCCEEDED']['amount'].sum())
        distinct_ips = int(chc['ip'].nunique()) if len(chc) else 0

        metrics = {
            'attempts': n_attempts,
            'succeeded': n_succ,
            'success_rate': round(success_rate, 4),
            'distinct_cards': distinct_cards,
            'distinct_bins': distinct_bins,
            'distinct_ips': distinct_ips,
            'rejected_amount': round(rejected_amount, 2),
            'max_cards_5min': max_5,
            'max_cards_60min': max_60,
            'max_cards_per_ip': max_cards_per_ip,
            'top_code': top_code,
            'top_code_count': top_code_count,
        }

        # Evidence: first 5 attempts in time order.
        ev_rows = m.sort_values('transaction_created_at').head(5)
        evidence = []
        for _, r in ev_rows.iterrows():
            evidence.append({
                'transaction_id': r['transaction_id'],
                'amount': float(r['amount']) if pd.notna(r['amount']) else None,
                'status': r['status'],
                'transaction_type': r['transaction_type'],
                'rejection_reason': r['rejection_reason'] if pd.notna(r['rejection_reason']) else None,
                'timestamp': str(r['transaction_created_at']),
                'card_bin': f"{int(r['bin_card_number']):06d}" if pd.notna(r['bin_card_number']) else None,
                'card_last_digits': f"{int(r['card_last_digits']):04d}" if pd.notna(r['card_last_digits']) else None,
                'card_holder': r['card_holder'] if pd.notna(r['card_holder']) else None,
                'client_name': r['client_name'] if pd.notna(r.get('client_name')) else None,
                'client_email': r['client_email'] if pd.notna(r.get('client_email')) else None,
                'ip': r['ip'] if pd.notna(r['ip']) else None,
            })

        findings.append({
            'type': 'zero_settlement_card_testing',
            'company_name': mname,
            'company_id': m['company_id'].iloc[0] if len(m) else '',
            'risk_score': score,
            'confidence': confidence,
            'fingerprints': fps,
            'description_es': build_rejected_description_es(mname, fps, metrics, currency),
            'recommended_action_es': (
                "Revisar y considerar congelar el merchant: sesión sin liquidación "
                "con comportamiento de card testing. No hay exposición a chargebacks "
                "(nada se liquidó), pero indica abuso de la cuenta para probar "
                "tarjetas robadas."
            ),
            'action_code': 'REVIEW_MERCHANT',
            'metrics': metrics,
            'evidence': evidence,
            'currency': currency,
        })

    return findings


# ---------------------------------------------------------------------------
# Confirmed-fraud indicators
# ---------------------------------------------------------------------------
#
# Values the team has confirmed are linked to fraud — an email from a
# chargeback report, a cardholder name from a bank notice, an IP from a
# previous case. Stored in Supabase (migration 0008) and handed to the engine
# as a JSON file, the same way the watchlist already is.
#
# The signal this exists to catch is CROSS-MERCHANT: a payer identity
# confirmed as fraud at merchant A turning up at merchant B. Each indicator
# remembers where it was confirmed (`source_company_name`) so a hit somewhere
# else is distinguishable from the same merchant re-offending.
#
# Two match tiers, deliberately asymmetric:
#
#   exact  A normalized value matches exactly. This is analyst-confirmed
#          fraud data, so it FLOORS the merchant's risk score at the Critical
#          line rather than adding points. It cannot be diluted by a low
#          score elsewhere, and it needs no weight change — which is why it
#          ships while the scoring weights stay frozen.
#
#   fuzzy  A near match (name variant, same email local part on a new host,
#          neighbouring BIN). Adds points like any other signal — and is
#          therefore GATED OFF until the weights are recalibrated, because
#          the score already saturates at 100 on ordinary card-testing
#          patterns and extra points would land on a maxed-out score and do
#          nothing. See tests/CALIBRATION.md.
#
# Constants live here rather than at the top of the file because this block
# is self-contained: nothing outside it reads them.

# Turn on only after the W_* weights have been recalibrated against a real
# CSV. Until then fuzzy hits are still computed and reported (so analysts can
# see them and judge the rules), they just don't move the score.
ENABLE_FUZZY_INDICATOR_SCORING = False

# Exact hit floors the merchant here. 70 is the engine's existing Critical
# line — max() rather than assignment so a merchant that independently scored
# 95 is not demoted.
INDICATOR_EXACT_FLOOR = 70

# Points a fuzzy hit contributes once scoring is enabled.
W_INDICATOR_FUZZY = 15

# Name / company similarity for fuzzy matching. Reuses the same ratio the
# engine already applies to near-duplicate cardholder names so the two ideas
# of "similar name" stay consistent.
INDICATOR_NAME_RATIO = NAME_SIMILARITY_RATIO

# Free-mail and disposable hosts can never be email_domain indicators: a hit
# would fire on a large share of all legitimate traffic. Rejected at write
# time by the UI and again here, so a value that slipped into the table
# before this list grew still can't do damage.
UNINDEXABLE_EMAIL_DOMAINS = {
    'gmail.com', 'googlemail.com', 'hotmail.com', 'outlook.com', 'live.com',
    'yahoo.com', 'yahoo.es', 'icloud.com', 'me.com', 'aol.com', 'proton.me',
    'protonmail.com', 'msn.com', 'gmx.com', 'mail.com', 'zoho.com',
}

# Local parts too generic to identify a person.
UNINDEXABLE_EMAIL_LOCALS = {
    'info', 'admin', 'contacto', 'ventas', 'soporte', 'ayuda', 'hola',
    'no-reply', 'noreply', 'test', 'pagos', 'facturacion',
}

# Reserved / shared IP space that identifies a network, not a device.
UNINDEXABLE_IPS = {'127.0.0.1', '0.0.0.0', '::1', 'localhost'}

# Gmail-class hosts treat dots in the local part as cosmetic.
_GMAIL_CLASS = {'gmail.com', 'googlemail.com'}

# Legal suffixes stripped before comparing company names.
_COMPANY_SUFFIXES = {
    'sa', 'sadecv', 'srl', 'ltda', 'ltd', 'inc', 'llc', 'corp', 'co',
    'cv', 'de', 'sas', 'eirl',
}

# Which CSV columns feed which indicator type. A person_name indicator is
# checked against BOTH the embossed cardholder name and the payer name,
# because a confirmed fraudster shows up in either field depending on channel.
INDICATOR_SOURCE_COLUMNS = {
    # Cards are always BIN + last 4 together. Neither half identifies a card
    # on its own: a BIN is an entire issuing bank (every Visa debit card from
    # one bank shares it), and last-4 is one in ten thousand. Offering either
    # alone would guarantee false positives, so the type does not exist.
    'card_key':     ['card_key'],
    'email':        ['client_email'],
    'email_domain': ['client_email'],
    'phone':        ['client_phone'],
    'ip':           ['ip'],
    'person_name':  ['card_holder', 'client_name'],
    'company_name': ['company_name'],
    'company_id':   ['company_id'],
}

INDICATOR_TYPES = tuple(INDICATOR_SOURCE_COLUMNS.keys())

# Types where a near match is meaningful. Everything else is exact-only —
# a card_key or company_id that is nearly right is simply a different value.
# A card_key is deliberately absent: "nearly the same card" is a different
# card, and near-BIN matching was only meaningful when BINs stood alone.
FUZZY_CAPABLE_TYPES = {'email', 'person_name', 'company_name', 'ip'}


def _accent_fold(s: str) -> str:
    """Strip the accents that appear in Latin American name data."""
    for a, b in (('á', 'a'), ('é', 'e'), ('í', 'i'), ('ó', 'o'), ('ú', 'u'),
                 ('ñ', 'n'), ('ü', 'u'), ('Á', 'A'), ('É', 'E'), ('Í', 'I'),
                 ('Ó', 'O'), ('Ú', 'U'), ('Ñ', 'N'), ('Ü', 'U')):
        s = s.replace(a, b)
    return s


def _norm_digits(v, keep_last=None):
    """Digits only. `keep_last` trims to the last N — used for phone numbers,
    where the same line appears with and without a country code."""
    if v is None:
        return None
    d = ''.join(ch for ch in str(v) if ch.isdigit())
    if not d:
        return None
    if keep_last and len(d) >= keep_last:
        d = d[-keep_last:]
    return d or None


def norm_email(v):
    """Lowercase; drop +tags; drop dots in the local part for Gmail-class
    hosts only (they are cosmetic there and significant everywhere else)."""
    if v is None:
        return None
    s = str(v).strip().lower()
    if '@' not in s or s.startswith('@') or s.endswith('@'):
        return None
    local, _, domain = s.rpartition('@')
    local = local.split('+')[0]
    if domain in _GMAIL_CLASS:
        local = local.replace('.', '')
    if not local or not domain:
        return None
    return f'{local}@{domain}'


def norm_email_domain(v):
    """Domain portion of an address, or a bare domain typed on its own."""
    if v is None:
        return None
    s = str(v).strip().lower().lstrip('@')
    if '@' in s:
        s = s.rpartition('@')[2]
    s = s.strip()
    return s or None


def norm_phone(v):
    """Last 8 digits. Guatemalan and Salvadoran numbers are 8 digits; the
    export carries them with and without the country code depending on
    channel, so the tail is the stable part."""
    return _norm_digits(v, keep_last=8)


def norm_ip(v):
    """Trim and lowercase. Deliberately not parsed into an ipaddress object:
    the column occasionally carries proxy chains and we would rather compare
    the raw token than silently drop a malformed one."""
    if v is None:
        return None
    s = str(v).strip().lower()
    # Take the first hop of an X-Forwarded-For style chain.
    if ',' in s:
        s = s.split(',')[0].strip()
    return s or None


def norm_person_name(v):
    """Uppercase, accent-fold, drop punctuation, sort tokens.

    Token sorting collapses "PEREZ JUAN" and "JUAN PEREZ" onto one key, which
    matters because the cardholder field and the payer field order names
    differently. Placeholder values (PAYWAVE/VISA and friends) are rejected —
    they are not identities.
    """
    if v is None:
        return None
    # Placeholder check runs on the RAW value: CONTACTLESS_PLACEHOLDERS holds
    # entries in the exact case the export produces ('no-name' lowercase,
    # 'PAYWAVE/VISA' uppercase), so upper-casing first would miss half of them.
    if not is_real_name(v):
        return None
    s = _accent_fold(str(v).strip().upper())
    s = ''.join(ch if ch.isalnum() or ch.isspace() else ' ' for ch in s)
    tokens = [t for t in s.split() if t]
    if not tokens:
        return None
    return ' '.join(sorted(tokens))


def norm_company_name(v):
    """Like a person name but strips legal suffixes, which vary between how a
    merchant registers and how the export renders them."""
    if v is None:
        return None
    s = _accent_fold(str(v).strip().upper())
    # Periods are DELETED rather than turned into spaces so "S.A." collapses
    # to the token "SA" and gets recognised as a legal suffix. Splitting it
    # into "S" and "A" would leave two tokens the suffix list can't match.
    s = s.replace('.', '')
    s = ''.join(ch if ch.isalnum() or ch.isspace() else ' ' for ch in s)
    tokens = [t for t in s.split() if t and t.lower() not in _COMPANY_SUFFIXES]
    if not tokens:
        return None
    return ' '.join(tokens)


def norm_card_bin(v):
    """6- or 8-digit BIN. The column arrives as a float in some exports, so
    digits-only handles the trailing '.0'."""
    d = _norm_digits(v)
    if not d:
        return None
    if len(d) >= 8:
        return d[:8]
    return d[:6].zfill(6) if len(d) >= 6 else d.zfill(6)


def norm_card_last4(v):
    d = _norm_digits(v)
    return d[-4:].zfill(4) if d else None


# Separators an analyst might paste between BIN and last 4. Comma is
# excluded on purpose: the UI splits bulk input on commas, so allowing it
# here would turn one card into two broken values.
_CARD_KEY_SEPARATORS = ('-', ' ', '/', '|', ':', '	')


def norm_card_key(v):
    """Normalize a BIN + last-4 pair to 'BBBBBB-LLLL'.

    Accepts the shapes a chargeback report or a pasted spreadsheet actually
    produces: '411111-1234', '411111 1234', '411111/1234', or the two halves
    run together as 10 or 12 digits.

    A full card number is REFUSED rather than reduced to its BIN and last 4.
    Accepting one would mean the untouched PAN lands in `value_raw`, and the
    desktop client writes that column directly with no way to canonicalize
    it first. Refusing is the only behavior both clients can guarantee.
    """
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None

    for sep in _CARD_KEY_SEPARATORS:
        if sep in s:
            b, _, l4 = s.partition(sep)
            nb, nl = norm_card_bin(b), norm_card_last4(l4)
            # A 6/8-digit BIN and a 4-digit tail, nothing longer.
            if nb and nl and len(_norm_digits(b) or '') in (6, 8)                     and len(_norm_digits(l4) or '') == 4:
                return f'{nb}-{nl}'
            return None

    digits = _norm_digits(s)
    if not digits:
        return None
    if len(digits) == 10:            # 6-digit BIN + last 4
        return f'{digits[:6]}-{digits[-4:]}'
    if len(digits) == 12:            # 8-digit BIN + last 4
        return f'{digits[:8]}-{digits[-4:]}'
    return None


def norm_generic(v):
    if v is None:
        return None
    s = str(v).strip()
    return s or None


# norm_card_bin / norm_card_last4 stay as helpers for norm_card_key even
# though neither is a selectable indicator type any more.
INDICATOR_NORMALIZERS = {
    'card_key':     norm_card_key,
    'email':        norm_email,
    'email_domain': norm_email_domain,
    'phone':        norm_phone,
    'ip':           norm_ip,
    'person_name':  norm_person_name,
    'company_name': norm_company_name,
    'company_id':   norm_generic,
}


def normalize_indicator_value(indicator_type, value):
    """Public entry point used by the engine AND by the write path, so a value
    is normalized identically whether it is being stored or matched."""
    fn = INDICATOR_NORMALIZERS.get(indicator_type)
    if fn is None:
        return None
    try:
        return fn(value)
    except Exception:
        # A malformed cell must never take down a run.
        return None


def indicator_rejection_reason(indicator_type, value_norm):
    """Return why this value is unusable as an indicator, or None if it's fine.

    Called by the UI before saving and by the engine when loading, so a value
    that predates a growth of these lists still can't fire.
    """
    if not value_norm:
        return 'El valor no se pudo normalizar (formato no reconocido).'
    if len(value_norm) < 2:
        return 'El valor es demasiado corto.'

    if indicator_type == 'email_domain' and value_norm in UNINDEXABLE_EMAIL_DOMAINS:
        return (f'"{value_norm}" es un dominio de correo público. Coincidiría con '
                f'una gran parte del tráfico legítimo. Usa el correo completo.')
    if indicator_type == 'email':
        local = value_norm.split('@')[0]
        if local in UNINDEXABLE_EMAIL_LOCALS:
            return f'"{local}@" es un buzón genérico, no identifica a una persona.'
    if indicator_type == 'ip' and value_norm in UNINDEXABLE_IPS:
        return f'"{value_norm}" es una dirección reservada, no identifica un dispositivo.'
    if indicator_type == 'person_name' and len(value_norm.split()) < 2:
        return ('Un solo nombre o apellido genera demasiados falsos positivos. '
                'Usa el nombre completo.')
    return None


def card_key_input_error(raw):
    """Why this card entry is unusable, or None if it parses.

    Separate from indicator_rejection_reason because it inspects the RAW
    input: once normalization has failed the shape is gone, and 'no se pudo
    normalizar' is useless feedback when the fix is 'you pasted a full card
    number'.
    """
    if raw is None or not str(raw).strip():
        return 'Escribe el BIN y los últimos 4 dígitos.'
    digits = _norm_digits(raw) or ''
    if len(digits) > 12:
        return ('Parece un número de tarjeta completo. Registra solo el BIN '
                '(6 u 8 dígitos) y los últimos 4 — el número completo no se '
                'almacena nunca.')
    if norm_card_key(raw) is None:
        return ('Formato no reconocido. Usa BIN y últimos 4, por ejemplo '
                '«411111-1234» o «411111 1234».')
    return None


class FraudIndicatorSet:
    """Matches a CSV against the confirmed-fraud indicator list.

    Built once per run. Exact matching is a hash lookup vectorized with
    .isin() over a normalized column — the same technique the rejection-code
    masks use. Fuzzy matching is blocked on a cheap key so it stays linear in
    practice rather than comparing every indicator against every row.
    """

    def __init__(self, indicators):
        self.by_type = defaultdict(dict)   # type -> {value_norm: [indicator, ...]}
        self.fuzzy_by_type = defaultdict(list)
        self.count = 0

        now = datetime.now(timezone.utc)
        for ind in indicators or []:
            itype = ind.get('indicator_type')
            if itype not in INDICATOR_SOURCE_COLUMNS:
                continue
            if not ind.get('active', True):
                continue

            expires = ind.get('expires_at')
            if expires and _parse_ts(expires) and _parse_ts(expires) < now:
                continue

            # Re-normalize rather than trusting the stored value: if the
            # normalizer has changed since the row was written, the engine's
            # version is the authority.
            vnorm = normalize_indicator_value(itype, ind.get('value_raw') or ind.get('value_norm'))
            if indicator_rejection_reason(itype, vnorm):
                continue

            rec = {
                'id': ind.get('id'),
                'indicator_type': itype,
                'value_raw': ind.get('value_raw'),
                'value_norm': vnorm,
                'match_mode': ind.get('match_mode', 'exact'),
                'source': ind.get('source'),
                'source_company_name': ind.get('source_company_name'),
                'added_by_email': ind.get('added_by_email'),
                'added_at': ind.get('added_at'),
                'notes': ind.get('notes'),
            }
            mode = rec['match_mode']
            if mode in ('exact', 'both'):
                self.by_type[itype].setdefault(vnorm, []).append(rec)
            if mode in ('fuzzy', 'both') and itype in FUZZY_CAPABLE_TYPES:
                self.fuzzy_by_type[itype].append(rec)
            self.count += 1

    def __len__(self):
        return self.count

    # ── Matching ─────────────────────────────────────────────────────────

    def match_frame(self, df):
        """Return {company_name: [hit, ...]} for every indicator that fires.

        One hit per (indicator, merchant) pair — an indicator matching forty
        rows at one merchant is one finding, not forty.
        """
        if self.count == 0 or len(df) == 0:
            return {}

        hits = defaultdict(dict)   # company -> {(indicator_id, kind): hit}
        companies = df['company_name'].astype(str)

        for itype, columns in INDICATOR_SOURCE_COLUMNS.items():
            exact_map = self.by_type.get(itype) or {}
            fuzzy_list = self.fuzzy_by_type.get(itype) or []
            if not exact_map and not fuzzy_list:
                continue

            normalizer = INDICATOR_NORMALIZERS[itype]
            for col in columns:
                if col not in df.columns:
                    continue
                # Normalize the column once, reuse for both tiers.
                norm_col = df[col].map(lambda v: normalize_indicator_value(itype, v)
                                       if pd.notna(v) else None)

                if exact_map:
                    mask = norm_col.isin(exact_map.keys()) & norm_col.notna()
                    if mask.any():
                        self._collect_exact(hits, companies, norm_col, mask, exact_map, col)

                if fuzzy_list:
                    self._collect_fuzzy(hits, companies, norm_col, fuzzy_list, itype, col)

        return {company: list(by_key.values()) for company, by_key in hits.items()}

    def _collect_exact(self, hits, companies, norm_col, mask, exact_map, column):
        for idx in norm_col.index[mask]:
            value = norm_col.loc[idx]
            company = companies.loc[idx]
            for rec in exact_map.get(value, []):
                key = (rec['id'], 'exact')
                if key in hits[company]:
                    continue
                hits[company][key] = self._make_hit(rec, 'exact', value, company, column)

    def _collect_fuzzy(self, hits, companies, norm_col, fuzzy_list, itype, column):
        # Compare against the distinct values in this column, not every row —
        # a merchant with 5,000 transactions usually has far fewer identities.
        distinct = [v for v in norm_col.dropna().unique()]
        if not distinct:
            return
        if len(distinct) > NAME_SIMILARITY_MAX_NAMES * 20:
            distinct = distinct[:NAME_SIMILARITY_MAX_NAMES * 20]

        for rec in fuzzy_list:
            target = rec['value_norm']
            for value in distinct:
                if value == target:
                    continue        # exact tier already owns this
                if not _fuzzy_indicator_match(itype, target, value):
                    continue
                rows = norm_col.index[norm_col == value]
                for idx in rows:
                    company = companies.loc[idx]
                    key = (rec['id'], 'fuzzy')
                    if key in hits[company]:
                        continue
                    hits[company][key] = self._make_hit(rec, 'fuzzy', value, company, column)

    @staticmethod
    def _make_hit(rec, kind, matched_value, company, column):
        origin = rec.get('source_company_name')
        return {
            'indicator_id': rec['id'],
            'indicator_type': rec['indicator_type'],
            'match_kind': kind,
            'value_raw': rec['value_raw'],
            'matched_value': matched_value,
            'matched_column': column,
            'source': rec.get('source'),
            'source_company_name': origin,
            # The headline case: confirmed at one merchant, seen at another.
            'cross_merchant': bool(origin) and origin != company,
            'added_by_email': rec.get('added_by_email'),
            'added_at': rec.get('added_at'),
        }


def _fuzzy_indicator_match(itype, target, value):
    """Type-specific idea of 'close enough'. Exact equality is handled by the
    exact tier and is excluded before this is called."""
    if itype == 'ip':
        # Same /24 — same household or small office, not the same device.
        t, v = target.split('.'), value.split('.')
        return len(t) == 4 and len(v) == 4 and t[:3] == v[:3]

    if itype == 'email':
        t_local, _, t_dom = target.partition('@')
        v_local, _, v_dom = value.partition('@')
        # Same identity on a new host is the strong case.
        if t_local == v_local and t_dom != v_dom:
            return True
        if t_dom != v_dom:
            return False
        return difflib.SequenceMatcher(None, t_local, v_local).ratio() >= INDICATOR_NAME_RATIO

    if itype in ('person_name', 'company_name'):
        # Cheap blocking key first: sharing no leading character means the
        # ratio cannot clear the threshold for realistic name lengths.
        if target[:1] != value[:1] and not (set(target.split()) & set(value.split())):
            return False
        return difflib.SequenceMatcher(None, target, value).ratio() >= INDICATOR_NAME_RATIO

    return False


def _parse_ts(v):
    """Tolerant ISO-8601 parse; returns None rather than raising."""
    if not v:
        return None
    try:
        s = str(v).replace('Z', '+00:00')
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def load_indicators(path):
    """Read the indicator JSON the API/desktop stages next to the watchlist.

    Accepts either a bare list or {'indicators': [...]} so the file can grow
    metadata later without breaking older engines.
    """
    if not path:
        return []
    if not os.path.exists(path):
        print(f'[indicators] file not found: {path}', file=sys.stderr)
        return []
    try:
        # utf-8-sig, not utf-8: a BOM would otherwise raise JSONDecodeError
        # and silently degrade the run to zero indicators. Anything that
        # hand-writes this file on Windows (PowerShell's Set-Content
        # -Encoding utf8 among them) emits one.
        with open(path, encoding='utf-8-sig') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        # An unreadable indicator file must degrade to "no indicators",
        # never fail the run — the rest of the analysis is still valuable.
        # But say so on stderr: a report that quietly checked nothing looks
        # exactly like a report that found nothing.
        print(f'[indicators] could not read {path}: {type(e).__name__}',
              file=sys.stderr)
        return []
    if isinstance(data, dict):
        return data.get('indicators', [])
    return data if isinstance(data, list) else []


def build_indicator_description_es(hits):
    """One Spanish sentence summarizing why this merchant was flagged, with
    enough provenance that a reviewer can trace the match."""
    if not hits:
        return ''
    cross = [h for h in hits if h['cross_merchant']]
    exact = [h for h in hits if h['match_kind'] == 'exact']

    label = {
        'card_key': 'tarjeta',
        'email': 'correo', 'email_domain': 'dominio de correo',
        'phone': 'teléfono', 'ip': 'IP', 'person_name': 'nombre',
        'company_name': 'comercio', 'company_id': 'ID de comercio',
    }

    parts = []
    if cross:
        h = cross[0]
        parts.append(
            f"Coincide con datos de fraude ya confirmados en otro comercio: "
            f"{label.get(h['indicator_type'], h['indicator_type'])} "
            f"«{h['value_raw']}» fue confirmado en «{h['source_company_name']}»"
        )
    elif exact:
        h = exact[0]
        parts.append(
            f"Coincide con un indicador de fraude confirmado: "
            f"{label.get(h['indicator_type'], h['indicator_type'])} «{h['value_raw']}»"
        )
    else:
        h = hits[0]
        parts.append(
            f"Coincidencia aproximada con un indicador confirmado: "
            f"{label.get(h['indicator_type'], h['indicator_type'])} «{h['value_raw']}» "
            f"≈ «{h['matched_value']}»"
        )

    src = hits[0].get('source')
    who = hits[0].get('added_by_email')
    prov = []
    if src:
        prov.append(f"fuente: {src}")
    if who:
        prov.append(f"registrado por {who}")
    if prov:
        parts.append(f" ({'; '.join(prov)})")

    if len(hits) > 1:
        parts.append(f". {len(hits)} indicadores coinciden en total")
    return ''.join(parts) + '.'


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def score_merchant(
    mname, df_u, ladder_hit, velocity_hit, bin_diversity_hit, critical_code_count,
    minfraud_count, watchlist_merchants, watchlist_cards,
    cross_merchant_cards_here, channel_switches_here, name_rotations_here,
    suspicious_tests_mask_for_merchant, high_reject_rate, foreign_card_hit,
    merchant_card_keys=None,
):
    """Return (risk_score, fingerprints_list)."""
    score = 0
    fingerprints = []

    if ladder_hit:
        score += 40
        fingerprints.append('amount_ladder')

    if velocity_hit:
        score += 15
        fingerprints.append('velocity_burst')
        if velocity_hit.get('round_number_repetition'):
            score += 10
            fingerprints.append('round_number_repetition')

    if bin_diversity_hit:
        score += 30
        fingerprints.append('bin_diversity_burst')

    if high_reject_rate:
        score += 20
        fingerprints.append('high_reject_rate')

    if critical_code_count >= 3:
        score += 25
        fingerprints.append('critical_codes')
    elif critical_code_count >= 1:
        score += 15
        fingerprints.append('critical_codes')

    if minfraud_count > 0:
        score += 10
        fingerprints.append('minfraud_blocked')

    if mname in watchlist_merchants:
        score += 20
        fingerprints.append('watchlist_merchant')

    if cross_merchant_cards_here:
        score += 25
        fingerprints.append('cross_merchant_reuse')

    if channel_switches_here:
        score += 40
        fingerprints.append('channel_switch_retry')

    if name_rotations_here:
        score += 25
        fingerprints.append('real_name_rotation')

    if suspicious_tests_mask_for_merchant.any():
        score += 10
        fingerprints.append('multi_test_transactions')

    if foreign_card_hit:
        # High volume of foreign cards at one merchant in a short window is a
        # strong card-testing / stolen-card fencing indicator.
        score += 25
        fingerprints.append('foreign_card_velocity')

    # Watchlist card hits add a small bump. Check ALL cards seen at this
    # merchant — not just those flagged by cross_merchant_reuse — so a card
    # previously burned on another merchant still triggers the bump even if
    # it only shows up on one merchant this run.
    cards_to_check = merchant_card_keys if merchant_card_keys is not None else cross_merchant_cards_here
    for ck in cards_to_check:
        if ck in watchlist_cards:
            score += 10
            fingerprints.append('watchlist_card')
            break

    return min(score, 100), fingerprints


# ---------------------------------------------------------------------------
# Watchlist management
# ---------------------------------------------------------------------------

def load_watchlist(path):
    if not os.path.exists(path):
        return {'merchants': {}, 'cards': {}}
    with open(path) as f:
        return json.load(f)


def save_watchlist(wl, path):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as f:
        json.dump(wl, f, indent=2, default=str)


def update_watchlist(wl, critical_findings, date_str):
    for f in critical_findings:
        mname = f.get('company_name')
        if mname:
            entry = wl['merchants'].get(mname, {'first_flagged': date_str, 'flag_count': 0})
            entry['last_flagged'] = date_str
            entry['flag_count'] = entry.get('flag_count', 0) + 1
            entry['company_id'] = f.get('company_id', entry.get('company_id', ''))
            entry['last_risk_score'] = f.get('risk_score', 0)
            wl['merchants'][mname] = entry
        # Track cards involved
        for ev in f.get('evidence', []):
            bin_ = ev.get('card_bin')
            last4 = ev.get('card_last_digits')
            if bin_ and last4:
                ck = f"{bin_}-{last4}"
                entry = wl['cards'].get(ck, {'first_flagged': date_str, 'flag_count': 0})
                entry['last_flagged'] = date_str
                entry['flag_count'] = entry.get('flag_count', 0) + 1
                wl['cards'][ck] = entry
    return wl


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------

def analyze(csv_path, watchlist_path=None, indicators_path=None):
    # Schema is validated inside load_and_dedupe before any columns get touched.
    df_raw, df_u = load_and_dedupe(csv_path)

    # Precompute rejection-code classification masks ONCE on the full df_u
    # instead of recomputing per-merchant via `.apply(is_critical_code)` etc.
    # Same semantics as the row-level helpers: NaN → False; otherwise stringify
    # and check set membership (critical) or substring (MinFraud).
    #
    # `fillna('').astype(str)` is a single pass; `.isin()` and `.str.contains()`
    # are vectorized in C. The merchant loop later just slices these boolean
    # columns by group index — turning O(merchants × rows-per-merchant) Python
    # callable invocations into one C-level pass per CSV.
    _reason_str = df_u['rejection_reason'].fillna('').astype(str)
    df_u['_is_critical_code']    = _reason_str.isin(CRITICAL_CODES)
    df_u['_is_minfraud_blocked'] = _reason_str.str.contains(MINFRAUD_SUBSTRING, regex=False, na=False)

    # Watchlist — both merchants and cards persist permanently once flagged.
    watchlist = load_watchlist(watchlist_path) if watchlist_path else {'merchants': {}, 'cards': {}}
    watchlist_merchants = set(watchlist['merchants'].keys())
    watchlist_cards = set(watchlist['cards'].keys())

    # Date range
    date_start = df_u['transaction_created_at'].min()
    date_end = df_u['transaction_created_at'].max()
    date_str = date_start.isoformat() if pd.notna(date_start) else datetime.now(timezone.utc).isoformat()

    # Currency for this CSV. One value per file because CSVs are country-
    # specific; threaded through findings and the summary so the frontend
    # and the Spanish action text both render the right ISO code.
    currency = detect_currency(df_u)

    # Confirmed-fraud indicators. Matched once over the whole frame and then
    # grouped by merchant, so the per-merchant loop below is a dict lookup.
    # An empty or missing file degrades to "no indicators" rather than
    # failing the run.
    indicator_set = FraudIndicatorSet(load_indicators(indicators_path))
    indicator_hits_by_merchant = indicator_set.match_frame(df_u)

    # Test transactions
    suspicious_tests = identify_test_transactions(df_u)

    # Global detections
    name_rotations = detect_real_name_rotation(df_u)
    cross_merchant = detect_cross_merchant_reuse(df_u)
    channel_switches = detect_channel_switch(df_u)
    velocity_bursts = detect_velocity_burst(df_u)
    bin_diversity_bursts = detect_bin_diversity_burst(df_u)
    foreign_card_bursts = detect_foreign_card_velocity(df_u)
    abandoned = detect_abandoned_suspicious(df_u)

    # Self-contained detector for merchants that never settle a charge but show
    # card-testing behavior. Operates on its own attempt-level view of df_raw
    # and writes only to its own report section — see the module-level note.
    suspicious_rejected = detect_suspicious_rejected_merchants(
        df_raw, watchlist_merchants, watchlist_cards, currency
    )

    # Duplicates run last so we can exclude cards/merchants already flagged
    # by other detectors — a "duplicate" on a fraud-implicated card is fraud,
    # not a billing error.
    fraud_cards = set(name_rotations.keys())
    fraud_cards.update(h['card_key'] for h in cross_merchant)
    fraud_cards.update(h['card_key'] for h in channel_switches)
    fraud_merchants = set(velocity_bursts.keys()) | set(bin_diversity_bursts.keys())
    duplicates = detect_duplicates(df_u, fraud_cards, fraud_merchants)

    # Index cross-merchant and channel-switch by merchant for easy lookup
    cross_by_merchant = defaultdict(list)
    for hit in cross_merchant:
        for m in hit['merchants']:
            cross_by_merchant[m].append(hit)

    switch_by_merchant = defaultdict(list)
    for hit in channel_switches:
        switch_by_merchant[hit['company_name']].append(hit)

    # Name rotations: attach to merchants where the card appeared
    rotation_by_merchant = defaultdict(list)
    for ck, identities in name_rotations.items():
        bin_, last4 = ck.split('-')
        try:
            rows = df_u[(df_u['bin_card_number'] == float(bin_)) &
                        (df_u['card_last_digits'] == float(last4))]
            for m in rows['company_name'].unique():
                rotation_by_merchant[m].append({'card_key': ck, **identities})
        except (ValueError, TypeError):
            pass

    # Per-merchant fingerprints + scoring
    critical_findings = []
    monitor_findings = []
    flagged_txn_rows = []

    for mname, group in df_u.groupby('company_name', sort=False):
        ladder_hit = detect_amount_ladder(group)
        velocity_hit = velocity_bursts.get(mname)
        bin_diversity_hit = bin_diversity_bursts.get(mname)
        foreign_card_hit = foreign_card_bursts.get(mname)

        # Cache per-merchant boolean masks computed from `status` / rejection reasons
        # so downstream checks don't recompute them 3–4× each.
        status = group['status']
        rejected_mask = (status == 'REJECTED')
        succeeded_mask = (status == 'SUCCEEDED')
        n_total = len(group)
        n_rej = int(rejected_mask.sum())
        n_succ = int(succeeded_mask.sum())

        # Use the precomputed masks from df_u (added once at the top of
        # analyze()). Equivalent to apply(is_critical_code) but C-level.
        critical_code_rows = group[group['_is_critical_code']]
        minfraud_rows      = group[group['_is_minfraud_blocked']]

        cross_here = cross_by_merchant.get(mname, [])
        cross_card_keys = list({h['card_key'] for h in cross_here})

        switches_here = switch_by_merchant.get(mname, [])
        rotations_here = rotation_by_merchant.get(mname, [])

        # Tests mask restricted to this merchant
        test_mask = suspicious_tests & (df_u['company_name'] == mname)

        # High reject rate: only meaningful for merchants with ≥5 tx.
        # Threshold is the unified REJECT_RATE_THRESHOLD (see constants).
        high_reject_rate = n_total >= 5 and (n_rej / n_total) >= REJECT_RATE_THRESHOLD

        merchant_card_keys = set(group['card_key'].dropna())

        risk_score, fingerprints = score_merchant(
            mname, df_u, ladder_hit, velocity_hit, bin_diversity_hit,
            len(critical_code_rows), len(minfraud_rows),
            watchlist_merchants, watchlist_cards,
            cross_card_keys, switches_here, rotations_here,
            test_mask, high_reject_rate, foreign_card_hit,
            merchant_card_keys=merchant_card_keys,
        )

        # ── Confirmed-fraud indicators ───────────────────────────────────
        # Applied after score_merchant rather than inside it, because an
        # exact hit is not a scoring signal — it is analyst-confirmed fact
        # that outranks the model. Floor rather than assign, so a merchant
        # that independently scored higher keeps its score.
        merchant_indicator_hits = indicator_hits_by_merchant.get(mname, [])
        exact_hits = [h for h in merchant_indicator_hits if h['match_kind'] == 'exact']
        fuzzy_hits = [h for h in merchant_indicator_hits if h['match_kind'] == 'fuzzy']
        cross_hits = [h for h in merchant_indicator_hits if h['cross_merchant']]

        if exact_hits:
            risk_score = max(risk_score, INDICATOR_EXACT_FLOOR)
            fingerprints.append('confirmed_indicator_exact')
        if cross_hits:
            # The case this feature exists for: fraud confirmed at one
            # merchant reappearing at another. Reported as its own
            # fingerprint so it can be filtered and counted separately.
            fingerprints.append('confirmed_indicator_cross_merchant')
        if fuzzy_hits:
            fingerprints.append('confirmed_indicator_fuzzy')
            if ENABLE_FUZZY_INDICATOR_SCORING:
                risk_score = min(risk_score + W_INDICATOR_FUZZY, 100)

        if risk_score < 20:
            continue

        # Build finding object
        ticket_rows = group[succeeded_mask]
        # Chargeback-exposure rule (post-2026-05): every succeeded charge at a
        # merchant that lands in the Critical tier is treated as at-risk for
        # chargeback, regardless of which fingerprint fired. The previous rule
        # only counted exposure when ladder/velocity/switch were among the
        # fingerprints, which silently zeroed out merchants whose dominant
        # pattern was watchlist hit, BIN diversity, foreign-card velocity,
        # MinFraud block, name rotation, or cross-merchant reuse. The risk-
        # score gate is implicit: exposure is only written to the output
        # for risk_score >= 70 (the Critical branch below); we compute it
        # unconditionally because the cost is trivial and it keeps the value
        # available for any future reuse.
        exposure = float(ticket_rows['amount'].sum()) if len(ticket_rows) > 0 else 0.0

        # Evidence: first 5 rows. df_u is already globally time-sorted, so no
        # need to re-sort the per-merchant slice.
        #
        # The payer fields (client_name / client_email / ip) are recorded here
        # to match what the zero-settlement detector already stores. Until
        # this was levelled up, the two sections wrote different evidence
        # shapes, which meant a confirmed-fraud indicator could be checked
        # against the history of one section but not the other.
        evidence_rows = group.head(5)
        evidence = []
        for _, r in evidence_rows.iterrows():
            evidence.append({
                'transaction_id': r['transaction_id'],
                'amount': float(r['amount']) if pd.notna(r['amount']) else None,
                'status': r['status'],
                'transaction_type': r['transaction_type'] if pd.notna(r['transaction_type']) else None,
                'rejection_reason': r['rejection_reason'] if pd.notna(r['rejection_reason']) else None,
                'timestamp': str(r['transaction_created_at']),
                'card_bin': f"{int(r['bin_card_number']):06d}" if pd.notna(r['bin_card_number']) else None,
                'card_last_digits': f"{int(r['card_last_digits']):04d}" if pd.notna(r['card_last_digits']) else None,
                'card_holder': r['card_holder'] if pd.notna(r['card_holder']) else None,
                'client_name': r['client_name'] if pd.notna(r.get('client_name')) else None,
                'client_email': r['client_email'] if pd.notna(r.get('client_email')) else None,
                'ip': r['ip'] if pd.notna(r['ip']) else None,
            })

        # Classify as critical or monitor
        if risk_score >= 70:
            confidence = 'Critical'
            action_code = decide_action(fingerprints, switches_here, cross_here)
            description = build_description_es(mname, fingerprints, group, watchlist_merchants)
            # An indicator hit is the most actionable thing a reviewer can be
            # told, so it leads the description rather than trailing it.
            if merchant_indicator_hits:
                description = build_indicator_description_es(merchant_indicator_hits) + ' ' + description
            action_es = build_action_es(action_code, len(ticket_rows), exposure, currency)
            critical_findings.append({
                'type': classify_finding_type(fingerprints),
                'company_name': mname,
                'company_id': group['company_id'].iloc[0] if len(group) > 0 else '',
                'risk_score': risk_score,
                'confidence': confidence,
                'fingerprints': fingerprints,
                'description_es': description,
                'evidence': evidence,
                'recommended_action_es': action_es,
                'action_code': action_code,
                'estimated_chargeback_exposure': round(exposure, 2),
                'currency': currency,
                'total_transactions': n_total,
                'rejected_count': n_rej,
                'succeeded_count': n_succ,
                'indicator_hits': merchant_indicator_hits,
            })
        elif risk_score >= 40:
            confidence = 'Monitor'
            description = build_description_es(mname, fingerprints, group, watchlist_merchants)
            if merchant_indicator_hits:
                description = build_indicator_description_es(merchant_indicator_hits) + ' ' + description
            monitor_findings.append({
                'type': classify_finding_type(fingerprints),
                'company_name': mname,
                'company_id': group['company_id'].iloc[0] if n_total > 0 else '',
                'risk_score': risk_score,
                'confidence': confidence,
                'fingerprints': fingerprints,
                'description_es': description,
                'action_code': 'MONITOR',
                'evidence_count': n_total,
                'indicator_hits': merchant_indicator_hits,
            })

        # Build flagged_transactions rows for the CSV
        for _, r in group.iterrows():
            # Only include rows with at least one fingerprint reason
            if risk_score < 40:
                continue
            flagged_txn_rows.append({
                'transaction_id': r['transaction_id'],
                'transaction_created_at': str(r['transaction_created_at']),
                'company_id': r['company_id'],
                'company_name': r['company_name'],
                'amount': float(r['amount']) if pd.notna(r['amount']) else None,
                'status': r['status'],
                'transaction_type': r['transaction_type'],
                'card_bin': f"{int(r['bin_card_number']):06d}" if pd.notna(r['bin_card_number']) else '',
                'card_last_digits': f"{int(r['card_last_digits']):04d}" if pd.notna(r['card_last_digits']) else '',
                'card_holder': r['card_holder'] if pd.notna(r['card_holder']) else '',
                'client_name': r.get('client_name', '') if pd.notna(r.get('client_name', '')) else '',
                'client_email': r.get('client_email', '') if pd.notna(r.get('client_email', '')) else '',
                'client_phone': r.get('client_phone', '') if pd.notna(r.get('client_phone', '')) else '',
                'ip': r['ip'] if pd.notna(r['ip']) else '',
                'rejection_reason': r['rejection_reason'] if pd.notna(r['rejection_reason']) else '',
                'gateway_message': r['gateway_message'] if pd.notna(r['gateway_message']) else '',
                'risk_score': risk_score,
                'confidence': confidence,
                'fraud_fingerprints': ';'.join(fingerprints),
                'recommended_action': action_code if risk_score >= 70 else 'MONITOR',
                'notes': f"Parte de hallazgo: {classify_finding_type(fingerprints)}",
            })

    # Ring detection (same IP at 2+ merchants with same card)
    rings = detect_rings(df_u)

    # High-risk-score transaction highlights: rows where the gateway's own
    # risk_score or ip_risk_score exceeds HIGH_RISK_SCORE_THRESHOLD.
    risk_score_numeric = pd.to_numeric(df_u['risk_score'], errors='coerce')
    ip_risk_numeric = pd.to_numeric(df_u['ip_risk_score'], errors='coerce')
    high_risk_mask = (
        (risk_score_numeric > HIGH_RISK_SCORE_THRESHOLD)
        | (ip_risk_numeric > HIGH_RISK_SCORE_THRESHOLD)
    )
    high_risk_rows = df_u[high_risk_mask]
    high_risk_score_transactions = []
    for idx, r in high_risk_rows.iterrows():
        rs = risk_score_numeric.loc[idx]
        ips = ip_risk_numeric.loc[idx]
        high_risk_score_transactions.append({
            'transaction_id': r['transaction_id'],
            'transaction_created_at': str(r['transaction_created_at']),
            'company_name': r['company_name'],
            'company_id': r['company_id'],
            'amount': float(r['amount']) if pd.notna(r['amount']) else None,
            'status': r['status'],
            'risk_score': float(rs) if pd.notna(rs) else None,
            'ip_risk_score': float(ips) if pd.notna(ips) else None,
            'ip': r['ip'] if pd.notna(r['ip']) else None,
            'card_bin': f"{int(r['bin_card_number']):06d}" if pd.notna(r['bin_card_number']) else None,
            'card_last_digits': f"{int(r['card_last_digits']):04d}" if pd.notna(r['card_last_digits']) else None,
            'rejection_reason': r['rejection_reason'] if pd.notna(r['rejection_reason']) else None,
        })
    # Sort by the higher of the two risk scores, descending
    high_risk_score_transactions.sort(
        key=lambda t: max(t['risk_score'] or 0, t['ip_risk_score'] or 0),
        reverse=True,
    )

    # Section priority: Critical > Monitor > suspicious-rejected. A merchant
    # that already surfaced in the existing Critical/Monitor tiers is shown
    # there (the more important section) and dropped from the new section, so
    # nothing is listed twice. The existing tiers are left untouched.
    already_flagged = (
        {f['company_name'] for f in critical_findings}
        | {f['company_name'] for f in monitor_findings}
    )
    suspicious_rejected = [
        f for f in suspicious_rejected if f['company_name'] not in already_flagged
    ]

    # Watchlist hits
    watchlist_hits_merchants = [m for m in df_u['company_name'].unique() if m in watchlist_merchants]

    # Update watchlist for next run
    if watchlist_path:
        watchlist = update_watchlist(watchlist, critical_findings, date_str)
        save_watchlist(watchlist, watchlist_path)

    # Summary
    summary = {
        'date_range': {
            'start': str(date_start)[:10] if pd.notna(date_start) else None,
            'end': str(date_end)[:10] if pd.notna(date_end) else None,
        },
        'total_rows': len(df_raw),
        'unique_transactions': len(df_u),
        'status_counts': df_u['status'].value_counts().to_dict(),
        'total_amount_attempted': round(float(df_u['amount'].sum()), 2),
        'total_amount_succeeded': round(float(df_u[df_u['status'] == 'SUCCEEDED']['amount'].sum()), 2),
        'reject_rate': round(float((df_u['status'] == 'REJECTED').sum() / len(df_u)), 4) if len(df_u) > 0 else 0,
        'total_critical_findings': len(critical_findings),
        'total_monitor_findings': len(monitor_findings),
        'total_duplicate_findings': len(duplicates),
        'total_watchlist_hits': len(watchlist_hits_merchants),
        'estimated_chargeback_exposure': round(sum(f.get('estimated_chargeback_exposure', 0) for f in critical_findings), 2),
        'currency': currency,
        'total_high_risk_score_transactions': len(high_risk_score_transactions),
        'total_foreign_card_velocity_merchants': len(foreign_card_bursts),
        'total_suspicious_rejected_merchants': len(suspicious_rejected),
        'indicators_loaded': len(indicator_set),
        'total_indicator_merchants': len(indicator_hits_by_merchant),
        'total_indicator_cross_merchant': len([
            m for m, hits in indicator_hits_by_merchant.items()
            if any(h['cross_merchant'] for h in hits)
        ]),
    }

    return {
        'summary': summary,
        'critical_findings': sorted(critical_findings, key=lambda x: -x['risk_score']),
        'monitor_findings': sorted(monitor_findings, key=lambda x: -x['risk_score']),
        'suspicious_rejected_merchants': sorted(suspicious_rejected, key=lambda x: -x['risk_score']),
        'duplicate_findings': duplicates,
        'abandoned_findings': abandoned,
        'trends': {
            'repeat_offenders_from_watchlist': watchlist_hits_merchants,
            'new_watchlist_entries': [f['company_name'] for f in critical_findings if f['company_name'] not in watchlist_merchants],
            'velocity_outliers': [{'company_name': k, **v} for k, v in velocity_bursts.items()],
            'foreign_card_velocity': [{'company_name': k, **v} for k, v in foreign_card_bursts.items()],
            'ring_signatures': rings,
        },
        'flagged_transactions': flagged_txn_rows,
        'high_risk_score_transactions': high_risk_score_transactions,
        # Flat, merchant-keyed view of every indicator that fired. The API
        # layer uses this to bump hit_count without re-walking the findings,
        # and the UI renders it as its own report section. Cross-merchant
        # hits sort first — they are the reason this feature exists.
        'indicator_matches': sorted(
            [
                {
                    'company_name': company,
                    'cross_merchant': any(h['cross_merchant'] for h in hits),
                    'exact_count': sum(1 for h in hits if h['match_kind'] == 'exact'),
                    'fuzzy_count': sum(1 for h in hits if h['match_kind'] == 'fuzzy'),
                    'hits': hits,
                }
                for company, hits in indicator_hits_by_merchant.items()
            ],
            key=lambda m: (not m['cross_merchant'], -m['exact_count'], m['company_name']),
        ),
    }


def classify_finding_type(fingerprints):
    if 'channel_switch_retry' in fingerprints:
        return 'channel_switch'
    if 'cross_merchant_reuse' in fingerprints:
        return 'ring'
    if 'amount_ladder' in fingerprints or 'velocity_burst' in fingerprints:
        return 'card_testing'
    if 'watchlist_merchant' in fingerprints:
        return 'repeat_offender'
    return 'general_fraud'


def decide_action(fingerprints, switches_here, cross_here):
    if 'channel_switch_retry' in fingerprints:
        return 'REVIEW_CHARGE'
    if 'cross_merchant_reuse' in fingerprints and cross_here:
        return 'INVESTIGATE_RING'
    return 'FREEZE_MERCHANT'


def build_description_es(mname, fingerprints, group, watchlist_merchants):
    pieces = []
    rejected = int((group['status'] == 'REJECTED').sum())
    succeeded = int((group['status'] == 'SUCCEEDED').sum())
    pieces.append(f"{len(group)} transacciones ({rejected} REJECTED, {succeeded} SUCCEEDED).")

    if 'amount_ladder' in fingerprints:
        pieces.append("Patrón de amount ladder en una misma tarjeta: ≥3 intentos consecutivos con montos monotónicos (ascendentes o descendentes) en ≤20 min — comportamiento típico de card testing.")
    if 'velocity_burst' in fingerprints:
        pieces.append("Velocidad anormal de transacciones por minuto.")
    if 'bin_diversity_burst' in fingerprints:
        pieces.append("Alta diversidad de BINs en corto tiempo — patrón típico de card testing.")
    if 'high_reject_rate' in fingerprints:
        pieces.append(f"Tasa de rechazo inusualmente alta (≥{int(REJECT_RATE_THRESHOLD * 100)}%).")
    if 'cross_merchant_reuse' in fingerprints:
        pieces.append("Tarjeta(s) usada(s) en múltiples merchants.")
    if 'channel_switch_retry' in fingerprints:
        pieces.append("Retry por canal distinto después de rechazo con código de fraude.")
    if 'real_name_rotation' in fingerprints:
        pieces.append("Misma tarjeta con rotación de identidad (≥3 nombres, emails o teléfonos distintos).")
    if 'critical_codes' in fingerprints:
        # Was: sum(1 for r in group['rejection_reason'] if is_critical_code(r)).
        # The precomputed `_is_critical_code` column produces the same count
        # without re-running the Python predicate per row.
        critical_count = int(group['_is_critical_code'].sum())
        pieces.append(f"{critical_count} rechazos con códigos críticos (05, 63, 43, SM).")
    if 'watchlist_merchant' in fingerprints:
        pieces.append("REPEAT OFFENDER: ya flaggeado como crítico en los últimos 90 días.")
    if 'multi_test_transactions' in fingerprints:
        pieces.append("Múltiples test transactions (≤$1), sugiere card testing.")
    if 'foreign_card_velocity' in fingerprints:
        pieces.append(
            f"Alto volumen de tarjetas extranjeras en poco tiempo "
            f"(≥{FOREIGN_CARD_COUNT_THRESHOLD} tarjetas de países distintos "
            f"en {FOREIGN_CARD_WINDOW_HOURS}h) — indicador típico de "
            f"card testing / fencing de tarjetas robadas."
        )

    return " ".join(pieces)


def build_action_es(action_code, n_successful, exposure, currency=DEFAULT_CURRENCY):
    # `:,.2f` → US-style thousands separator + 2 decimals (e.g., 5,678.34).
    # Frontend uses the same convention via toLocaleString('en-US', ...),
    # so the per-merchant action text and the summary KPI match.
    # Currency is the ISO code (USD, GTQ, ...). We render "USD 5,678.34"
    # rather than "$5,678.34" because `$` is ambiguous across Latin American
    # currencies (Mexico, Argentina, Chile all use $ for their local peso).
    if action_code == 'FREEZE_MERCHANT':
        return f"Congelar cuenta del merchant y retener depósito. Revisar los {n_successful} cargos exitosos ({currency} {exposure:,.2f}) para exposición a chargebacks."
    elif action_code == 'REVIEW_CHARGE':
        return f"Revisar el cargo exitoso de {currency} {exposure:,.2f} — riesgo alto de chargeback por channel-switch retry."
    elif action_code == 'INVESTIGATE_RING':
        return "Investigar a los merchants involucrados como una entidad única. Revisar si comparten dueño/RUC/email de onboarding."
    else:
        return "Monitorear y agregar a watchlist."


def detect_rings(df_u):
    """Same IP at 2+ merchants with same card."""
    df = df_u[df_u['card_key'].notna() & df_u['ip'].notna()]

    rings = []
    seen = set()
    for (ip, ck), group in df.groupby(['ip', 'card_key']):
        merchants = group['company_name'].unique()
        if len(merchants) >= 2:
            key = (ip, ck)
            if key in seen:
                continue
            seen.add(key)
            rings.append({
                'merchants': list(merchants),
                'common_ip': ip,
                'common_card': ck,
                'n_attempts': len(group),
                'rejected': int((group['status'] == 'REJECTED').sum()),
            })
    return rings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_path')
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--watchlist')
    parser.add_argument('--update-watchlist')
    parser.add_argument('--indicators',
                        help='Path to a confirmed-fraud indicator JSON file '
                             '(list, or {"indicators": [...]}). Optional.')
    parser.add_argument('--output')
    args = parser.parse_args()

    if args.validate_only:
        df = _read_csv_with_encoding_fallback(args.csv_path, nrows=5)
        ok, missing_req, missing_opt = validate_schema(df)
        print(json.dumps({
            'schema_ok': ok,
            'missing_required': missing_req,
            'missing_optional': missing_opt,
        }, indent=2))
        sys.exit(0 if ok else 1)

    wl_path = args.update_watchlist or args.watchlist
    findings = analyze(args.csv_path, watchlist_path=wl_path,
                       indicators_path=args.indicators)

    output_path = args.output or '/tmp/findings.json'
    with open(output_path, 'w') as f:
        json.dump(findings, f, indent=2, default=str)

    # Print a short summary
    s = findings['summary']
    print(f"Analyzed {s['unique_transactions']} transactions from {s['date_range']['start']} to {s['date_range']['end']}")
    print(f"Critical findings: {s['total_critical_findings']}")
    print(f"Monitor findings: {s['total_monitor_findings']}")
    print(f"Duplicates: {s['total_duplicate_findings']}")
    print(f"Watchlist hits: {s['total_watchlist_hits']}")
    print(f"High-risk-score transactions (>{HIGH_RISK_SCORE_THRESHOLD}): {s['total_high_risk_score_transactions']}")
    print(f"Merchants with foreign-card velocity: {s['total_foreign_card_velocity_merchants']}")
    print(f"Suspicious all-rejected merchants (no settlement): {s['total_suspicious_rejected_merchants']}")
    if s.get('indicators_loaded'):
        print(f"Confirmed-fraud indicators loaded: {s['indicators_loaded']}")
        print(f"Merchants matching an indicator: {s['total_indicator_merchants']}"
              f" ({s['total_indicator_cross_merchant']} cross-merchant)")
    print(f"Chargeback exposure estimate: {s.get('currency', DEFAULT_CURRENCY)} {s['estimated_chargeback_exposure']:,.2f}")
    print(f"Output written to: {output_path}")


if __name__ == '__main__':
    main()
