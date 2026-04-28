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


def load_and_dedupe(csv_path):
    """
    Load the CSV and deduplicate to one row per transaction_id
    (keeping the final status transition).

    Schema is validated immediately after the CSV is parsed and before any
    columns are touched — otherwise a missing required column raises
    KeyError from inside pd.to_datetime instead of the friendly
    "Missing required columns" error.
    """
    df = pd.read_csv(csv_path, low_memory=False)
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

    # Exclude transactions with critical codes or MinFraud blocks on the row itself
    tainted_row = (df['rejection_reason'].apply(is_critical_code)
                   | df['rejection_reason'].apply(is_minfraud_blocked))
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

def analyze(csv_path, watchlist_path=None):
    # Schema is validated inside load_and_dedupe before any columns get touched.
    df_raw, df_u = load_and_dedupe(csv_path)

    # Watchlist — both merchants and cards persist permanently once flagged.
    watchlist = load_watchlist(watchlist_path) if watchlist_path else {'merchants': {}, 'cards': {}}
    watchlist_merchants = set(watchlist['merchants'].keys())
    watchlist_cards = set(watchlist['cards'].keys())

    # Date range
    date_start = df_u['transaction_created_at'].min()
    date_end = df_u['transaction_created_at'].max()
    date_str = date_start.isoformat() if pd.notna(date_start) else datetime.now(timezone.utc).isoformat()

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

        reason = group['rejection_reason']
        critical_code_rows = group[reason.apply(is_critical_code)]
        minfraud_rows = group[reason.apply(is_minfraud_blocked)]

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

        if risk_score < 20:
            continue

        # Build finding object
        ticket_rows = group[succeeded_mask]
        exposure = 0
        if switches_here:
            exposure += sum(s['amount'] for s in switches_here)
        if ladder_hit or velocity_hit:
            # Successful charges during a fraud burst are chargeback risk
            exposure += float(ticket_rows['amount'].sum()) if len(ticket_rows) > 0 else 0

        # Evidence: first 5 rows. df_u is already globally time-sorted, so no
        # need to re-sort the per-merchant slice.
        evidence_rows = group.head(5)
        evidence = []
        for _, r in evidence_rows.iterrows():
            evidence.append({
                'transaction_id': r['transaction_id'],
                'amount': float(r['amount']) if pd.notna(r['amount']) else None,
                'status': r['status'],
                'rejection_reason': r['rejection_reason'] if pd.notna(r['rejection_reason']) else None,
                'timestamp': str(r['transaction_created_at']),
                'card_bin': f"{int(r['bin_card_number']):06d}" if pd.notna(r['bin_card_number']) else None,
                'card_last_digits': f"{int(r['card_last_digits']):04d}" if pd.notna(r['card_last_digits']) else None,
                'card_holder': r['card_holder'] if pd.notna(r['card_holder']) else None,
            })

        # Classify as critical or monitor
        if risk_score >= 70:
            confidence = 'Critical'
            action_code = decide_action(fingerprints, switches_here, cross_here)
            description = build_description_es(mname, fingerprints, group, watchlist_merchants)
            action_es = build_action_es(action_code, len(ticket_rows), exposure)
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
                'total_transactions': n_total,
                'rejected_count': n_rej,
                'succeeded_count': n_succ,
            })
        elif risk_score >= 40:
            confidence = 'Monitor'
            description = build_description_es(mname, fingerprints, group, watchlist_merchants)
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
        'total_high_risk_score_transactions': len(high_risk_score_transactions),
        'total_foreign_card_velocity_merchants': len(foreign_card_bursts),
    }

    return {
        'summary': summary,
        'critical_findings': sorted(critical_findings, key=lambda x: -x['risk_score']),
        'monitor_findings': sorted(monitor_findings, key=lambda x: -x['risk_score']),
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
        critical_count = sum(1 for r in group['rejection_reason'] if is_critical_code(r))
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


def build_action_es(action_code, n_successful, exposure):
    if action_code == 'FREEZE_MERCHANT':
        return f"Congelar cuenta del merchant y retener depósito. Revisar los {n_successful} cargos exitosos (USD ${exposure:.2f}) para exposición a chargebacks."
    elif action_code == 'REVIEW_CHARGE':
        return f"Revisar el cargo exitoso de USD ${exposure:.2f} — riesgo alto de chargeback por channel-switch retry."
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
    parser.add_argument('--output')
    args = parser.parse_args()

    if args.validate_only:
        df = pd.read_csv(args.csv_path, nrows=5)
        ok, missing_req, missing_opt = validate_schema(df)
        print(json.dumps({
            'schema_ok': ok,
            'missing_required': missing_req,
            'missing_optional': missing_opt,
        }, indent=2))
        sys.exit(0 if ok else 1)

    wl_path = args.update_watchlist or args.watchlist
    findings = analyze(args.csv_path, watchlist_path=wl_path)

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
    print(f"Chargeback exposure estimate: ${s['estimated_chargeback_exposure']:,.2f}")
    print(f"Output written to: {output_path}")


if __name__ == '__main__':
    main()
