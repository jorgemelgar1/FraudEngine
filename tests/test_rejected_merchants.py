#!/usr/bin/env python3
"""Unit tests for the suspicious-all-rejected-merchant detector.

Self-contained: run with plain `python tests/test_rejected_merchants.py`
(no pytest required), or via `pytest tests/test_rejected_merchants.py`.

All data here is fabricated — no real cardholder information.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyze  # noqa: E402

BASE = datetime(2026, 5, 20, 10, 0, 0)
COLUMNS = analyze.REQUIRED_COLUMNS


def _row(**kw):
    """One raw CSV row with sensible El-Salvador/LINK defaults."""
    defaults = {
        'transaction_id': 'tx1', 'company_name': 'M', 'company_id': 'C-M',
        'amount': 40.0, 'status': 'REJECTED', 'transaction_type': 'LINK',
        'transaction_created_at': BASE, 'last_intent_at': BASE,
        'card_last_digits': 1111, 'bin_card_number': 411111,
        'card_holder': 'JUAN PEREZ', 'card_brand': 'VISA',
        'rejection_reason': '05 - SOSPECHA DE FRAUDE', 'gateway_message': 'x',
        'ip': '186.1.1.1', 'authentication_type': 'NONE',
        'client_name': 'Juan Perez', 'client_email': 'juan@example.com',
        'client_phone': '50370000000', 'country_name': 'El Salvador',
        'risk_score': 10, 'ip_risk_score': 10,
        'card_country_mind_fraud': 'EL SALVADOR',
    }
    defaults.update(kw)
    return defaults


def _df(rows):
    df = pd.DataFrame(rows, columns=COLUMNS)
    df['last_intent_at'] = pd.to_datetime(df['last_intent_at'])
    df['transaction_created_at'] = pd.to_datetime(df['transaction_created_at'])
    return df


def _detect(rows, wl_merchants=None, wl_cards=None):
    return analyze.detect_suspicious_rejected_merchants(
        _df(rows), wl_merchants or set(), wl_cards or set(), 'USD',
    )


# ── tests ────────────────────────────────────────────────────────────────────

def test_single_card_retry_excluded():
    """One customer retrying ONE blocked card is not card testing."""
    rows = [_row(transaction_id=f'tx{i}', transaction_created_at=BASE + timedelta(minutes=2 * i))
            for i in range(8)]
    assert _detect(rows) == [], "single-card all-fail should be excluded by the card floor"


def test_two_card_zero_settlement_is_monitor():
    rows = []
    for i in range(6):
        bin_, l4 = (411111, 1111) if i % 2 == 0 else (422222, 2222)
        rows.append(_row(transaction_id=f'tx{i}', bin_card_number=bin_,
                         card_last_digits=l4,
                         transaction_created_at=BASE + timedelta(minutes=10 * i)))
    out = _detect(rows)
    assert len(out) == 1
    assert out[0]['confidence'] == 'Monitor'
    assert 'zero_settlement_session' in out[0]['fingerprints']


def test_bin_attack_burst_is_critical():
    """6 distinct cards in <5 min on one IP over LINK -> BIN-attack burst."""
    rows = []
    for i in range(6):
        rows.append(_row(transaction_id=f'tx{i}', bin_card_number=510000 + i,
                         card_last_digits=5000 + i, card_holder=f'NAME {i}',
                         transaction_created_at=BASE + timedelta(seconds=24 * i)))
    out = _detect(rows)
    assert len(out) == 1
    f = out[0]
    assert f['confidence'] == 'Critical'
    assert 'card_fanout_burst' in f['fingerprints']
    assert 'single_ip_multi_card' in f['fingerprints']
    assert f['metrics']['rejected_amount'] > 0


def test_repeated_decline_code_fingerprint():
    rows = []
    # one card declined 12x with the same code
    for i in range(12):
        rows.append(_row(transaction_id=f'a{i}', rejection_reason='14 - LLAMAR AL EMISOR',
                         transaction_created_at=BASE + timedelta(minutes=2 * i)))
    # three more distinct cards so the entry gate + diversity are satisfied
    for j, (b, l4) in enumerate([(422222, 2222), (433333, 3333), (444444, 4444)]):
        rows.append(_row(transaction_id=f'b{j}', bin_card_number=b, card_last_digits=l4,
                         transaction_created_at=BASE + timedelta(minutes=30 + j)))
    out = _detect(rows)
    assert len(out) == 1
    assert 'repeated_decline_code' in out[0]['fingerprints']
    assert out[0]['metrics']['top_code'] == '14'
    assert out[0]['metrics']['top_code_count'] >= 12


def test_pos_channel_disables_ip_and_fanout_signals():
    """On POS the ip is the terminal; per-IP / fan-out signals must NOT fire."""
    rows = []
    for i in range(6):
        rows.append(_row(transaction_id=f'tx{i}', transaction_type='POS',
                         bin_card_number=510000 + i, card_last_digits=5000 + i,
                         transaction_created_at=BASE + timedelta(seconds=24 * i)))
    out = _detect(rows)
    # It may still surface via channel-agnostic signals, but the cardholder-side
    # ones must be gated off.
    fps = out[0]['fingerprints'] if out else []
    assert 'single_ip_multi_card' not in fps
    assert 'card_fanout_burst' not in fps
    assert 'card_fanout_session' not in fps


def test_attempt_dedup_collapses_status_transitions():
    """DRAFT->PENDING->REJECTED for one attempt collapses to a single terminal
    attempt, while distinct cards are preserved."""
    rows = [
        _row(transaction_id='tx1', status='DRAFT'),
        _row(transaction_id='tx1', status='PENDING'),
        _row(transaction_id='tx1', status='REJECTED'),
        _row(transaction_id='tx2', status='REJECTED', bin_card_number=422222, card_last_digits=2222),
    ]
    attempts = analyze._build_attempts(_df(rows))
    attempts = attempts[attempts['status'] != 'DRAFT']
    assert len(attempts) == 2  # tx1 collapsed to one terminal row, tx2 separate
    assert set(attempts['status']) == {'REJECTED'}
    assert attempts['_card_key'].nunique() == 2


def test_watchlist_merchant_bump():
    rows = []
    for i in range(6):
        bin_, l4 = (411111, 1111) if i % 2 == 0 else (422222, 2222)
        rows.append(_row(transaction_id=f'tx{i}', bin_card_number=bin_, card_last_digits=l4,
                         transaction_created_at=BASE + timedelta(minutes=10 * i)))
    out = _detect(rows, wl_merchants={'M'})
    assert 'watchlist_merchant' in out[0]['fingerprints']


def test_full_analyze_preserves_existing_keys():
    """End-to-end through analyze(): the new key is added and every existing
    top-level key and summary field is still present (regression guard)."""
    rows = []
    # a clean merchant that settles -> existing behavior path
    for i in range(5):
        rows.append(_row(transaction_id=f's{i}', company_name='Good', company_id='C-G',
                         status='SUCCEEDED', transaction_type='POS', rejection_reason='',
                         transaction_created_at=BASE + timedelta(minutes=5 * i)))
    # A zero-settlement card-testing merchant that the EXISTING engine misses
    # (non-critical decline code + only 5 distinct BINs, so neither
    # critical_codes nor bin_diversity_burst fire) but the new section catches
    # via card fan-out. This mirrors the real Mandados/Kabu case.
    for i in range(6):
        rows.append(_row(transaction_id=f'z{i}', company_name='Bad', company_id='C-B',
                         bin_card_number=510000 + (i % 5), card_last_digits=5000 + (i % 5),
                         card_holder=f'NAME {i}', rejection_reason='14 - LLAMAR AL EMISOR',
                         transaction_created_at=BASE + timedelta(seconds=20 * i)))
    df = _df(rows)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'in.csv')
        df.to_csv(p, index=False)
        res = analyze.analyze(p)
    for k in ['summary', 'critical_findings', 'monitor_findings',
              'suspicious_rejected_merchants', 'duplicate_findings',
              'abandoned_findings', 'trends', 'flagged_transactions',
              'high_risk_score_transactions']:
        assert k in res, f"missing top-level key {k}"
    assert 'total_suspicious_rejected_merchants' in res['summary']
    names = [f['company_name'] for f in res['suspicious_rejected_merchants']]
    assert 'Bad' in names
    assert 'Good' not in names  # settles -> never in this section


# ── runner ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
