#!/usr/bin/env python3
"""Regression tests for the 2026-09 finding-integrity fixes.

Self-contained: run with plain `python tests/test_finding_integrity.py`
(no pytest required), or via `pytest tests/test_finding_integrity.py`.

Every bug pinned here was found by an external review of analyze.py and
reproduced against the real engine before being fixed. They share a theme:
the detectors were right and the plumbing around them was wrong, so findings
were suppressed, mis-attributed, or quoted the wrong rows. None of them
needed a weight change to fix, which is why the W_* constants are untouched.

All data here is fabricated — no real cardholder information.
"""
import csv
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyze  # noqa: E402

COLUMNS = analyze.REQUIRED_COLUMNS
_TMP = tempfile.mkdtemp(prefix='cubo-finding-integrity-')


def _row(**kw):
    """One raw CSV row with sensible Guatemala/LINK defaults."""
    r = {c: '' for c in COLUMNS}
    r.update({
        'company_name': 'M', 'company_id': 'C-M', 'amount': '100',
        'status': 'REJECTED', 'transaction_type': 'LINK', 'card_brand': 'VISA',
        'country_name': 'Guatemala', 'risk_score': '10', 'ip_risk_score': '10',
        'card_country_mind_fraud': 'GT', 'ip': '1.2.3.4',
    })
    r.update(kw)
    return r


def _stamp(minutes_from_start):
    """Wall-clock string `minutes_from_start` after 2026-09-01 10:00."""
    total = 10 * 60 + minutes_from_start
    return '2026-09-%02d %02d:%02d:00' % (1 + total // 1440, (total % 1440) // 60, total % 60)


def _write(rows, name):
    path = os.path.join(_TMP, name)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return path


def _card_testing_session(reason, n=6, spacing=600, company='ACME'):
    """A zero-settlement card-testing session: n cards, all declined.

    `spacing` in minutes. The default puts the attempts outside every card
    fan-out window, which is what keeps the exposure model in the Monitor
    band and makes the severity interaction below visible.
    """
    rows = []
    for i in range(n):
        rows.append(_row(
            transaction_id='T%d' % i, company_name=company,
            transaction_created_at=_stamp(i * spacing),
            last_intent_at=_stamp(i * spacing),
            card_last_digits='%04d' % (1000 + i),
            bin_card_number='%06d' % (411111 + i),
            card_holder='PERSON %d' % i, rejection_reason=reason,
            ip='10.0.0.%d' % i, client_name='P%d' % i,
            client_email='p%d@x.com' % i,
        ))
    return rows


def _all_findings(out):
    return (out['critical_findings'] + out['monitor_findings']
            + out['suspicious_rejected_merchants'])


# ── Severity is preserved across sections ────────────────────────────────────

def test_a_fraud_decline_code_does_not_hide_a_critical_finding():
    """The bug that inverted the engine's own signal.

    The two models have different Critical lines (70 for exposure, 50 for
    card-testing). Deduplication compared them by SECTION, so a Monitor
    exposure finding suppressed a Critical card-testing one — and only
    Critical findings are queued for review. Because fraud-specific decline
    codes are what push the exposure score into the Monitor band, the clearer
    the fraud, the more likely the finding vanished.

    Both sessions below are the same attack. Only the decline reason differs.
    """
    for reason in ('51 - FONDOS INSUFICIENTES', '05 - SOSPECHA DE FRAUDE'):
        out = analyze.analyze(_write(_card_testing_session(reason), 'sev.csv'))
        criticals = [f for f in _all_findings(out) if f['confidence'] == 'Critical']
        assert criticals, 'no Critical finding survived for reason %r' % reason
        assert any(f['company_name'] == 'ACME' for f in criticals), \
            'ACME lost its Critical finding for reason %r' % reason


def test_the_surviving_finding_keeps_the_suppressed_one_s_reasons():
    """Whichever listing loses must donate its fingerprints to the winner,
    so the reason it fired is not lost along with its row."""
    out = analyze.analyze(
        _write(_card_testing_session('05 - SOSPECHA DE FRAUDE'), 'sev2.csv'))
    findings = [f for f in _all_findings(out) if f['company_name'] == 'ACME']
    assert len(findings) == 1, 'ACME should be listed exactly once'
    fps = findings[0]['fingerprints']
    # 'critical_codes' comes from the exposure model, 'zero_settlement_session'
    # from the card-testing one. Both fired; both must still be visible.
    assert 'zero_settlement_session' in fps, fps
    assert 'critical_codes' in fps, fps


# ── Evidence names the rows that triggered the finding ───────────────────────

def test_evidence_quotes_the_attack_not_the_first_five_rows():
    """Evidence used to be `group.head(5)` — the merchant's earliest rows.

    This matters far beyond presentation: accept_finding (migration 0004)
    writes every card in `payload->'evidence'` to the permanent watchlist. So
    the old behaviour watchlisted the first five customers of the day and left
    the attacker's cards unrecorded, on a table that is never pruned.
    """
    rows = []
    for i in range(5):        # ordinary sales, earliest in the file
        rows.append(_row(
            transaction_id='S%d' % i, company_name='SHOP', amount='250',
            status='SUCCEEDED', transaction_created_at=_stamp(i),
            last_intent_at=_stamp(i), card_last_digits='%04d' % (9000 + i),
            bin_card_number='555555', card_holder='GOOD CUSTOMER %d' % i,
            rejection_reason='', ip='9.9.9.9', client_name='G%d' % i,
            client_email='g%d@x.com' % i,
        ))
    for i in range(8):        # the attack, later
        rows.append(_row(
            transaction_id='F%d' % i, company_name='SHOP',
            transaction_created_at=_stamp(600 + i), last_intent_at=_stamp(600 + i),
            card_last_digits='%04d' % (2000 + i),
            bin_card_number='%06d' % (422222 + i),
            card_holder='ATTACKER %d' % i,
            rejection_reason='05 - SOSPECHA DE FRAUDE', ip='6.6.6.6',
            client_name='A%d' % i, client_email='a%d@x.com' % i,
        ))

    out = analyze.analyze(_write(rows, 'evidence.csv'))
    findings = _all_findings(out)
    assert findings, 'the attack produced no finding at all'

    evidence = findings[0]['evidence']
    assert evidence, 'finding carried no evidence'
    good = {'%04d' % (9000 + i) for i in range(5)}
    attack = {'%04d' % (2000 + i) for i in range(8)}
    quoted = {e['card_last_digits'] for e in evidence}

    assert quoted & attack, 'evidence names none of the cards that triggered it'
    assert not (quoted & good), \
        'evidence still names innocent cards, which acceptance would watchlist: %s' % (quoted & good)


def test_evidence_is_not_padded_with_unrelated_rows():
    """Under-filling is correct. Every extra evidence row becomes a permanent
    watchlist entry when an analyst accepts the finding, so a finding with
    three triggering rows must quote three, not three plus two bystanders."""
    rows = []
    for i in range(10):       # bystanders
        rows.append(_row(
            transaction_id='OK%d' % i, company_name='LADDER', amount='500',
            status='SUCCEEDED', transaction_created_at=_stamp(i),
            last_intent_at=_stamp(i), card_last_digits='%04d' % (7000 + i),
            bin_card_number='555555', card_holder='CUSTOMER %d' % i,
            rejection_reason='', client_name='C%d' % i,
            client_email='c%d@x.com' % i,
        ))
    for i, amt in enumerate((10, 20, 30)):   # one card walked up the amounts
        rows.append(_row(
            transaction_id='L%d' % i, company_name='LADDER', amount=str(amt),
            status='REJECTED', transaction_created_at=_stamp(300 + i),
            last_intent_at=_stamp(300 + i), card_last_digits='4242',
            bin_card_number='411111', card_holder='LADDER GUY',
            rejection_reason='05 - SOSPECHA DE FRAUDE',
            client_name='L', client_email='l@x.com',
        ))

    path = _write(rows, 'ladder.csv')
    _, df_u = analyze.load_and_dedupe(path)
    group = df_u[df_u['company_name'] == 'LADDER']

    triggers = set(analyze.detect_amount_ladder(group))
    assert len(triggers) == 3, 'the ladder detector should name its three rows'

    picked = analyze._select_evidence_rows(group, triggers)
    assert len(picked) == 3, \
        'evidence padded to %d rows when only 3 triggered' % len(picked)
    assert set(picked['card_last_digits']) == {'4242'}, \
        'evidence names cards that did not trigger: %s' % set(picked['card_last_digits'])

    # And with no triggers at all it must still prefer declined rows over the
    # merchant's earliest ones, rather than falling back to position.
    fallback = analyze._select_evidence_rows(group, set())
    assert set(fallback['status']) == {'REJECTED'}, \
        'fallback quoted settled rows while declines were available'


# ── Attribution ──────────────────────────────────────────────────────────────

def _switch_pair(reject_at, succeed_at):
    return [
        _row(transaction_id='X1', company_name=reject_at, company_id='CA',
             amount='500', status='REJECTED', transaction_type='POS',
             transaction_created_at=_stamp(0), last_intent_at=_stamp(0),
             card_last_digits='4242', bin_card_number='411111',
             card_holder='JUAN PEREZ', rejection_reason='05 - SOSPECHA DE FRAUDE',
             ip='5.5.5.5', client_name='Juan', client_email='j@x.com'),
        _row(transaction_id='X2', company_name=succeed_at, company_id='CB',
             amount='500', status='SUCCEEDED', transaction_type='LINK',
             transaction_created_at=_stamp(2), last_intent_at=_stamp(2),
             card_last_digits='4242', bin_card_number='411111',
             card_holder='JUAN PEREZ', rejection_reason='',
             ip='5.5.5.5', client_name='Juan', client_email='j@x.com'),
    ]


def test_channel_switch_does_not_blame_the_merchant_that_declined():
    """The detector groups by card, so the retry can land at a different
    merchant. It used to report that as one merchant switching its own
    channel, attributed to the merchant that did the DECLINING — scoring the
    merchant whose fraud control worked, and never naming the one that took
    the money."""
    path = _write(_switch_pair('MERCH_A', 'MERCH_B'), 'cross.csv')
    _, df_u = analyze.load_and_dedupe(path)
    hits = analyze.detect_channel_switch(df_u)
    assert len(hits) == 1
    assert hits[0]['cross_merchant'] is True
    assert hits[0]['rejected_company_name'] == 'MERCH_A'
    assert hits[0]['succeeded_company_name'] == 'MERCH_B'

    out = analyze.analyze(path)
    a = [f for f in _all_findings(out) if f['company_name'] == 'MERCH_A']
    assert a, 'MERCH_A should still be scored for its own fraud-coded rejection'
    assert not any('switch' in fp for fp in a[0]['fingerprints']), \
        'MERCH_A is still scored for a channel switch that happened elsewhere'
    assert out['trends']['cross_merchant_channel_switch'], \
        'the cross-merchant pattern must still be reported somewhere'


def test_same_merchant_channel_switch_still_scores():
    """The fix must not cost the engine the signal it was built for."""
    path = _write(_switch_pair('MERCH_A', 'MERCH_A'), 'same.csv')
    _, df_u = analyze.load_and_dedupe(path)
    hits = analyze.detect_channel_switch(df_u)
    assert len(hits) == 1
    assert hits[0]['cross_merchant'] is False

    out = analyze.analyze(path)
    a = [f for f in _all_findings(out) if f['company_name'] == 'MERCH_A']
    assert a, 'same-merchant channel switch stopped producing a finding'
    assert any('switch' in fp for fp in a[0]['fingerprints']), a[0]['fingerprints']


# ── Attempt timing ───────────────────────────────────────────────────────────

def test_attempts_hours_apart_are_not_a_five_minute_burst():
    """Several attempts on one transaction_id share a single
    transaction_created_at. Timing card fan-out on that column turned a slow
    grind into the top burst tier, worth 40 points."""
    rows = []
    for i in range(6):
        rows.append(_row(
            transaction_id='ONE', company_name='BURST',
            transaction_created_at=_stamp(0),        # identical for all six
            last_intent_at=_stamp(i * 60),           # one hour apart
            card_last_digits='%04d' % (5000 + i),
            bin_card_number='%06d' % (455555 + i),
            card_holder='Y %d' % i,
            rejection_reason='51 - FONDOS INSUFICIENTES', ip='8.8.8.8',
            client_name='Y%d' % i, client_email='y%d@x.com' % i,
        ))
    out = analyze.analyze(_write(rows, 'burst.csv'))
    for f in out['suspicious_rejected_merchants']:
        assert 'card_fanout_burst' not in f['fingerprints'], \
            'attempts an hour apart still count as a <5 min burst'


# ── Unresolved sessions ──────────────────────────────────────────────────────

def _retry_pair(shared_id):
    """A fraud-coded decline, then a successful retry on another channel two
    minutes later. With `shared_id` both attempts carry one transaction_id,
    which is how the export represents a retry against the same payment."""
    tx_b = 'TX1' if shared_id else 'TX2'
    return [
        _row(transaction_id='TX1', company_name='RETRY', amount='500',
             status='REJECTED', transaction_type='POS',
             transaction_created_at=_stamp(0), last_intent_at=_stamp(0),
             card_last_digits='4242', bin_card_number='411111',
             card_holder='JUAN PEREZ', rejection_reason='05 - SOSPECHA DE FRAUDE',
             ip='5.5.5.5', client_name='Juan', client_email='j@x.com'),
        _row(transaction_id=tx_b, company_name='RETRY', amount='500',
             status='SUCCEEDED', transaction_type='LINK',
             transaction_created_at=_stamp(2), last_intent_at=_stamp(2),
             card_last_digits='4242', bin_card_number='411111',
             card_holder='JUAN PEREZ', rejection_reason='',
             ip='5.5.5.5', client_name='Juan', client_email='j@x.com'),
    ]


def test_a_retry_is_kept_whether_or_not_it_shares_a_transaction_id():
    """Deduplication used to collapse by transaction_id alone, which removed
    two different kinds of duplicate: a payment's DRAFT/PENDING/final status
    rows (noise) and its separate ATTEMPTS (evidence).

    A decline followed by a successful retry therefore became one successful
    row, and the pattern vanished. Whether the engine saw the attack came down
    to whether the processor issued one transaction_id or two — nothing about
    the fraud itself."""
    results = {}
    for shared in (False, True):
        path = _write(_retry_pair(shared), 'retry-%s.csv' % shared)
        _, df_u = analyze.load_and_dedupe(path)
        out = analyze.analyze(path)
        findings = [f for f in _all_findings(out) if f['company_name'] == 'RETRY']
        results[shared] = {
            'rows': len(df_u),
            'switches': len(analyze.detect_channel_switch(df_u)),
            'fingerprints': sorted(findings[0]['fingerprints']) if findings else [],
            'score': findings[0]['risk_score'] if findings else None,
        }

    assert results[True]['rows'] == 2, \
        'the retry was collapsed away: %d row(s) survived' % results[True]['rows']
    assert results[True] == results[False], \
        'one transaction_id gives a different answer than two:\n  two: %s\n  one: %s' % (
            results[False], results[True])
    assert 'channel_switch_retry' in results[True]['fingerprints'], results[True]


def test_transaction_and_attempt_counts_stay_distinct():
    """df_u is now one row per attempt, so `unique_transactions` — which the
    dashboard renders as "Transacciones" — must still count payments. Reusing
    len(df_u) would have quietly inflated it."""
    out = analyze.analyze(_write(_retry_pair(shared_id=True), 'counts.csv'))
    assert out['summary']['unique_transactions'] == 1, out['summary']['unique_transactions']
    assert out['summary']['total_attempts'] == 2, out['summary']['total_attempts']


def test_monitor_findings_carry_the_rows_that_triggered_them():
    """A Monitor finding used to be a score and a sentence with nothing behind
    them — an analyst opening one in Historial could not check the claim.

    Evidence here is safe: _accept_one_finding (migration 0004) refuses any
    finding whose review_status is not 'pending' and whose confidence is not
    'Critical', and Monitor findings fail both, so these rows can never reach
    the watchlist."""
    out = analyze.analyze(_write(_retry_pair(shared_id=False), 'monitorev.csv'))
    monitors = [f for f in out['monitor_findings']]
    assert monitors, 'this fixture is meant to produce a Monitor finding'
    for f in monitors:
        assert 'evidence' in f, 'Monitor finding has no evidence key'
        assert f['evidence'], 'Monitor finding has an empty evidence list'
        assert 'evidence_count' in f, 'evidence_count was dropped'
        for e in f['evidence']:
            assert 'transaction_id' in e and 'status' in e, e


def test_pending_only_session_cannot_reach_critical():
    """PENDING means the payment has not resolved. Six pending checkouts used
    to score Critical/100 with no decline and no aging rule, which is
    indistinguishable from a shopper who abandoned six carts."""
    rows = []
    for i in range(6):
        rows.append(_row(
            transaction_id='P%d' % i, company_name='PEND', status='PENDING',
            transaction_created_at=_stamp(i), last_intent_at=_stamp(i),
            card_last_digits='%04d' % (3000 + i),
            bin_card_number='%06d' % (433333 + i),
            card_holder='X %d' % i, rejection_reason='', ip='7.7.7.7',
            client_name='X%d' % i, client_email='x%d@x.com' % i,
        ))
    out = analyze.analyze(_write(rows, 'pending.csv'))
    for f in out['suspicious_rejected_merchants']:
        assert f['confidence'] != 'Critical', \
            'a session with nothing declined reached Critical'
        assert 'unresolved_attempts_only' in f['fingerprints']


# ── Normalization ────────────────────────────────────────────────────────────

def test_identifier_columns_survive_a_blank_cell():
    """A single blank cell makes pandas type the whole column float64, so
    50212345678 arrives as 50212345678.0 whose digits end in a spurious zero.
    norm_phone keeps the last 8, so the stored indicator and the CSV value
    disagreed and phone indicators could never fire."""
    rows = [
        _row(transaction_id='A', client_phone='50212345678',
             transaction_created_at=_stamp(0), last_intent_at=_stamp(0),
             card_last_digits='1111', bin_card_number='411111'),
        _row(transaction_id='B', client_phone='',          # the blank
             transaction_created_at=_stamp(1), last_intent_at=_stamp(1),
             card_last_digits='2222', bin_card_number='411111'),
    ]
    _, df_u = analyze.load_and_dedupe(_write(rows, 'phone.csv'))
    from_csv = analyze.norm_phone(df_u.loc[df_u['transaction_id'] == 'A', 'client_phone'].iloc[0])
    assert from_csv == analyze.norm_phone('50212345678'), \
        'CSV phone %r does not match the same number typed as an indicator' % from_csv


def test_fraud_codes_are_matched_on_their_stable_prefix():
    """The text after the code is not stable in the export — capitalisation,
    padding, misspellings and channel suffixes all vary. Full-string equality
    silently treated every variant as "not a fraud code"."""
    for variant in ('05 - SOSPECHA DE FRAUDE',
                    '05 - Sospecha de Fraude',
                    ' 05 - SOSPECHA DE FRAUDE ',
                    '05 - SOSPECHA DE FRAUDE (POS)'):
        assert analyze.is_critical_code(variant), 'not recognised: %r' % variant

    # Codes that are genuinely only Monitor must not be promoted by this.
    assert not analyze.is_critical_code('34 - LLAMAR AL EMISOR')
    assert analyze.is_monitor_code('34 - llamar al emisor')
    assert not analyze.is_critical_code('')
    assert not analyze.is_critical_code(None)


def test_domestic_cards_are_not_foreign():
    """`country_name` spells countries out; `card_country_mind_fraud` uses a
    code. Uppercasing alone left 'SV' != 'EL SALVADOR', so the foreign-card
    rule fired on ordinary domestic traffic."""
    assert analyze._normalize_country_code('SV') == analyze._normalize_country_code('El Salvador')
    assert analyze._normalize_country_code('GT') == analyze._normalize_country_code('Guatemala')
    assert analyze._normalize_country_code('PA') == analyze._normalize_country_code('Panama')


def test_velocity_bands_follow_the_currency():
    """Tiers were USD-shaped and applied to whatever number the CSV carried,
    so a GTQ ticket worth about USD 30 was treated as a big-ticket merchant
    and held to a fifth of the allowance."""
    usd_small = analyze.velocity_ceiling(30, 'USD')
    gtq_same = analyze.velocity_ceiling(231, 'GTQ')     # ≈ USD 30
    assert usd_small == gtq_same, \
        'USD %s/min vs GTQ %s/min for the same real ticket' % (usd_small, gtq_same)
    # A genuinely large local ticket must still be held to the tight ceiling.
    assert analyze.velocity_ceiling(5000, 'GTQ') < usd_small
    # An unknown currency falls back to the USD bands rather than crashing.
    assert analyze.velocity_ceiling(30, 'XYZ') == usd_small


def test_settlement_wording_matches_what_actually_settled():
    """The gate admits sessions up to ZERO_SETTLEMENT_MAX_SUCCESS_RATE, so a
    finding can be raised on a session that did settle something. Telling the
    analyst 'nada se liquidó' in that case is simply false."""
    rows = _card_testing_session('05 - SOSPECHA DE FRAUDE', n=20, spacing=30,
                                 company='PARTIAL')
    rows[0]['status'] = 'SUCCEEDED'          # 1 of 20 = 5%, still inside the gate
    out = analyze.analyze(_write(rows, 'partial.csv'))

    partial = [f for f in out['suspicious_rejected_merchants']
               if f['company_name'] == 'PARTIAL']
    # Asserted, not assumed: without this the loop below has nothing to check
    # and the test passes by doing nothing.
    assert partial, 'the partial-settlement session produced no finding to inspect'

    for f in partial:
        assert f['metrics']['succeeded'] == 1, f['metrics']
        assert 'nada se liquidó' not in f['recommended_action_es'], \
            'claims nothing settled when %d payment(s) did' % f['metrics']['succeeded']
        assert 'casi nula' in f['recommended_action_es'], \
            'should say settlement was near-zero, not absent'


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failures = 0
    for t in tests:
        try:
            t()
            print('  PASS  %s' % t.__name__)
        except AssertionError as e:
            failures += 1
            print('  FAIL  %s: %s' % (t.__name__, e))
        except Exception as e:                       # noqa: BLE001
            failures += 1
            print('  ERROR %s: %s: %s' % (t.__name__, type(e).__name__, e))
    print('\n%d/%d passed' % (len(tests) - failures, len(tests)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
