"""Tests for the confirmed-fraud indicator matcher (migration 0008).

Covers normalization per field type, the exact/fuzzy tiers, the cross-merchant
signal that motivated the feature, the un-indexable value guard, and the
promise that an exact hit floors the score without touching any W_* weight.

Run with plain python (no pytest needed):

    python tests/test_indicators.py
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pandas as pd  # noqa: E402
import analyze  # noqa: E402


def _ind(itype, value, **kw):
    """Build an indicator row the way Supabase would hand it over."""
    row = {
        'id': kw.get('id', f'{itype}-{value}'),
        'indicator_type': itype,
        'value_raw': value,
        'value_norm': analyze.normalize_indicator_value(itype, value),
        'match_mode': kw.get('match_mode', 'exact'),
        'active': kw.get('active', True),
        'source': kw.get('source', 'chargeback'),
        'source_company_name': kw.get('source_company_name'),
        'added_by_email': kw.get('added_by_email', 'ops@cubopago.com'),
        'added_at': kw.get('added_at', '2026-08-01T10:00:00Z'),
        'expires_at': kw.get('expires_at'),
    }
    return row


def _frame(rows):
    """Minimal frame with the columns the matcher reads."""
    cols = ['company_name', 'card_holder', 'client_name', 'client_email',
            'client_phone', 'ip', 'bin_card_number', 'card_last_digits',
            'card_key', 'company_id']
    return pd.DataFrame([{c: r.get(c) for c in cols} for r in rows])


# ── Normalization ────────────────────────────────────────────────────────────

def test_email_normalization():
    n = lambda v: analyze.normalize_indicator_value('email', v)
    # +tags are never identity
    assert n('Fraude+cubo@Example.com') == 'fraude@example.com'
    # dots are cosmetic on gmail only
    assert n('j.uan.perez@gmail.com') == 'juanperez@gmail.com'
    assert n('j.uan.perez@empresa.com') == 'j.uan.perez@empresa.com'
    assert n('not-an-email') is None


def test_phone_normalization_ignores_country_code():
    n = lambda v: analyze.normalize_indicator_value('phone', v)
    # Same line, three ways the export renders it.
    assert n('+502 5555 1234') == n('50255551234') == n('5555-1234')


def test_person_name_normalization_sorts_tokens():
    n = lambda v: analyze.normalize_indicator_value('person_name', v)
    # Cardholder field and payer field order names differently.
    assert n('JUAN PEREZ') == n('Perez, Juan') == n('juan  pérez')
    # Contactless placeholders are not identities.
    assert n('PAYWAVE/VISA') is None
    assert n('no-name') is None


def test_company_name_strips_legal_suffixes():
    n = lambda v: analyze.normalize_indicator_value('company_name', v)
    assert n('Inversiones Kabu, S.A.') == n('INVERSIONES KABU SA')


def test_card_key_accepts_the_formats_ops_actually_pastes():
    n = lambda v: analyze.normalize_indicator_value('card_key', v)
    # Separator style must not create duplicate rows.
    assert n('411111-1234') == n('411111 1234') == n('411111/1234') == '411111-1234'
    # Run together, as a spreadsheet column often renders it.
    assert n('4111111234') == '411111-1234'
    # 8-digit BINs are valid too.
    assert n('41111111-1234') == n('411111111234') == '41111111-1234'


def test_card_halves_alone_are_not_indicators():
    """A BIN is a whole issuing bank; last-4 is 1 in 10,000. Neither is a type."""
    assert 'card_bin' not in analyze.INDICATOR_SOURCE_COLUMNS
    assert 'card_last4' not in analyze.INDICATOR_SOURCE_COLUMNS
    # And neither half parses as a card on its own.
    assert analyze.normalize_indicator_value('card_key', '411111') is None
    assert analyze.normalize_indicator_value('card_key', '1234') is None


def test_full_card_number_is_refused_not_truncated():
    """Accepting a PAN would leave it sitting in value_raw. Refuse instead."""
    assert analyze.normalize_indicator_value('card_key', '4111111111111234') is None
    reason = analyze.card_key_input_error('4111111111111234')
    assert reason is not None and 'completo' in reason


def test_card_key_error_messages_are_actionable():
    assert analyze.card_key_input_error('411111-1234') is None
    assert 'BIN' in analyze.card_key_input_error('411111')
    assert analyze.card_key_input_error('') is not None


def test_card_key_is_exact_only():
    """"Nearly the same card" is a different card."""
    assert 'card_key' not in analyze.FUZZY_CAPABLE_TYPES


# ── Guard rails ──────────────────────────────────────────────────────────────

def test_public_email_domain_is_rejected():
    reason = analyze.indicator_rejection_reason('email_domain', 'gmail.com')
    assert reason is not None and 'público' in reason


def test_single_token_name_is_rejected():
    reason = analyze.indicator_rejection_reason('person_name', 'PEREZ')
    assert reason is not None


def test_full_name_is_accepted():
    norm = analyze.normalize_indicator_value('person_name', 'Juan Perez')
    assert analyze.indicator_rejection_reason('person_name', norm) is None


def test_unindexable_indicator_never_enters_the_set():
    s = analyze.FraudIndicatorSet([_ind('email_domain', 'gmail.com')])
    assert len(s) == 0, 'a public domain must not be loadable even if stored'


def test_inactive_and_expired_are_skipped():
    s = analyze.FraudIndicatorSet([
        _ind('email', 'a@x.com', id='i1', active=False),
        _ind('email', 'b@x.com', id='i2', expires_at='2020-01-01T00:00:00Z'),
        _ind('email', 'c@x.com', id='i3'),
    ])
    assert len(s) == 1


# ── Exact matching ───────────────────────────────────────────────────────────

def test_exact_email_match_across_normalization():
    """Indicator stored one way, CSV renders it another. Must still hit."""
    s = analyze.FraudIndicatorSet([_ind('email', 'fraude@example.com')])
    df = _frame([{'company_name': 'Tienda B', 'client_email': 'Fraude+promo@Example.com'}])
    hits = s.match_frame(df)
    assert 'Tienda B' in hits
    assert hits['Tienda B'][0]['match_kind'] == 'exact'


def test_person_name_matches_either_column():
    """A confirmed name should fire whether it lands in card_holder or client_name."""
    s = analyze.FraudIndicatorSet([_ind('person_name', 'Juan Perez')])

    on_card = s.match_frame(_frame([{'company_name': 'A', 'card_holder': 'PEREZ JUAN'}]))
    on_payer = s.match_frame(_frame([{'company_name': 'B', 'client_name': 'juan pérez'}]))
    assert 'A' in on_card and 'B' in on_payer


def test_one_hit_per_indicator_per_merchant():
    """40 matching rows at one merchant is one finding, not 40."""
    s = analyze.FraudIndicatorSet([_ind('email', 'x@y.com')])
    df = _frame([{'company_name': 'Tienda', 'client_email': 'x@y.com'} for _ in range(40)])
    hits = s.match_frame(df)
    assert len(hits['Tienda']) == 1


# ── The cross-merchant signal ────────────────────────────────────────────────

def test_cross_merchant_flag_set_when_seen_elsewhere():
    """The case the feature exists for: confirmed at A, shows up at B."""
    s = analyze.FraudIndicatorSet([
        _ind('email', 'malo@x.com', source_company_name='Mandados sv'),
    ])
    hits = s.match_frame(_frame([
        {'company_name': 'Comercio Nuevo', 'client_email': 'malo@x.com'},
    ]))
    hit = hits['Comercio Nuevo'][0]
    assert hit['cross_merchant'] is True
    assert hit['source_company_name'] == 'Mandados sv'


def test_same_merchant_is_not_cross_merchant():
    s = analyze.FraudIndicatorSet([
        _ind('email', 'malo@x.com', source_company_name='Mandados sv'),
    ])
    hits = s.match_frame(_frame([
        {'company_name': 'Mandados sv', 'client_email': 'malo@x.com'},
    ]))
    assert hits['Mandados sv'][0]['cross_merchant'] is False


def test_description_leads_with_the_cross_merchant_fact():
    s = analyze.FraudIndicatorSet([
        _ind('email', 'malo@x.com', source_company_name='Mandados sv'),
    ])
    hits = s.match_frame(_frame([
        {'company_name': 'Comercio Nuevo', 'client_email': 'malo@x.com'},
    ]))
    text = analyze.build_indicator_description_es(hits['Comercio Nuevo'])
    assert 'otro comercio' in text
    assert 'Mandados sv' in text
    assert 'ops@cubopago.com' in text, 'provenance must be traceable'


# ── Fuzzy matching ───────────────────────────────────────────────────────────

def test_fuzzy_name_variant_matches():
    s = analyze.FraudIndicatorSet([
        _ind('person_name', 'Estuardo Corzo', match_mode='fuzzy'),
    ])
    hits = s.match_frame(_frame([{'company_name': 'A', 'card_holder': 'ESTUARDO CORZOO'}]))
    assert 'A' in hits and hits['A'][0]['match_kind'] == 'fuzzy'


def test_fuzzy_email_same_local_new_domain():
    s = analyze.FraudIndicatorSet([
        _ind('email', 'juanperez@gmail.com', match_mode='fuzzy'),
    ])
    hits = s.match_frame(_frame([{'company_name': 'A', 'client_email': 'juanperez@outlook.com'}]))
    assert 'A' in hits


def test_fuzzy_does_not_fire_on_unrelated_names():
    s = analyze.FraudIndicatorSet([
        _ind('person_name', 'Juan Perez', match_mode='fuzzy'),
    ])
    hits = s.match_frame(_frame([{'company_name': 'A', 'card_holder': 'MARIA GOMEZ'}]))
    assert hits == {}


def test_card_key_matches_against_the_engine_card_column():
    s = analyze.FraudIndicatorSet([
        _ind('card_key', '411111-1234', source_company_name='Comercio A'),
    ])
    hits = s.match_frame(_frame([
        {'company_name': 'Comercio B', 'card_key': '411111-1234'},
    ]))
    assert 'Comercio B' in hits
    assert hits['Comercio B'][0]['cross_merchant'] is True


def test_exact_only_indicator_ignores_near_miss():
    s = analyze.FraudIndicatorSet([_ind('person_name', 'Juan Perez')])  # exact default
    hits = s.match_frame(_frame([{'company_name': 'A', 'card_holder': 'JUAN PEREZZ'}]))
    assert hits == {}


# ── Scoring integration ──────────────────────────────────────────────────────

def test_fuzzy_scoring_is_gated_off():
    """The weight freeze: fuzzy hits are reported but must not move a score."""
    assert analyze.ENABLE_FUZZY_INDICATOR_SCORING is False


def test_exact_floor_is_the_critical_line():
    """An exact hit must reach Critical without any weight change."""
    assert analyze.INDICATOR_EXACT_FLOOR == 70


def test_engine_weights_untouched():
    """Guard: this feature must not have altered the frozen scoring weights."""
    assert analyze.W_ZERO_SETTLEMENT == 25
    assert analyze.W_FANOUT_BURST == 40
    assert analyze.W_IP_MULTI_STRONG == 25
    assert analyze.SECTION_CRITICAL_THRESHOLD == 50


# ── End to end ───────────────────────────────────────────────────────────────

def test_full_analyze_flags_cross_merchant_indicator():
    """A clean merchant with one confirmed-fraud email must reach Critical."""
    import csv
    import json
    import tempfile

    fixture_dir = os.path.join(_HERE, 'fixtures')
    os.makedirs(fixture_dir, exist_ok=True)
    csv_path = os.path.join(fixture_dir, '_indicator_e2e.csv')
    ind_path = os.path.join(fixture_dir, '_indicator_e2e.json')

    cols = analyze.REQUIRED_COLUMNS
    rows = []
    for i in range(8):
        rows.append({
            'transaction_id': f'tx{i:04d}', 'company_name': 'Comercio Nuevo',
            'company_id': 'C-NEW', 'amount': 100.0, 'status': 'SUCCEEDED',
            'transaction_type': 'LINK',
            'transaction_created_at': f'2026-08-01T10:0{i}:00',
            'last_intent_at': f'2026-08-01T10:0{i}:00',
            'card_last_digits': 9000 + i, 'bin_card_number': 455555,
            'card_holder': f'CLIENTE {i}', 'card_brand': 'VISA',
            'rejection_reason': '', 'gateway_message': 'OK',
            'ip': f'10.0.0.{i}', 'authentication_type': 'NONE',
            'client_name': f'Cliente {i}', 'client_email': 'malo@fraude.com',
            'client_phone': '50255551234', 'country_name': 'Guatemala',
            'risk_score': 10, 'ip_risk_score': 10,
            'card_country_mind_fraud': 'GUATEMALA',
        })
    with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    with open(ind_path, 'w', encoding='utf-8') as fh:
        json.dump([_ind('email', 'malo@fraude.com',
                        source_company_name='Mandados sv')], fh)

    # Without indicators this merchant is unremarkable.
    baseline = analyze.analyze(csv_path)
    assert not any(f['company_name'] == 'Comercio Nuevo'
                   for f in baseline['critical_findings']), \
        'merchant should be clean before indicators are applied'

    # With the indicator it must reach Critical via the floor.
    res = analyze.analyze(csv_path, indicators_path=ind_path)
    crit = [f for f in res['critical_findings'] if f['company_name'] == 'Comercio Nuevo']
    assert crit, 'exact indicator hit must produce a Critical finding'
    f = crit[0]
    assert f['risk_score'] >= analyze.INDICATOR_EXACT_FLOOR
    assert 'confirmed_indicator_exact' in f['fingerprints']
    assert 'confirmed_indicator_cross_merchant' in f['fingerprints']
    assert f['indicator_hits'][0]['cross_merchant'] is True
    assert 'Mandados sv' in f['description_es']

    # Summary + the flat section the UI renders.
    assert res['summary']['indicators_loaded'] == 1
    assert res['summary']['total_indicator_cross_merchant'] == 1
    assert res['indicator_matches'][0]['company_name'] == 'Comercio Nuevo'

    os.remove(csv_path)
    os.remove(ind_path)


def test_missing_indicator_file_degrades_quietly():
    assert analyze.load_indicators(None) == []
    assert analyze.load_indicators('/nonexistent/path.json') == []


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failures = 0
    for t in tests:
        try:
            t()
            print(f'  PASS  {t.__name__}')
        except AssertionError as e:
            failures += 1
            print(f'  FAIL  {t.__name__}: {e}')
        except Exception as e:
            failures += 1
            print(f'  ERROR {t.__name__}: {type(e).__name__}: {e}')
    print(f'\n{len(tests) - failures}/{len(tests)} passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
