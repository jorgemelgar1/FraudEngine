"""Tests for the findings_history row mapping (migration 0007).

Covers api/analyze.py:build_findings_rows — the pure part of the persistence
path that decides, for every finding in a report, which `section` it belongs
to, whether it enters the review queue, and what exposure value it carries.

Run with plain python (no pytest needed):

    python tests/test_persistence.py
"""

import os
import sys

# api/ is a sibling of tests/ under the repo root. Put the root on sys.path so
# `import analyze` resolves inside api/analyze.py, then api/ itself so the
# module can be imported directly.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
for p in (_ROOT, os.path.join(_ROOT, 'api')):
    if p not in sys.path:
        sys.path.insert(0, p)

import importlib.util  # noqa: E402

# api/analyze.py shadows the root analyze.py by name, so load it under an
# explicit module name instead of a plain `import analyze`.
_spec = importlib.util.spec_from_file_location(
    'api_analyze', os.path.join(_ROOT, 'api', 'analyze.py'),
)
api_analyze = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_analyze)

build_findings_rows = api_analyze.build_findings_rows

RUN_ID = '00000000-0000-0000-0000-000000000001'


def _report(**sections):
    """Minimal report dict with a summary and whichever sections are given."""
    return {
        'summary': {'currency': 'GTQ'},
        'critical_findings': sections.get('critical', []),
        'monitor_findings': sections.get('monitor', []),
        'suspicious_rejected_merchants': sections.get('zero_settlement', []),
    }


def _exposure_critical(name='Tienda A'):
    return {
        'type': 'stolen_card_ring',
        'company_name': name,
        'company_id': 'c-1',
        'risk_score': 85,
        'confidence': 'Critical',
        'fingerprints': ['cross_merchant_reuse'],
        'action_code': 'FREEZE',
        'estimated_chargeback_exposure': 1234.56,
        'description_es': 'desc',
    }


def _exposure_monitor(name='Tienda B'):
    return {
        'type': 'velocity',
        'company_name': name,
        'company_id': 'c-2',
        'risk_score': 45,
        'confidence': 'Monitor',
        'fingerprints': ['velocity_burst'],
        'action_code': 'MONITOR',
        'description_es': 'desc',
    }


def _zero_settlement(name='Mandados sv', confidence='Critical'):
    return {
        'type': 'zero_settlement_card_testing',
        'company_name': name,
        'company_id': 'c-3',
        'risk_score': 65 if confidence == 'Critical' else 30,
        'confidence': confidence,
        'fingerprints': ['zero_settlement_session', 'card_fanout_burst'],
        'action_code': 'REVIEW_MERCHANT',
        'currency': 'USD',
        'description_es': 'desc',
        'evidence': [{'card_bin': '439093', 'card_last_digits': '1234'}],
    }


# ── Tests ────────────────────────────────────────────────────────────────────

def test_sections_are_labelled():
    """Each source list maps to the right `section` value."""
    ordered, rows = build_findings_rows(RUN_ID, _report(
        critical=[_exposure_critical()],
        monitor=[_exposure_monitor()],
        zero_settlement=[_zero_settlement()],
    ))
    assert len(rows) == 3, rows
    assert [r['section'] for r in rows] == ['exposure', 'exposure', 'zero_settlement']
    # `ordered` must stay aligned with `rows` — the id write-back zips them.
    assert [s for _f, s in ordered] == [r['section'] for r in rows]
    assert [f['company_name'] for f, _s in ordered] == [r['company_name'] for r in rows]


def test_review_status_follows_tier_not_section():
    """Critical is reviewable in BOTH sections; Monitor never is."""
    ordered, rows = build_findings_rows(RUN_ID, _report(
        critical=[_exposure_critical()],
        monitor=[_exposure_monitor()],
        zero_settlement=[
            _zero_settlement('Mandados sv', 'Critical'),
            _zero_settlement('Inversiones Kabu', 'Monitor'),
        ],
    ))
    by_name = {r['company_name']: r for r in rows}
    assert by_name['Tienda A']['review_status'] == 'pending'
    assert by_name['Tienda B']['review_status'] == 'not_applicable'
    # The whole point of migration 0007: a zero-settlement Critical queues up
    # for review exactly like an exposure Critical.
    assert by_name['Mandados sv']['review_status'] == 'pending'
    assert by_name['Inversiones Kabu']['review_status'] == 'not_applicable'


def test_zero_settlement_has_null_exposure():
    """Zero-settlement findings settle nothing, so exposure must be NULL."""
    _ordered, rows = build_findings_rows(RUN_ID, _report(
        critical=[_exposure_critical()],
        zero_settlement=[_zero_settlement()],
    ))
    by_name = {r['company_name']: r for r in rows}
    assert by_name['Tienda A']['chargeback_exposure_usd'] == 1234.56
    assert by_name['Mandados sv']['chargeback_exposure_usd'] is None


def test_currency_falls_back_to_run_currency():
    """Per-finding currency wins; otherwise the run's summary currency."""
    _ordered, rows = build_findings_rows(RUN_ID, _report(
        critical=[_exposure_critical()],       # no per-finding currency
        zero_settlement=[_zero_settlement()],  # carries 'USD'
    ))
    by_name = {r['company_name']: r for r in rows}
    assert by_name['Tienda A']['chargeback_exposure_currency'] == 'GTQ'
    assert by_name['Mandados sv']['chargeback_exposure_currency'] == 'USD'


def test_evidence_survives_into_payload():
    """Accept upserts cards from payload->evidence, so it must round-trip."""
    _ordered, rows = build_findings_rows(RUN_ID, _report(
        zero_settlement=[_zero_settlement()],
    ))
    evidence = rows[0]['payload']['evidence']
    assert evidence[0]['card_bin'] == '439093'
    assert evidence[0]['card_last_digits'] == '1234'


def test_report_without_zero_settlement_key():
    """Reports from a sidecar predating the detector must still map cleanly."""
    legacy = {
        'summary': {'currency': 'USD'},
        'critical_findings': [_exposure_critical()],
        'monitor_findings': [],
    }
    _ordered, rows = build_findings_rows(RUN_ID, legacy)
    assert len(rows) == 1
    assert rows[0]['section'] == 'exposure'


def test_empty_report_produces_no_rows():
    ordered, rows = build_findings_rows(RUN_ID, _report())
    assert ordered == []
    assert rows == []


def test_every_row_satisfies_not_null_columns():
    """findings_history NOT NULLs: run_id, company_name, finding_type,
    confidence, risk_score, fingerprints, payload."""
    _ordered, rows = build_findings_rows(RUN_ID, _report(
        critical=[_exposure_critical()],
        monitor=[_exposure_monitor()],
        zero_settlement=[_zero_settlement()],
    ))
    required = ('run_id', 'company_name', 'finding_type', 'confidence',
                'risk_score', 'fingerprints', 'payload')
    for r in rows:
        for col in required:
            assert r.get(col) is not None, f'{col} is NULL in {r["company_name"]}'
        assert r['run_id'] == RUN_ID
        # Section must satisfy the 0007 check constraint.
        assert r['section'] in ('exposure', 'zero_settlement')
        # review_status must satisfy the 0004 check constraint.
        assert r['review_status'] in (
            'pending', 'accepted', 'rejected', 'not_applicable',
        )


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
