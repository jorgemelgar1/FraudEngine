"""Currency detection, and a guard against the bug class that broke it.

Multi-currency shipped 2026-05-15 and never worked once. `analyze.py` defined
`_normalize_country` twice: the currency helper (lower-case, accent-folded)
at line 215, and a foreign-card comparison helper (UPPER-case) 500 lines
below. Python keeps the last definition, so every COUNTRY_TO_CURRENCY lookup
received an uppercase string, missed the lower-case keys, and fell through to
the USD default.

It hid for four months because two of the three countries genuinely use USD -
the broken lookup returned the right answer for Panama and El Salvador by
coincidence. Only Guatemala exposed it.

Run with plain python (no pytest needed):

    python tests/test_currency.py
"""

import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pandas as pd  # noqa: E402
import analyze  # noqa: E402


def _frame(country, n=5):
    return pd.DataFrame({'country_name': [country] * n})


# ── The bug itself ───────────────────────────────────────────────────────────

def test_guatemala_is_gtq():
    """The regression. This returned USD for four months."""
    assert analyze.detect_currency(_frame('Guatemala')) == 'GTQ'


def test_guatemala_in_any_casing():
    """The failure was a casing mismatch, so casing is the thing to pin down."""
    for spelling in ('Guatemala', 'GUATEMALA', 'guatemala', '  Guatemala  '):
        assert analyze.detect_currency(_frame(spelling)) == 'GTQ', spelling


def test_usd_countries():
    assert analyze.detect_currency(_frame('El Salvador')) == 'USD'
    assert analyze.detect_currency(_frame('Panama')) == 'USD'


def test_accent_folding():
    """The export writes Panamá with the accent; the table key has none."""
    assert analyze.detect_currency(_frame('Panamá')) == 'USD'


# ── No more silent defaults ──────────────────────────────────────────────────

def test_unmapped_country_is_unknown_not_usd():
    """The next country Cubo launches in must fail loudly.

    Returning USD for an unmapped country is what made the original bug
    invisible: the wrong answer looked exactly like a right one.
    """
    assert analyze.detect_currency(_frame('Costa Rica')) == 'UNKNOWN'
    assert analyze.detect_currency(_frame('Narnia')) == 'UNKNOWN'


def test_missing_country_column_is_unknown():
    assert analyze.detect_currency(pd.DataFrame({'amount': [1, 2]})) == 'UNKNOWN'


def test_empty_country_values_are_unknown():
    assert analyze.detect_currency(_frame('')) == 'UNKNOWN'


def test_explicit_fallback_still_honoured():
    """Callers may still opt into a fallback; nothing in the engine does."""
    assert analyze.detect_currency(_frame('Narnia'), default='USD') == 'USD'


# ── Provenance ───────────────────────────────────────────────────────────────

def test_source_country_is_reported():
    """Country is otherwise never persisted. Without this, a wrong currency
    code leaves nothing in the database to trace back to."""
    code, source = analyze.detect_currency_with_source(_frame('Guatemala'))
    assert code == 'GTQ'
    assert source == 'guatemala'


def test_source_is_none_when_undeterminable():
    code, source = analyze.detect_currency_with_source(_frame(''))
    assert code == 'UNKNOWN'
    assert source is None


def test_summary_carries_currency_and_source():
    fixture = os.path.join(_HERE, 'fixtures', 'synthetic.csv')
    if not os.path.exists(fixture):
        return  # fixtures are generated; skip rather than fail
    summary = analyze.analyze(fixture)['summary']
    assert 'currency' in summary
    assert 'currency_source' in summary


# ── The guard: no module may define the same top-level name twice ────────────

def test_no_shadowed_top_level_definitions():
    """This is the bug class, not just the bug.

    A second definition silently replaces the first with no warning from
    Python, no error at import, and no test failure anywhere. The only way to
    catch it is to look.
    """
    targets = [
        os.path.join(_ROOT, 'analyze.py'),
        os.path.join(_ROOT, 'api', 'analyze.py'),
        os.path.join(_ROOT, 'api', 'findings.py'),
        os.path.join(_ROOT, 'api', 'indicators.py'),
        os.path.join(_ROOT, 'desktop', 'python-src', 'main.py'),
    ]

    problems = []
    for path in targets:
        if not os.path.exists(path):
            continue
        tree = ast.parse(open(path, encoding='utf-8').read())
        seen = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in seen:
                    problems.append(
                        f'{os.path.relpath(path, _ROOT)}: {node.name} defined at '
                        f'line {seen[node.name]}, silently replaced at line {node.lineno}'
                    )
                seen[node.name] = node.lineno

    assert not problems, 'shadowed definitions:\n  ' + '\n  '.join(problems)


def test_foreign_card_helper_kept_its_behaviour():
    """The rename must not have changed what the foreign-card path does."""
    assert analyze._normalize_country_code('Guatemala') == 'GUATEMALA'
    assert analyze._normalize_country_code('  guatemala ') == 'GUATEMALA'
    assert analyze._normalize_country_code(None) is None
    assert analyze._normalize_country_code('') is None
    assert analyze._normalize_country_code('nan') is None


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
