"""Contract test: the dismissal reasons the app offers vs the ones the DB allows.

The five reasons live in two places — a check constraint in migration 0013 and
a const array in desktop/src/lib/findings.ts. If they drift, an analyst picks a
reason, hits save, and gets a raw Postgres constraint violation for an answer.

The reasons exist so "is the engine any good?" has data to answer from, so a
missing one is not cosmetic: it is a hole in the only measurement of whether
the detector is worth running.

Run with plain python (no pytest needed):

    python tests/test_review_vocabulary.py
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

_MIGRATION = os.path.join(_ROOT, 'supabase', 'migrations', '0013_review_reasons.sql')
_FINDINGS_TS = os.path.join(_ROOT, 'desktop', 'src', 'lib', 'findings.ts')


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def _sql_reasons():
    block = re.search(
        r'check \(review_reason is null or review_reason in \((.*?)\)\)',
        _read(_MIGRATION), re.S)
    assert block, 'the review_reason check constraint moved or was renamed'
    return set(re.findall(r"'([a-z_]+)'", block.group(1)))


def _ts_reasons():
    block = re.search(r'export const REVIEW_REASONS = \[(.*?)\] as const;',
                      _read(_FINDINGS_TS), re.S)
    assert block, 'REVIEW_REASONS moved or was renamed'
    return set(re.findall(r"value:\s*'([a-z_]+)'", block.group(1)))


def test_every_offered_reason_is_accepted_by_the_database():
    extra = _ts_reasons() - _sql_reasons()
    assert not extra, (
        f'the app offers {sorted(extra)}, which migration 0013 rejects. '
        f'Choosing one would fail the save with a constraint violation.')


def test_every_allowed_reason_is_offered():
    """The reverse: a reason the database accepts but nothing can produce is a
    category that will always read as zero in the breakdown."""
    missing = _sql_reasons() - _ts_reasons()
    assert not missing, (
        f'migration 0013 allows {sorted(missing)} but the app never offers '
        f'them, so no dismissal can ever carry that reason.')


def test_the_detector_error_reason_exists():
    """The one that earns the whole feature. Without separating "the engine was
    wrong" from "the engine was right and we are fine with this merchant",
    the dismissal count says nothing about whether the engine works."""
    assert 'error_detector' in _ts_reasons()
    assert 'error_detector' in _sql_reasons()


def test_the_list_stays_short():
    """Long taxonomies get answered with whichever option is first, which is
    worse than no taxonomy at all."""
    n = len(_ts_reasons())
    assert n <= 6, f'{n} reasons is too many to pick from honestly'


def test_every_reason_has_a_human_label():
    block = re.search(r'export const REVIEW_REASONS = \[(.*?)\] as const;',
                      _read(_FINDINGS_TS), re.S)
    pairs = re.findall(r"value:\s*'([a-z_]+)',\s*label:\s*'([^']+)'", block.group(1))
    assert len(pairs) == len(_ts_reasons()), 'a reason is missing its label'
    for value, label in pairs:
        assert label and label[0].isupper(), f'{value} has an odd label: {label!r}'
        assert '_' not in label, f'{value} shows its raw code as a label'


def test_precision_counts_only_decided_findings():
    """Pending findings are not evidence either way. Including them would make
    the engine look worse every time the queue grew, which is the opposite of
    what the number is for."""
    sql = _read(_MIGRATION)
    body = re.search(r'with decided as \((.*?)\)\s*select jsonb_build_object', sql, re.S)
    assert body, 'the review_stats CTE moved or was renamed'
    assert "review_status in ('accepted', 'rejected')" in body.group(1), (
        'review_stats no longer restricts to decided findings')


def test_changing_a_decision_requires_an_explanation():
    """It rewrites a record somebody else made. Enforced in SQL, not just in
    the form, so no client can skip it."""
    sql = _read(os.path.join(_ROOT, 'supabase', 'migrations',
                             '0014_watchlist_and_decisions.sql'))
    body = re.search(r'create or replace function change_review_decision(.*?)\n\$\$;',
                     sql, re.S)
    assert body, 'change_review_decision moved or was renamed'
    assert "coalesce(btrim(p_explanation), '') = ''" in body.group(1), (
        'the explanation is no longer required by the database')


def test_removing_a_merchant_requires_a_reason_and_does_not_delete():
    """The watchlist row IS the evidence that justified freezing a merchant.
    Removal marks it; deleting it destroys the record for a decision somebody
    may have to defend later."""
    sql = _read(os.path.join(_ROOT, 'supabase', 'migrations',
                             '0014_watchlist_and_decisions.sql'))
    body = re.search(
        r'create or replace function set_watchlist_merchant_removed(.*?)\n\$\$;',
        sql, re.S)
    assert body, 'set_watchlist_merchant_removed moved or was renamed'
    assert "coalesce(btrim(p_reason), '') = ''" in body.group(1), (
        'a merchant can now be removed without saying why')
    assert 'delete from watchlist_merchants' not in body.group(1), (
        'removal must be soft — the row is the audit trail')


def test_the_engine_stops_matching_removed_entries():
    """Otherwise removal is cosmetic and a wrongly-frozen merchant stays
    flagged forever. All three loaders have to filter."""
    loaders = [
        ('runner/supabase_io.py', 'removed_at=is.null'),
        ('api/analyze.py',        'removed_at=is.null'),
        ('desktop/src/lib/watchlist.ts', ".is('removed_at', null)"),
    ]
    for path, needle in loaders:
        src = _read(os.path.join(_ROOT, *path.split('/')))
        assert src.count(needle) >= 2, (
            f'{path} does not filter removed entries on BOTH the merchant and '
            f'card queries')


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
        except Exception as e:                              # noqa: BLE001
            failures += 1
            print(f'  ERROR {t.__name__}: {type(e).__name__}: {e}')
    print(f'\n{len(tests) - failures}/{len(tests)} passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
