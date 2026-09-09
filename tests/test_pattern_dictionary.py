"""Contract test: every code the engine emits has plain Spanish in the app.

The engine speaks in codes — `bin_diversity_burst`, `channel_switch_retry` —
and desktop/src/lib/patterns.ts turns them into sentences an analyst can read.
Nothing connects the two, so adding a detector to analyze.py and forgetting the
dictionary puts a raw snake_case identifier in front of a human. It does not
crash and it does not look like a bug; it looks like the tool is half-finished.

Same for `finding_type`, which supplies the one-line verdict at the top of
every row, and `action_code`, which supplies the recommendation. A missing
entry there silently degrades to a generic label.

Why the dictionary lives in the app at all: the desktop analyzer is a frozen
PyInstaller snapshot of analyze.py, so changing wording in the engine forces a
sidecar rebuild and puts scoring logic in the blast radius of a copy edit.

Run with plain python (no pytest needed):

    python tests/test_pattern_dictionary.py
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

_ENGINE = os.path.join(_ROOT, 'analyze.py')
_PATTERNS_TS = os.path.join(_ROOT, 'desktop', 'src', 'lib', 'patterns.ts')


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def _engine_fingerprints():
    """Every code analyze.py can append to a finding's `fingerprints`."""
    src = _read(_ENGINE)
    codes = set(re.findall(r"fingerprints\.append\('([a-z0-9_]+)'\)", src))
    assert codes, 'no fingerprints found — did the append pattern change?'
    return codes


def _engine_finding_types():
    """Every value classify_finding_type() can return."""
    src = _read(_ENGINE)
    body = re.search(r'def classify_finding_type\(.*?\n(?=\n*def )', src, re.S)
    assert body, 'classify_finding_type moved or was renamed'
    return set(re.findall(r"return '([a-z_]+)'", body.group(0)))


def _engine_action_codes():
    src = _read(_ENGINE)
    body = re.search(r'def decide_action\(.*?\n(?=\n*def )', src, re.S)
    assert body, 'decide_action moved or was renamed'
    return set(re.findall(r"return '([A-Z_]+)'", body.group(0)))


def _ts_keys(block_name):
    """Top-level keys of an exported object literal in patterns.ts."""
    src = _read(_PATTERNS_TS)
    m = re.search(rf'export const {block_name}[^=]*=\s*\{{(.*?)\n\}};', src, re.S)
    assert m, f'{block_name} is not declared in desktop/src/lib/patterns.ts'
    return set(re.findall(r'^\s{2}([A-Za-z0-9_]+):', m.group(1), re.M))


# ── Fingerprints ─────────────────────────────────────────────────────────────

def test_every_fingerprint_has_a_spanish_entry():
    missing = _engine_fingerprints() - _ts_keys('PATTERNS')
    assert not missing, (
        f'analyze.py can emit {sorted(missing)}, which patterns.ts cannot '
        f'translate. An analyst would see the raw code.')


def test_no_invented_fingerprints():
    """The reverse drift: a dictionary entry for a code nothing produces is
    dead weight that reads as a supported detector."""
    extra = _ts_keys('PATTERNS') - _engine_fingerprints()
    assert not extra, (
        f'patterns.ts translates {sorted(extra)}, which analyze.py never emits.')


def test_every_entry_has_a_label_and_an_explanation():
    src = _read(_PATTERNS_TS)
    block = re.search(r'export const PATTERNS[^=]*=\s*\{(.*?)\n\};', src, re.S)
    entries = re.findall(
        r'^\s{2}([A-Za-z0-9_]+):\s*\{(.*?)\n\s{2}\},', block.group(1), re.S | re.M)
    assert entries, 'could not parse the PATTERNS entries'
    for code, body in entries:
        assert 'label:' in body, f'{code} has no label'
        assert 'explain:' in body, f'{code} has no explain'
        text = ''.join(re.findall(r"'([^']*)'", body))
        assert len(text) > 30, f'{code} explanation is too short to be useful'


def test_explanations_are_not_left_in_english():
    """The engine's own descriptions are half Spanglish — "amount ladder",
    "REPEAT OFFENDER", "flaggeado", "retry", "fencing". Rewriting them in
    Spanish is the entire point of this file, so guard the regression."""
    src = _read(_PATTERNS_TS)
    block = re.search(r'export const PATTERNS[^=]*=\s*\{(.*?)\n\};', src, re.S)
    prose = block.group(1).lower()
    for word in ('amount ladder', 'repeat offender', 'flaggeado',
                 'card testing', 'fencing', 'burst of'):
        assert word not in prose, f'"{word}" is still untranslated in patterns.ts'


# ── Verdicts and actions ─────────────────────────────────────────────────────

def test_every_finding_type_has_a_verdict():
    missing = _engine_finding_types() - _ts_keys('VERDICTS')
    assert not missing, (
        f'classify_finding_type can return {sorted(missing)}, which VERDICTS '
        f'does not cover — the row would fall back to a generic label.')


def test_every_action_code_has_a_recommendation():
    missing = _engine_action_codes() - _ts_keys('ACTIONS')
    assert not missing, (
        f'decide_action can return {sorted(missing)}, missing from ACTIONS.')


# ── Ordering ─────────────────────────────────────────────────────────────────

def test_the_ranking_covers_every_pattern():
    """rankPatterns puts unknown codes last. That is the right fallback, but a
    code missing from RANK would be sorted below genuinely weaker evidence."""
    src = _read(_PATTERNS_TS)
    block = re.search(r'const RANK = \[(.*?)\];', src, re.S)
    assert block, 'RANK moved or was renamed'
    ranked = set(re.findall(r"'([a-z0-9_]+)'", block.group(1)))
    missing = _ts_keys('PATTERNS') - ranked
    assert not missing, f'{sorted(missing)} are translated but never ranked'


def test_confirmed_fraud_outranks_the_heuristics():
    """A confirmed-fraud match is not a heuristic — it is a value the team has
    already watched do damage. It leads."""
    src = _read(_PATTERNS_TS)
    block = re.search(r'const RANK = \[(.*?)\];', src, re.S)
    order = re.findall(r"'([a-z0-9_]+)'", block.group(1))
    assert order.index('confirmed_indicator_cross_merchant') < order.index('high_reject_rate')
    assert order.index('confirmed_indicator_exact') < order.index('velocity_burst')


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
