"""Nothing reaches the Slack channel as an English identifier.

The engine speaks in snake_case keys — `amount_ladder`, `cms_error`,
`Critical`. Those are column values and internal identifiers, and ops reads
the channel in Spanish. Two of them were leaking into messages: the
fingerprint list on every finding line, and the confidence tier next to the
score.

The dictionary is duplicated across the language boundary — Python for the
runner, TypeScript for the app — because the runner has to be able to
describe a finding with Supabase unreachable, so it cannot fetch the labels.
Duplication is fine as long as it cannot drift silently, which is what
test_python_labels_match_the_app pins.
"""

import io
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'runner'))

import slack  # noqa: E402


PATTERNS_TS = os.path.join(os.path.dirname(__file__), '..',
                           'desktop', 'src', 'lib', 'patterns.ts')
MIGRATION_0012 = os.path.join(os.path.dirname(__file__), '..',
                              'supabase', 'migrations', '0012_runner_cycles.sql')


def _ts_labels():
    """{fingerprint: label} as the desktop app defines them."""
    src = io.open(PATTERNS_TS, encoding='utf-8').read()
    return {m.group(1): m.group(2) for m in
            re.finditer(r"([a-z0-9_]+):\s*\{\s*label:\s*'([^']*)'", src)}


# ── the dictionaries agree ───────────────────────────────────────────────────

def test_python_labels_match_the_app():
    """Same fingerprint, same Spanish, in both languages.

    If this fails someone added or reworded a pattern on one side only, and
    the channel and the app are now calling the same thing two things.
    """
    ts = _ts_labels()
    assert ts, 'parsed no labels out of patterns.ts — did its shape change?'
    for key, label in ts.items():
        assert key in slack._PATTERN_LABEL, (
            f'{key} exists in the app but not in runner/slack.py')
        assert slack._PATTERN_LABEL[key] == label, (
            f'{key}: app says {label!r}, slack.py says '
            f'{slack._PATTERN_LABEL[key]!r}')


def test_no_extra_labels_in_python():
    """A pattern the app does not know about is equally a drift."""
    extra = set(slack._PATTERN_LABEL) - set(_ts_labels())
    assert not extra, f'in slack.py but not in patterns.ts: {sorted(extra)}'


def test_every_outcome_in_the_check_constraint_has_a_label():
    """Migration 0012 is the vocabulary; none of it may reach Slack raw."""
    sql = io.open(MIGRATION_0012, encoding='utf-8').read()
    m = re.search(r"outcome\s+in\s*\(([^)]*)\)", sql, re.I | re.S)
    assert m, 'could not find the outcome check constraint in 0012'
    outcomes = set(re.findall(r"'([a-z_]+)'", m.group(1)))
    assert outcomes, 'parsed no outcomes out of the constraint'
    missing = outcomes - set(slack._OUTCOME_LABEL)
    assert not missing, f'outcomes with no Spanish label: {sorted(missing)}'


# ── the labels are actually used ─────────────────────────────────────────────

def _event(**over):
    e = {'kind': slack.NEW, 'company_name': 'Tienda X', 'confidence': 'Critical',
         'risk_score': 90, 'exposure': 1200.0, 'currency': 'USD',
         'section': 'exposure', 'detail': None,
         'fingerprints': ['amount_ladder', 'critical_codes']}
    e.update(over)
    return e


def test_finding_line_shows_spanish_not_fingerprint_keys():
    line = slack._finding_line(_event(), 'PA')
    assert 'Escalera de montos' in line
    assert 'Rechazos por fraude' in line
    assert 'amount_ladder' not in line
    assert 'critical_codes' not in line


def test_finding_line_translates_the_tier():
    assert 'Crítico' in slack._finding_line(_event(), 'PA')
    assert 'Critical' not in slack._finding_line(_event(), 'PA')


def test_monitor_tier_is_left_alone():
    """Monitor is the same word in Spanish. Translating it would be worse."""
    line = slack._finding_line(_event(confidence='Monitor'), 'GT')
    assert 'Monitor' in line


def test_unknown_fingerprint_is_humanised_not_raw():
    """The engine gains detectors faster than this file gets updated."""
    line = slack._finding_line(_event(fingerprints=['card_fanout_fast']), 'SV')
    assert 'card_fanout_fast' not in line
    assert 'Card fanout fast' in line


def test_no_underscore_key_survives_into_a_whole_message():
    """The end-to-end version of the complaint that started this."""
    msg = slack.build_findings_message('PA', [_event()], summary={})
    blob = str(msg)
    for key in slack._PATTERN_LABEL:
        assert key not in blob, f'{key} reached the message unlabelled'


def test_outcome_label_covers_the_common_failures():
    assert slack.outcome_label('cms_error') == 'falló la descarga desde el CMS'
    assert 'token' in slack.outcome_label('token_error')
    assert slack.outcome_label('') == '?'


def test_unknown_outcome_passes_through_rather_than_vanishing():
    """Better a raw code than silence about which failure it was."""
    assert slack.outcome_label('brand_new_failure') == 'brand_new_failure'
