"""Contract test: the re-open note the DATABASE writes vs the regex the APP parses.

When the runner re-opens a rejected finding, `reopen_finding` (migration 0010)
appends a sentence to `review_notes` explaining why. The Pendientes screen
parses that sentence back out to show "volvió porque …".

Two languages, one string format, nothing connecting them. If the SQL wording
ever changes, the banner does not crash — it silently stops showing a reason,
which is the same as not having built it. That is exactly the failure this
whole feature exists to prevent, so it gets a test.

It has already earned its keep. The first version of the regex cut at the
first colon, and the timestamp in the note is `YYYY-MM-DD HH24:MI` — the reason
rendered as "00 UTC: el puntaje subió de 45 a 90".

Run with plain python (no pytest needed):

    python tests/test_reopen_note_contract.py
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

_MIGRATION = os.path.join(_ROOT, 'supabase', 'migrations', '0010_finding_dedup.sql')
_FINDINGS_TS = os.path.join(_ROOT, 'desktop', 'src', 'lib', 'findings.ts')


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def _js_regex_to_python(source, name):
    """Pull `const <name> = /…/;` out of the TypeScript and compile it."""
    m = re.search(rf'const {name}\s*=\s*/(.+?)/[gimsuy]*\s*;', source)
    assert m, f'{name} is not declared in desktop/src/lib/findings.ts'
    return re.compile(m.group(1))


# The literal `reopen_finding` builds, as Postgres renders it. Kept here in the
# exact shape the SQL produces so the assertions below are about the real
# string, not a paraphrase of it.
def _note(reason, old=45, new=90, stamp='2026-09-09 14:00'):
    return (f'Reabierto automáticamente {stamp} UTC: {reason} '
            f'(puntaje anterior {old}, ahora {new})')


# ── The SQL still writes what we think it writes ─────────────────────────────

def test_the_migration_still_builds_the_note_this_way():
    sql = _read(_MIGRATION)
    block = re.search(r'review_notes\s*=\s*concat_ws\((.*?)\)\s*\n\s*where',
                      sql, re.S)
    assert block, 'the review_notes assignment in reopen_finding moved'
    body = block.group(1)
    assert 'Reabierto autom' in body, 'the note prefix changed'
    assert "' UTC: '" in body, (
        'the note no longer separates the timestamp from the reason with '
        '" UTC: ", which is what the app anchors on')
    assert "'YYYY-MM-DD HH24:MI'" in body, (
        'the timestamp format changed; if it no longer contains a colon the '
        'app regex can be simplified, and if it gained one this test is why '
        'the parse still works')


def test_the_timestamp_really_does_contain_a_colon():
    """The trap. Documented so nobody "simplifies" the regex back."""
    assert ':' in '2026-09-09 14:00'.split(' ')[1]


# ── The app parses it correctly ──────────────────────────────────────────────

def test_an_escalation_reason_is_extracted_whole():
    rx = _js_regex_to_python(_read(_FINDINGS_TS), 'REOPEN_RE')
    m = rx.match(_note('el puntaje subió de 45 a 90'))
    assert m, 'the app can no longer parse the note the database writes'
    reason = m.group(1)
    assert reason.startswith('el puntaje subió de 45 a 90'), reason
    assert 'UTC' not in reason, (
        f'the timestamp leaked into the reason: {reason!r} — this is the '
        f'first-colon bug')


def test_a_cooloff_reason_is_extracted_whole():
    rx = _js_regex_to_python(_read(_FINDINGS_TS), 'REOPEN_RE')
    m = rx.match(_note('terminó el periodo de silencio de 48h'))
    assert m and m.group(1).startswith('terminó el periodo de silencio')


def test_the_tier_crossing_reason_survives_its_own_colon_free_text():
    rx = _js_regex_to_python(_read(_FINDINGS_TS), 'REOPEN_RE')
    m = rx.match(_note('subió de Monitor a Critical'))
    assert m and m.group(1).startswith('subió de Monitor a Critical')


def test_the_redundant_score_tail_is_stripped():
    """The note ends with "(puntaje anterior 45, ahora 90)", restating the
    sentence before it. The current score is already on the row."""
    ts = _read(_FINDINGS_TS)
    rx = _js_regex_to_python(ts, 'REOPEN_RE')
    tail = _js_regex_to_python(ts, 'TRAILING_SCORES')
    reason = rx.match(_note('el puntaje subió de 45 a 90')).group(1)
    cleaned = tail.sub('', reason).strip()
    assert cleaned == 'el puntaje subió de 45 a 90', cleaned


def test_the_newest_entry_wins_when_a_finding_reopened_twice():
    """reopen_finding APPENDS with ' | ', so a twice-reopened finding carries
    both notes and the last one is the current story."""
    ts = _read(_FINDINGS_TS)
    rx = _js_regex_to_python(ts, 'REOPEN_RE')
    joined = ' | '.join([
        _note('terminó el periodo de silencio de 48h', stamp='2026-09-01 09:00'),
        _note('el puntaje subió de 45 a 90', stamp='2026-09-09 14:00'),
    ])
    # Mirrors the app: split, walk backwards, take the first that matches.
    reason = None
    for part in reversed(joined.split(' | ')):
        m = rx.match(part.strip())
        if m:
            reason = m.group(1)
            break
    assert reason and reason.startswith('el puntaje subió'), reason


def test_an_undo_note_is_not_mistaken_for_a_reopen():
    """_undo_one_finding writes "Undone by …" and clears reviewed_at, so those
    rows never reach the banner — but the regex must not match them either."""
    rx = _js_regex_to_python(_read(_FINDINGS_TS), 'REOPEN_RE')
    assert not rx.match('Undone by jorge@cubopago.com at 2026-09-09 14:00:00 UTC')


def test_the_app_requires_reviewed_at_before_showing_the_banner():
    """The rule that makes this unambiguous: reopen KEEPS reviewed_at, undo
    NULLs it. Guard the check rather than the comment."""
    ts = _read(_FINDINGS_TS)
    body = re.search(r'export function reopenInfo\(.*?\n\}', ts, re.S)
    assert body, 'reopenInfo moved or was renamed'
    assert 'if (!f.reviewed_at) return null;' in body.group(0), (
        'reopenInfo no longer gates on reviewed_at, so a finding whose '
        'decision was undone would be shown as "dismissed and returned"')


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
