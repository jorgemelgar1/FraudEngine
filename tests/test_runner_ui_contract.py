"""Contract tests between the runner (Python) and the Runner screen (React).

There is no shared configuration between a cron job on a Raspberry Pi and a
Tauri app, so four values are simply written down twice. Duplication that
nothing checks is duplication that drifts, and each of these drifts silently:

  ROTATION            wrong "next slot" times, with nothing to notice them by
  STALE_AFTER_HOURS   the app calls a country healthy that `--health` calls
                      overdue, or the reverse - and the two disagreeing is
                      worse than either being wrong, because it destroys
                      trust in both
  TOKEN_WARN_DAYS     the app warns on a different day than the Pi's log
  COUNTRY_NAMES       a country renders as a bare code

The fifth check is the one with teeth: every outcome the runner can WRITE has
to be renderable by the screen and accepted by the database. An outcome the
Python emits that the TypeScript has no label for renders as a raw slug like
`token_error` in front of a user; one the check constraint rejects fails the
bookkeeping write - silently, because that write is best-effort - and leaves
the cycle stuck showing 'running' forever.

Run with plain python (no pytest needed):

    python tests/test_runner_ui_contract.py
"""

import os
import re
import sys
import tempfile
from datetime import timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

# config snapshots the environment at import time, exactly as the other
# runner tests do.
os.environ.setdefault('RUNNER_STATE_DIR', tempfile.mkdtemp(prefix='ui-contract-'))

for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config              # noqa: E402
import cycle               # noqa: E402
import state as runner_state   # noqa: E402

_RUNNER_TS = os.path.join(_ROOT, 'desktop', 'src', 'lib', 'runner.ts')
_RUNNER_TSX = os.path.join(_ROOT, 'desktop', 'src', 'pages', 'Runner.tsx')
_MIGRATION = os.path.join(_ROOT, 'supabase', 'migrations',
                          '0012_runner_cycles.sql')


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def _number(source, name):
    m = re.search(rf'export const {name}\s*=\s*(\d+)\s*;', source)
    assert m, f'{name} is not declared in desktop/src/lib/runner.ts'
    return int(m.group(1))


# ── The mirrored constants ───────────────────────────────────────────────────

def test_rotation_matches():
    ts = _read(_RUNNER_TS)
    m = re.search(r'export const ROTATION\s*=\s*\[(.*?)\]', ts, re.S)
    assert m, 'ROTATION is not declared in runner.ts'
    rotation = re.findall(r"'([A-Z]{2})'", m.group(1))
    assert rotation == config.ROTATION, (
        f'runner.ts has {rotation}, runner/config.py has {config.ROTATION}. '
        f'The screen would show the wrong next-slot times.')


def test_stale_threshold_matches():
    hours = _number(_read(_RUNNER_TS), 'STALE_AFTER_HOURS')
    expected = runner_state.STALE_AFTER / timedelta(hours=1)
    assert hours == expected, (
        f'runner.ts says a country is stale after {hours} h, '
        f'runner/state.py says {expected} h. `cycle.py --health` and the app '
        f'would disagree about whether the runner is healthy.')


def test_token_warning_matches():
    days = _number(_read(_RUNNER_TS), 'TOKEN_WARN_DAYS')
    assert days == cycle.TOKEN_WARN_DAYS, (
        f'runner.ts warns at {days} days, runner/cycle.py at '
        f'{cycle.TOKEN_WARN_DAYS}.')


def test_country_names_match():
    ts = _read(_RUNNER_TS)
    m = re.search(r'export const COUNTRY_NAMES[^=]*=\s*\{(.*?)\}', ts, re.S)
    assert m, 'COUNTRY_NAMES is not declared in runner.ts'
    names = dict(re.findall(r"(\w+):\s*'([^']+)'", m.group(1)))
    expected = {code: meta['name'] for code, meta in config.COUNTRIES.items()}
    assert names == expected, (
        f'runner.ts has {names}, runner/config.py has {expected}.')


# ── The outcome vocabulary, across all three languages ───────────────────────

def _outcomes_allowed_by_migration():
    block = re.search(r'check \(outcome in \((.*?)\)\)', _read(_MIGRATION), re.S)
    assert block, 'the outcome check constraint moved or was renamed'
    return set(re.findall(r"'([a-z_]+)'", block.group(1)))


def _outcomes_in_typescript():
    ts = _read(_RUNNER_TS)
    block = re.search(r'export type CycleOutcome\s*=(.*?);', ts, re.S)
    assert block, 'the CycleOutcome union moved or was renamed'
    return set(re.findall(r"'([a-z_]+)'", block.group(1)))


def _outcomes_labelled_by_the_screen():
    tsx = _read(_RUNNER_TSX)
    block = re.search(r'const OUTCOMES[^=]*=\s*\{(.*?)\n\};', tsx, re.S)
    assert block, 'the OUTCOMES label map moved or was renamed'
    return set(re.findall(r'^\s{2}(\w+):\s*\{', block.group(1), re.M))


def test_typescript_knows_every_outcome_the_database_allows():
    allowed = _outcomes_allowed_by_migration()
    known = _outcomes_in_typescript()
    missing = allowed - known
    assert not missing, (
        f'migration 0012 allows {sorted(missing)} but the CycleOutcome union '
        f'does not list them, so those rows would not typecheck as cycles.')


def test_the_screen_can_render_every_outcome():
    known = _outcomes_in_typescript()
    labelled = _outcomes_labelled_by_the_screen()
    missing = known - labelled
    assert not missing, (
        f'{sorted(missing)} have no entry in the OUTCOMES map, so a cycle '
        f'that ended that way would render its raw slug to the user.')


def test_no_outcome_is_invented_by_the_screen():
    """The reverse drift: a label for an outcome nothing can produce is dead
    code that reads as a supported state."""
    allowed = _outcomes_allowed_by_migration()
    extra = _outcomes_labelled_by_the_screen() - allowed
    assert not extra, (
        f'the screen labels {sorted(extra)}, which migration 0012 would '
        f'reject, so no cycle can ever have that outcome.')


def test_the_runner_can_produce_every_outcome_the_screen_shows():
    """Every state the UI presents should be reachable. A label nobody can
    trigger is a promise the system does not keep."""
    import run as runner
    import supabase_io as sio
    import cubo_api
    import token_store

    reachable = {'running', 'ok', 'no_email'}
    for exc in (cubo_api.CmsError('x'), sio.SupabaseError('x'),
                token_store.TokenError('x'), config.ConfigError('x'),
                Exception('x')):
        reachable.add(runner.classify_failure(exc)[0])
    # gmail_error needs the lazily-imported module to exist before
    # classify_failure can recognise it.
    import gmail
    reachable.add(runner.classify_failure(gmail.GmailError('x'))[0])

    unreachable = _outcomes_labelled_by_the_screen() - reachable
    assert not unreachable, (
        f'the screen shows {sorted(unreachable)}, but nothing in the runner '
        f'can produce them.')


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
