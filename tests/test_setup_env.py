"""Tests for runner/setup_env.py — the interactive .env builder.

Only the pure parts, which are the parts that can be wrong in a way nobody
notices: the derived URL pattern is the runner's guard against downloading
whatever a malformed or spoofed email contains, and the key check is what
stops the anon key being pasted where the service-role key belongs.

Run with plain python (no pytest needed):

    python tests/test_setup_env.py
"""

import base64
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import setup_env  # noqa: E402


LINK = ('https://cdn.example.internal/reports/csv/'
        '8943090c-1111-2222-3333-444455556666.csv')


# ── Deriving the URL pattern ─────────────────────────────────────────────────

def test_pattern_matches_the_link_it_came_from():
    pattern, _note = setup_env.pattern_from_link(LINK)
    assert pattern and re.fullmatch(pattern, LINK)


def test_pattern_matches_other_reports_of_the_same_shape():
    """It has to generalise - the report id changes every time."""
    pattern, _ = setup_env.pattern_from_link(LINK)
    other = ('https://cdn.example.internal/reports/csv/'
             'deadbeef-0000-1111-2222-333344445555.csv')
    assert re.fullmatch(pattern, other)


def test_pattern_refuses_a_different_host():
    """The whole point. A spoofed email pointing somewhere else must not turn
    the runner into a fetch-anything tool."""
    pattern, _ = setup_env.pattern_from_link(LINK)
    evil = ('https://evil.example.com/reports/csv/'
            '8943090c-1111-2222-3333-444455556666.csv')
    assert re.fullmatch(pattern, evil) is None


def test_pattern_refuses_a_different_path_or_extension():
    pattern, _ = setup_env.pattern_from_link(LINK)
    for bad in (
        'https://cdn.example.internal/other/csv/'
        '8943090c-1111-2222-3333-444455556666.csv',
        'https://cdn.example.internal/reports/csv/'
        '8943090c-1111-2222-3333-444455556666.exe',
        'https://cdn.example.internal/reports/csv/'
        '../../8943090c-1111-2222-3333-444455556666.csv',
    ):
        assert re.fullmatch(pattern, bad) is None, bad


def test_query_string_is_dropped_with_a_note():
    """Tracking parameters vary per recipient; keeping them would build a
    pattern that matches exactly one link and nothing else."""
    pattern, note = setup_env.pattern_from_link(LINK + '?utm_source=email')
    assert pattern and note and re.fullmatch(pattern, LINK)


def test_link_without_a_report_id_is_rejected():
    pattern, note = setup_env.pattern_from_link('https://cdn.x.io/a/b.csv')
    assert pattern is None and 'report id' in note


def test_non_link_is_rejected():
    assert setup_env.pattern_from_link('not a link')[0] is None


# ── Recognising the key ──────────────────────────────────────────────────────

def _jwt(role):
    payload = base64.urlsafe_b64encode(
        json.dumps({'role': role}).encode()).decode().rstrip('=')
    return f'eyJhbGciOiJIUzI1NiJ9.{payload}.signature'


def test_service_role_jwt_is_accepted():
    assert setup_env.describe_key(_jwt('service_role'))[0] == 'service_role'


def test_anon_key_is_caught():
    """The two keys look identical and are next to each other in the
    dashboard. Pasting the wrong one fails much later, as an RLS error that
    says nothing about which key was used."""
    role, note = setup_env.describe_key(_jwt('anon'))
    assert role == 'anon' and 'ANON' in note


def test_new_format_keys():
    assert setup_env.describe_key('sb_secret_abc123')[0] == 'service_role'
    role, note = setup_env.describe_key('sb_publishable_abc123')
    assert role == 'anon' and 'PUBLISHABLE' in note


def test_nonsense_is_rejected():
    assert setup_env.describe_key('hunter2')[0] is None


# ── Project URL ──────────────────────────────────────────────────────────────

def test_url_is_normalised_and_checked():
    assert setup_env.check_supabase_url(
        'https://abc.supabase.co/')[0] == 'https://abc.supabase.co'
    assert setup_env.check_supabase_url('http://abc.supabase.co')[0] is None
    assert setup_env.check_supabase_url(
        'https://abc.supabase.co/rest/v1')[0] is None


# ── The file it writes ───────────────────────────────────────────────────────

def test_env_and_its_backup_stay_gitignored():
    """These hold a live service-role key in a PUBLIC repository.

    The backup matters as much as the original: re-running setup keeps the
    previous file as .env.backup, and `runner/.env` in .gitignore does not
    match it.
    """
    ignore = open(os.path.join(_ROOT, '.gitignore'), encoding='utf-8').read()
    assert 'runner/.env' in ignore
    assert '.env.backup' in ignore, (
        'setup_env.py writes runner/.env.backup; without a rule for it, a '
        'file containing the service-role key can be committed'
    )
    # And the example file, which is all placeholders, must stay tracked.
    assert os.path.exists(os.path.join(_ROOT, 'runner', '.env.example'))


def _values(pattern, **overrides):
    base = {
        'NEXT_PUBLIC_SUPABASE_URL': 'https://abc.supabase.co',
        'SUPABASE_SERVICE_ROLE_KEY': 'sb_secret_xyz',
        'RUNNER_EMAIL': 'runner@example.com',
        'CUBO_REPORT_SENDER': 'reports@example.internal',
        'CUBO_REPORT_LABEL': '',
        'CUBO_CSV_URL_PATTERN': pattern,
        'RUNNER_LOOKBACK_DAYS': '1',
    }
    base.update(overrides)
    return base


def _write_to_temp(values, existing=None):
    """Run write_env against a throwaway path. Returns (contents, carried)."""
    import tempfile

    original = setup_env.ENV_PATH
    tmpdir = tempfile.mkdtemp(prefix='setup-env-test-')
    setup_env.ENV_PATH = os.path.join(tmpdir, '.env')
    try:
        carried = setup_env.write_env(values, existing)
        with open(setup_env.ENV_PATH, encoding='utf-8') as fh:
            return fh.read(), carried
    finally:
        setup_env.ENV_PATH = original


def test_written_env_contains_the_pattern_but_not_the_sample_link():
    """The report link is a credential - possession of it is authorisation to
    download a full transaction export. It is used to derive a shape and must
    not survive that."""
    pattern, _ = setup_env.pattern_from_link(LINK)
    written, _carried = _write_to_temp(_values(pattern))

    assert LINK not in written, 'the raw report link was written to disk'
    assert '8943090c' not in written, 'the report id was written to disk'
    assert f'CUBO_CSV_URL_PATTERN={pattern}' in written
    assert 'SUPABASE_SERVICE_ROLE_KEY=sb_secret_xyz' in written

    # The pattern must survive a round trip through config's .env reader,
    # which strips surrounding quotes - a regex full of punctuation is exactly
    # the sort of value a naive parser mangles.
    for line in written.splitlines():
        if line.startswith('CUBO_CSV_URL_PATTERN='):
            value = line.partition('=')[2].strip().strip('"').strip("'")
            assert re.fullmatch(value, LINK), 'pattern broken by .env round trip'
            break
    else:
        raise AssertionError('CUBO_CSV_URL_PATTERN missing from the file')


def test_written_env_is_not_world_readable():
    """It holds a live service-role key. On Linux the file is created 0600
    before anything is written to it, so there is no window where it exists
    and is readable by others."""
    if sys.platform == 'win32':
        return  # NTFS inherits the user's directory ACL; nothing to assert
    import stat
    import tempfile

    original = setup_env.ENV_PATH
    tmpdir = tempfile.mkdtemp(prefix='setup-env-perm-')
    setup_env.ENV_PATH = os.path.join(tmpdir, '.env')
    try:
        setup_env.write_env(_values(r'https://x/y\.csv'))
        mode = stat.S_IMODE(os.stat(setup_env.ENV_PATH).st_mode)
    finally:
        setup_env.ENV_PATH = original

    assert mode == 0o600, f'expected 0600, got {oct(mode)}'


# ── Re-running setup ─────────────────────────────────────────────────────────

def test_values_this_script_does_not_manage_survive_a_rewrite():
    """GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET are added by hand AFTER setup
    runs. Dropping them on a re-run would break gmail.py with nothing at all
    pointing back at setup as the cause."""
    pattern, _ = setup_env.pattern_from_link(LINK)
    existing = {
        'NEXT_PUBLIC_SUPABASE_URL': 'https://old.supabase.co',
        'GMAIL_CLIENT_ID': 'abc.apps.googleusercontent.com',
        'GMAIL_CLIENT_SECRET': 'a-secret',
        'CUBO_API_ROOT': 'https://api.example.internal',
    }
    written, carried = _write_to_temp(_values(pattern), existing)

    assert 'GMAIL_CLIENT_ID=abc.apps.googleusercontent.com' in written
    assert 'GMAIL_CLIENT_SECRET=a-secret' in written
    assert 'CUBO_API_ROOT=https://api.example.internal' in written
    assert carried == ['CUBO_API_ROOT', 'GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET']

    # ...but a managed key is replaced, not duplicated.
    assert written.count('NEXT_PUBLIC_SUPABASE_URL=') == 1
    assert 'https://old.supabase.co' not in written


def test_report_sender_is_written():
    """Its absence is what made `gmail.py --check` fail after the Gmail work
    landed: setup predated it and never asked."""
    pattern, _ = setup_env.pattern_from_link(LINK)
    written, _ = _write_to_temp(_values(pattern))
    assert 'CUBO_REPORT_SENDER=reports@example.internal' in written


def test_blank_label_is_written_blank():
    """A label that does not exist in Gmail matches nothing, and the only
    symptom is zero emails found. Blank means 'search by sender', which
    always works."""
    pattern, _ = setup_env.pattern_from_link(LINK)
    written, _ = _write_to_temp(_values(pattern))
    assert 'CUBO_REPORT_LABEL=\n' in written


def test_existing_env_is_parsed_back():
    import tempfile

    original = setup_env.ENV_PATH
    tmpdir = tempfile.mkdtemp(prefix='setup-env-read-')
    setup_env.ENV_PATH = os.path.join(tmpdir, '.env')
    try:
        with open(setup_env.ENV_PATH, 'w', encoding='utf-8') as fh:
            fh.write('# a comment\n\nA=1\nB="two"\nC=\nbroken line\n')
        values = setup_env.read_existing_env()
    finally:
        setup_env.ENV_PATH = original

    assert values['A'] == '1'
    assert values['B'] == 'two', 'quotes must be stripped, as config.py does'
    assert values['C'] == ''
    assert 'broken line' not in values


def test_label_has_no_default_in_config():
    """A default naming a label the user never created makes every search
    match nothing."""
    import config
    assert config.REPORT_LABEL == '' or os.environ.get('CUBO_REPORT_LABEL')


# ── Runner ───────────────────────────────────────────────────────────────────

def _run_all():
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith('test_') and callable(o)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f'FAIL {name}: {e}')
        except Exception as e:                              # noqa: BLE001
            failed += 1
            print(f'ERROR {name}: {type(e).__name__}: {e}')
    print(f'{passed}/{len(tests)} passed'
          + (f', {failed} failed' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(_run_all())
