"""Tests for runner/cycle.py — the scheduled cycle.

The behaviours worth pinning down here are the ones that only show up in
production, hours apart:

  * the rotation is derived from the clock, so a missed slot does not shift it
  * an expired CMS token stops the run loudly, because an expired token and a
    quiet fraud day both produce zero findings
  * a report email that never arrives ends the job instead of asking again -
    a second request would put two identical mails in the mailbox, and every
    report mail is identical, so nothing could then tell them apart

Run with plain python (no pytest needed):

    python tests/test_cycle.py
"""

import base64
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

# Before importing config, which snapshots the environment at import time.
os.environ['RUNNER_STATE_DIR'] = tempfile.mkdtemp(prefix='cycle-test-')
os.environ['CUBO_REPORT_SENDER'] = 'reports@example.internal'
os.environ['CUBO_CSV_URL_PATTERN'] = (
    r'https://cdn\.example\.internal/reports/csv/[0-9a-fA-F-]{36}\.csv')
os.environ['GMAIL_CLIENT_ID'] = 'test-client.apps.googleusercontent.com'
os.environ['GMAIL_CLIENT_SECRET'] = 'test-secret'

for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config              # noqa: E402
import cubo_api            # noqa: E402
import cycle               # noqa: E402
import state as runner_state   # noqa: E402
import token_store         # noqa: E402


def _jwt(expires_in_days):
    exp = int((datetime.now(timezone.utc)
               + timedelta(days=expires_in_days)).timestamp())
    payload = base64.urlsafe_b64encode(
        json.dumps({'exp': exp}).encode()).decode().rstrip('=')
    return f'eyJhbGciOiJIUzI1NiJ9.{payload}.signature'


def _capture(fn):
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = fn()
    return result, buf.getvalue()


# ── Rotation ─────────────────────────────────────────────────────────────────

def test_rotation_follows_the_clock():
    """Stateless on purpose: a missed run must not shift the schedule, that
    country just picks up at its next slot."""
    expected = ['SV', 'PA', 'GT'] * 3
    for hour, want in enumerate(expected[:9]):
        got = cycle.choose_country(now=datetime(2026, 9, 9, hour))
        assert got == want, f'hour {hour}: expected {want}, got {got}'


def test_every_country_gets_a_slot_every_three_hours():
    seen = {cycle.choose_country(now=datetime(2026, 9, 9, h))
            for h in range(24)}
    assert seen == set(config.ROTATION)


def test_explicit_country_overrides_the_clock():
    assert cycle.choose_country('gt', now=datetime(2026, 9, 9, 0)) == 'GT'


def test_unknown_country_is_refused():
    try:
        cycle.choose_country('XX')
    except ValueError as e:
        assert 'XX' in str(e)
    else:
        raise AssertionError('an unknown country code must be refused')


# ── The CMS token ────────────────────────────────────────────────────────────

class _Token:
    """Replaces token_store for one test."""

    def __init__(self, token=None, missing=False):
        self.token, self.missing = token, missing

    def __enter__(self):
        self._read = token_store.read_token
        token_store.read_token = self._fake
        cycle.token_store = token_store
        return self

    def __exit__(self, *exc):
        token_store.read_token = self._read

    def _fake(self, path=None):
        if self.missing:
            raise FileNotFoundError('No stored token at /nowhere')
        return self.token


def test_expired_token_stops_the_run():
    """An expired token yields no reports and therefore no findings, which
    looks exactly like a clean week. It has to fail loudly instead."""
    with _Token(_jwt(-1)):
        try:
            _capture(cycle.check_token)
        except RuntimeError as e:
            assert 'caducó' in str(e)
        else:
            raise AssertionError('an expired token must stop the run')


def test_token_near_expiry_warns_but_continues():
    with _Token(_jwt(3)):
        token, output = _capture(cycle.check_token)
    assert token is not None
    assert 'AVISO' in output and 'caduca' in output


def test_healthy_token_is_reported_quietly():
    with _Token(_jwt(60)):
        token, output = _capture(cycle.check_token)
    assert token is not None
    assert 'AVISO' not in output
    assert 'días más' in output


def test_missing_token_points_at_the_workaround():
    """Manual-URL and --from-email modes still work without a CMS token, so
    the error should say so rather than implying everything is broken."""
    with _Token(missing=True):
        try:
            _capture(cycle.check_token)
        except RuntimeError as e:
            assert '--from-email' in str(e)
        else:
            raise AssertionError('a missing token must stop the run')


def test_opaque_token_is_not_rejected():
    """Not every token is a JWT. An unreadable expiry is not a reason to
    refuse to run - it is a reason to say the expiry is unreadable."""
    with _Token('an-opaque-token-value'):
        token, output = _capture(cycle.check_token)
    assert token == 'an-opaque-token-value'
    assert 'caducidad' in output


# ── The cycle itself ─────────────────────────────────────────────────────────

class _Cms:
    """Counts report requests, so 'never re-trigger' is checkable."""

    def __init__(self):
        self.triggers = []

    def __enter__(self):
        self._trigger = cubo_api.trigger_report
        cubo_api.trigger_report = self._fake
        return self

    def __exit__(self, *exc):
        cubo_api.trigger_report = self._trigger

    def _fake(self, token, country_id, date_from, date_to, timeout=60):
        self.triggers.append((country_id, date_from, date_to))
        return {'status': 200, 'body_bytes': 0,
                'requested_at': datetime.now(timezone.utc),
                'country_id': country_id,
                'date_from': date_from, 'date_to': date_to}


class _Mail:
    """Replaces gmail.wait_for_report with a fixed answer."""

    def __init__(self, result):
        self.result = result
        self.calls = 0

    def __enter__(self):
        import gmail
        self._gmail = gmail
        self._wait = gmail.wait_for_report
        gmail.wait_for_report = self._fake
        return self

    def __exit__(self, *exc):
        self._gmail.wait_for_report = self._wait

    def _fake(self, requested_at, timeout=None, poll=None, on_wait=None):
        self.calls += 1
        return self.result


def test_dry_run_requests_nothing():
    """Requesting a report cannot be simulated - it sends a real email to a
    real inbox. So a dry run must not do it."""
    with _Cms() as cms:
        code, output = _capture(lambda: cycle.run_cycle('GT', dry_run=True))
    assert code == 0
    assert cms.triggers == [], 'a dry run must not request a report'
    assert 'DRY RUN' in output


def test_timeout_ends_the_job_without_asking_again():
    """The central scheduling rule. A second request would queue a duplicate
    report and a duplicate email, and since every report mail is identical
    there would be no way to tell which answered which."""
    with _Token(_jwt(30)), _Cms() as cms, _Mail(None) as mail:
        code, output = _capture(lambda: cycle.run_cycle('GT'))

    assert cms.triggers == [(3, *cubo_api.date_window())], 'exactly one request'
    assert mail.calls == 1
    assert code == 0, 'a slow report is not a failure worth alerting on'
    assert 'próximo turno' in output


def test_a_found_report_is_downloaded_and_processed():
    link = ('https://cdn.example.internal/reports/csv/'
            '8943090c-1111-2222-3333-444455556666.csv')
    processed = {}

    import run as runner
    orig_download, orig_process = runner._download, runner.process
    runner._download = lambda url: '/tmp/fake.csv'
    runner.process = lambda source, dry_run=False, run_source='auto': (
        processed.update(path=source.path, message_id=source.message_id,
                         run_source=run_source, delete=source.delete_after))
    try:
        with _Token(_jwt(30)), _Cms() as cms, \
                _Mail(('msg-7', link, datetime.now(timezone.utc))):
            code, _ = _capture(lambda: cycle.run_cycle('SV'))
    finally:
        runner._download, runner.process = orig_download, orig_process

    assert code == 0
    assert cms.triggers[0][0] == 1, 'SV is country id 1'
    assert processed['message_id'] == 'msg-7'
    assert processed['run_source'] == 'auto', 'so /historial can tell it apart'
    assert processed['delete'] is True, 'a downloaded CSV must not survive'


# ── The analysis window ──────────────────────────────────────────────────────

def test_window_is_computed_in_local_time_not_utc():
    """The CMS reads these dates in each country's own timezone, so they must
    be built from local time.

    Computed in UTC they rolled over five hours early every evening (Panama is
    UTC-5), and the 19:00-23:00 slots asked for today-and-tomorrow instead of
    yesterday-and-today - receiving 19-23 hours of data instead of 25-47.
    Nothing looked wrong; the runs succeeded and the findings were real. Only
    detections that need a full day to become visible went missing.
    """
    from datetime import date

    start, end = cubo_api.date_window(1)
    today = date.today()
    assert end == today.strftime('%Y-%m-%d'), (
        f'window ends {end}, but today is locally {today} - the dates are '
        f'being computed in UTC again'
    )
    assert start == (today - timedelta(days=1)).strftime('%Y-%m-%d')


def test_evening_slots_still_reach_back_a_full_day():
    """The specific hours the UTC bug broke. At 19:00 local the window has to
    still include yesterday, or the 24-hour fan-out detector runs under its
    minimum."""
    for hour in (0, 12, 19, 20, 22, 23):
        evening = datetime(2026, 9, 12, hour, 0)
        start, end = cubo_api.date_window(1, end=evening)
        assert start == '2026-09-11', f'at {hour}:00 the window started {start}'
        assert end == '2026-09-12', f'at {hour}:00 the window ended {end}'

        # Hours of real data the API would return for that request.
        hours = (evening - datetime(2026, 9, 11)).total_seconds() / 3600
        assert hours >= 24, f'at {hour}:00 only {hours:.0f}h of data'


def test_lookback_override_widens_the_window():
    """The gap sweep after an outage longer than two days."""
    start, end = cubo_api.date_window(7, end=datetime(2026, 9, 12, 10, 0))
    assert (start, end) == ('2026-09-05', '2026-09-12')


def test_country_id_matches_the_confirmed_mapping():
    """Confirmed against the live countries endpoint, not guessed. A wrong id
    would request the wrong country's data."""
    assert (config.COUNTRIES['SV']['id'], config.COUNTRIES['PA']['id'],
            config.COUNTRIES['GT']['id']) == (1, 2, 3)


# ── Health ───────────────────────────────────────────────────────────────────

def _clear_state():
    path = config.state_path()
    if os.path.exists(path):
        os.remove(path)


def test_health_flags_a_country_that_never_ran():
    _clear_state()
    code, output = _capture(cycle.health)
    assert code == 1
    for country in config.ROTATION:
        assert f'ATRASADO: {country}' in output


def test_health_is_quiet_when_everything_is_current():
    _clear_state()
    now = datetime.now(timezone.utc)
    st = runner_state.load()
    for country in config.ROTATION:
        st = runner_state.record_success(country, now, st)
    runner_state.save(st)

    code, output = _capture(cycle.health)
    assert code == 0
    assert 'ATRASADO' not in output


def test_health_flags_only_the_stale_country():
    _clear_state()
    now = datetime.now(timezone.utc)
    st = runner_state.load()
    for country in config.ROTATION:
        st = runner_state.record_success(country, now, st)
    st = runner_state.record_success('PA', now - timedelta(hours=30), st)
    runner_state.save(st)

    code, output = _capture(cycle.health)
    assert code == 1
    assert 'ATRASADO: PA' in output
    assert 'ATRASADO: GT' not in output and 'ATRASADO: SV' not in output


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
