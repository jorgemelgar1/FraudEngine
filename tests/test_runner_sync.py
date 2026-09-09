"""Tests for runner/run.py:sync — the write half of the automated runner.

tests/test_dedup.py proves the DECISION is right. This proves the runner acts
on it correctly: that sixteen identical runs produce one row and not sixteen,
that a suppressed finding really writes nothing, that a promotion reaches the
review queue.

Supabase is replaced with a fake that applies the same state transitions the
SQL in migrations 0010/0011 does. That is not a substitute for running the
migration - it is a way to test the loop's arithmetic without a database, and
the fake is deliberately small enough to read in one screen.

Run with plain python (no pytest needed):

    python tests/test_runner_sync.py
"""

import io
import os
import re
import sys
import uuid
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

# Before importing config (via run), which snapshots the environment at import
# time. Keeps these tests off the real state file on a machine that has one.
import tempfile  # noqa: E402
os.environ['RUNNER_STATE_DIR'] = tempfile.mkdtemp(prefix='runner-sync-test-')

for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config                         # noqa: E402
import dedup                          # noqa: E402
import state as runner_state          # noqa: E402
import runner.run as run              # noqa: E402


RUN_ID = str(uuid.UUID(int=1))
NOW = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)


# ── A Supabase that lives in a dict ──────────────────────────────────────────

class FakeSupabase:
    """Mirrors the subset of supabase_io that sync() touches.

    Rows are keyed by finding_key because that is what migration 0011 makes
    the database do: the key is a generated column, so it is derived from the
    row rather than supplied with it.
    """

    class SupabaseError(RuntimeError):
        pass

    def __init__(self):
        self.rows = {}            # finding_key -> row dict
        self.watchlist_touches = []
        self.indicator_hits = 0

    # -- reads --

    def lookup_open_finding(self, finding_key):
        row = self.rows.get(finding_key)
        if not row:
            return None
        return {
            'id':               row['id'],
            'review_status':    row['review_status'],
            'confidence':       row['confidence'],
            'risk_score':       row['risk_score'],
            'times_seen':       row['times_seen'],
            'first_seen_at':    row['first_seen_at'],
            'last_seen_at':     row['last_seen_at'],
            'suppressed_until': row.get('suppressed_until'),
            'reviewed_at':      row.get('reviewed_at'),
        }

    # -- writes --

    def insert_findings(self, rows):
        out = []
        for r in rows:
            assert 'finding_key' not in r, (
                'finding_key is a GENERATED column (migration 0011); sending '
                'it makes Postgres reject the whole insert.'
            )
            key = dedup.finding_key(r['company_name'], r['section'])
            stored = dict(r)
            stored.update({
                'id': str(uuid.uuid4()),
                'finding_key': key,
                'times_seen': 1,
                'first_seen_at': NOW,
                'last_seen_at': NOW,
            })
            self.rows[key] = stored
            out.append(stored)
        return out

    def touch_finding(self, finding_id, row, promote=False):
        stored = self._by_id(finding_id)
        # Migration 0011 refreshes the whole finding, not four columns of it.
        for field in ('run_id', 'risk_score', 'confidence', 'finding_type',
                      'company_id', 'action_code', 'fingerprints', 'payload',
                      'chargeback_exposure_usd', 'chargeback_exposure_currency',
                      'description_es'):
            if field in row:
                stored[field] = row[field]
        stored['times_seen'] += 1
        stored['last_seen_at'] = NOW
        if promote and stored['review_status'] == 'not_applicable':
            stored['review_status'] = 'pending'
        return {'id': finding_id, 'times_seen': stored['times_seen']}

    def reopen_finding(self, finding_id, risk_score, confidence, reason):
        stored = self._by_id(finding_id)
        stored.update({
            'review_status': 'pending',
            'risk_score': risk_score,
            'confidence': confidence,
            'suppressed_until': None,
        })
        stored['times_seen'] += 1
        return {'id': finding_id, 'reopened': True}

    def touch_watchlist_merchant(self, company_name, risk_score, run_id=None):
        self.watchlist_touches.append(company_name)

    def record_indicator_hits(self, findings):
        self.indicator_hits += 1

    def _by_id(self, finding_id):
        for row in self.rows.values():
            if row['id'] == finding_id:
                return row
        raise AssertionError(f'Finding {finding_id} not found')


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _finding(company='Comercio Uno', score=72, confidence='Critical'):
    return {
        'company_name': company,
        'company_id': 'CMP-1',
        'type': 'chargeback_exposure',
        'confidence': confidence,
        'risk_score': score,
        'fingerprints': ['fanout_fast'],
        'action_code': 'REVIEW',
        'description_es': 'Descripción',
        'estimated_chargeback_exposure': 1234.56,
    }


def _report(critical=None, monitor=None, zero=None, currency='GTQ'):
    return {
        'summary': {'currency': currency, 'currency_source': 'guatemala'},
        'critical_findings': critical or [],
        'monitor_findings': monitor or [],
        'suspicious_rejected_merchants': zero or [],
    }


def _sync(report, fake, dry_run=False):
    """Run sync() against the fake, with its logging silenced."""
    original = run.supabase_io
    run.supabase_io = fake
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            return run.sync(report, RUN_ID, dry_run=dry_run), buf.getvalue()
    finally:
        run.supabase_io = original


# ── The central claim ────────────────────────────────────────────────────────

def test_sixteen_runs_produce_one_row():
    """The reason de-duplication exists. A merchant sits inside the
    today+yesterday window for ~48 h, so a 3-hour cycle re-detects it 16
    times. Sixteen rows in the review queue would end the tool."""
    fake = FakeSupabase()
    for _ in range(16):
        _sync(_report(critical=[_finding()]), fake)

    assert len(fake.rows) == 1, f'expected 1 row, got {len(fake.rows)}'
    row = next(iter(fake.rows.values()))
    assert row['times_seen'] == 16
    assert row['review_status'] == 'pending'


def test_first_run_inserts_and_second_updates():
    fake = FakeSupabase()
    counts, _ = _sync(_report(critical=[_finding()]), fake)
    assert counts[dedup.INSERT] == 1

    counts, _ = _sync(_report(critical=[_finding()]), fake)
    assert counts[dedup.UPDATE] == 1
    assert counts[dedup.INSERT] == 0


def test_update_refreshes_the_score_the_reviewer_sees():
    """A merchant first caught at 45 that is now at 90 is a different
    decision. The row must show 90."""
    fake = FakeSupabase()
    _sync(_report(critical=[_finding(score=45)]), fake)
    _sync(_report(critical=[_finding(score=90)]), fake)

    row = next(iter(fake.rows.values()))
    assert row['risk_score'] == 90


def test_update_refreshes_exposure_too():
    """Migration 0011 exists because 0010's touch_finding left exposure,
    description and run_id at first-detection values - so a reviewer saw a
    current score beside a two-day-old amount with no way to tell."""
    fake = FakeSupabase()
    _sync(_report(critical=[_finding()]), fake)

    f = _finding(score=90)
    f['estimated_chargeback_exposure'] = 9999.99
    old_run = next(iter(fake.rows.values()))['run_id']

    run_two = str(uuid.UUID(int=2))
    original = run.supabase_io
    run.supabase_io = fake
    try:
        with redirect_stdout(io.StringIO()):
            run.sync(_report(critical=[f]), run_two)
    finally:
        run.supabase_io = original

    row = next(iter(fake.rows.values()))
    assert row['chargeback_exposure_usd'] == 9999.99
    assert row['run_id'] == run_two and row['run_id'] != old_run


# ── Sections are independent ─────────────────────────────────────────────────

def test_same_merchant_in_two_sections_is_two_findings():
    """Identity is (merchant, section). A merchant flagged by both the
    exposure model and the card-testing detector has two problems, and a
    reviewer needs to see both."""
    fake = FakeSupabase()
    _sync(_report(critical=[_finding()], zero=[_finding()]), fake)
    assert len(fake.rows) == 2


# ── Suppression ──────────────────────────────────────────────────────────────

def test_accepted_finding_is_suppressed_and_watchlist_is_touched():
    fake = FakeSupabase()
    _sync(_report(critical=[_finding()]), fake)
    row = next(iter(fake.rows.values()))
    row['review_status'] = 'accepted'
    row['reviewed_at'] = NOW - timedelta(hours=1)
    seen_before = row['times_seen']

    counts, _ = _sync(_report(critical=[_finding()]), fake)

    assert counts[dedup.SUPPRESS] == 1
    assert row['times_seen'] == seen_before, 'a suppressed finding must not be written'
    assert fake.watchlist_touches == ['Comercio Uno']


def test_rejected_finding_stays_quiet_inside_the_cooloff():
    fake = FakeSupabase()
    _sync(_report(critical=[_finding()]), fake)
    row = next(iter(fake.rows.values()))
    row.update({
        'review_status': 'rejected',
        'reviewed_at': datetime.now(timezone.utc) - timedelta(hours=2),
        'suppressed_until': datetime.now(timezone.utc) + timedelta(hours=46),
    })

    counts, _ = _sync(_report(critical=[_finding()]), fake)
    assert counts[dedup.SUPPRESS] == 1
    assert row['review_status'] == 'rejected'
    assert fake.watchlist_touches == [], 'only accepted findings touch the watchlist'


def test_rejected_finding_reopens_when_it_escalates():
    fake = FakeSupabase()
    _sync(_report(critical=[_finding(score=50)]), fake)
    row = next(iter(fake.rows.values()))
    row.update({
        'review_status': 'rejected',
        'reviewed_at': datetime.now(timezone.utc) - timedelta(hours=2),
        'suppressed_until': datetime.now(timezone.utc) + timedelta(hours=46),
    })

    counts, _ = _sync(_report(critical=[_finding(score=80)]), fake)

    assert counts[dedup.REOPEN] == 1
    assert row['review_status'] == 'pending'
    assert row['risk_score'] == 80


# ── Promotion ────────────────────────────────────────────────────────────────

def test_monitor_promoted_to_pending_on_reaching_critical():
    """A Monitor-tier finding that escalates has to enter the review queue.
    Leaving it informational is how a merchant that quietly gets worse is
    never looked at - the exact failure this tool exists to prevent."""
    fake = FakeSupabase()
    _sync(_report(monitor=[_finding(score=30, confidence='Monitor')]), fake)
    row = next(iter(fake.rows.values()))
    assert row['review_status'] == 'not_applicable'

    _sync(_report(critical=[_finding(score=80, confidence='Critical')]), fake)
    assert row['review_status'] == 'pending'


def test_monitor_that_stays_monitor_is_not_queued():
    fake = FakeSupabase()
    _sync(_report(monitor=[_finding(score=30, confidence='Monitor')]), fake)
    _sync(_report(monitor=[_finding(score=35, confidence='Monitor')]), fake)

    row = next(iter(fake.rows.values()))
    assert row['review_status'] == 'not_applicable'
    assert row['times_seen'] == 2


# ── Within-run collisions ────────────────────────────────────────────────────

def test_duplicate_key_in_one_run_inserts_once():
    """Should be impossible - the engine emits one finding per merchant per
    section - but inserting both would create exactly the duplicate pair the
    whole mechanism exists to prevent, so it is handled rather than trusted."""
    fake = FakeSupabase()
    counts, output = _sync(
        _report(critical=[_finding(score=40), _finding(score=95)]), fake)

    assert len(fake.rows) == 1
    assert counts[dedup.INSERT] == 1
    assert next(iter(fake.rows.values()))['risk_score'] == 95, 'keep the worse one'
    assert 'dos veces' in output, 'a collision must be visible in the log'


# ── Dry run ──────────────────────────────────────────────────────────────────

def test_dry_run_writes_nothing():
    fake = FakeSupabase()
    counts, _ = _sync(_report(critical=[_finding()]), fake, dry_run=True)

    assert fake.rows == {}
    assert counts[dedup.INSERT] == 1, 'the decision is still reported'


def test_empty_report_is_not_an_error():
    fake = FakeSupabase()
    counts, _ = _sync(_report(), fake)
    assert sum(counts.values()) == 0
    assert fake.rows == {}


# ── Contracts with the database ──────────────────────────────────────────────

def test_no_writer_sends_finding_key():
    """Migration 0011 makes finding_key GENERATED. Postgres rejects an insert
    that supplies a value for it, so a client that 'helpfully' sets it breaks
    every insert - including the two apps' inserts, not just the runner's."""
    from importlib import util
    spec = util.spec_from_file_location(
        'api_analyze_check', os.path.join(_ROOT, 'api', 'analyze.py'))
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    _ordered, rows = mod.build_findings_rows(RUN_ID, _report(critical=[_finding()]))
    assert rows and 'finding_key' not in rows[0]

    sync_ts = open(os.path.join(_ROOT, 'desktop', 'src', 'lib', 'sync.ts'),
                   encoding='utf-8').read()
    assert 'finding_key' not in sync_ts, 'the desktop app must not send it either'


def test_migration_expression_matches_python():
    """If the SQL and the Python ever disagree, every existing finding becomes
    invisible to the runner and all of them are re-raised as new."""
    sql = open(os.path.join(_ROOT, 'supabase', 'migrations',
                            '0011_finding_key_generated.sql'),
               encoding='utf-8').read()
    generated = re.search(r'generated always as \((.*?)\) stored', sql,
                          re.S | re.I)
    assert generated, 'could not find the generated-column expression'
    expr = ' '.join(generated.group(1).split())
    assert expr == (
        "lower(trim(company_name)) || '|' || "
        "lower(coalesce(trim(section), 'exposure'))"
    ), f'unexpected expression: {expr}'

    # And that expression, applied by hand, equals what Python produces.
    company, section = '  Inversiones Kabu ', 'zero_settlement'
    assert dedup.finding_key(company, section) == (
        company.strip().lower() + '|' + section.strip().lower())


# ── Attribution and progress ─────────────────────────────────────────────────

def test_country_comes_from_the_csv_not_from_the_request():
    """PLAN.md principle 4. The country is read from the file's own
    country_name column, so asking for the wrong country id produces a
    mislabelled REQUEST, never a mislabelled analysis."""
    assert run.country_code_of(_report()) == 'GT'          # 'guatemala'
    for source, code in (('panama', 'PA'), ('el salvador', 'SV')):
        report = _report()
        report['summary']['currency_source'] = source
        assert run.country_code_of(report) == code, source


def test_unknown_country_yields_none_rather_than_a_guess():
    report = _report()
    report['summary']['currency_source'] = 'costa rica'
    assert run.country_code_of(report) is None
    report['summary']['currency_source'] = None
    assert run.country_code_of(report) is None


def test_progress_is_recorded_after_a_successful_run():
    path = config.state_path()
    if os.path.exists(path):
        os.remove(path)

    source = run.Source('/tmp/x.csv', delete_after=True, message_id='msg-42')
    buf = io.StringIO()
    with redirect_stdout(buf):
        run._record_progress(source, _report())

    saved = runner_state.load()
    assert runner_state.is_processed('msg-42', saved), (
        'the email must be marked consumed, or the next run re-processes it')
    assert runner_state.last_success('GT', saved) is not None


def test_progress_without_an_email_still_records_the_country():
    """A --url or --csv run has no message to mark, but it still proves that
    country is alive - which is what distinguishes a quiet week from an
    outage."""
    path = config.state_path()
    if os.path.exists(path):
        os.remove(path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        run._record_progress(run.Source('/tmp/x.csv'), _report())

    saved = runner_state.load()
    assert runner_state.last_success('GT', saved) is not None
    assert saved['processed_ids'] == []


def test_unknown_country_warns_rather_than_recording_the_wrong_one():
    path = config.state_path()
    if os.path.exists(path):
        os.remove(path)

    report = _report()
    report['summary']['currency_source'] = 'atlantis'
    buf = io.StringIO()
    with redirect_stdout(buf):
        run._record_progress(run.Source('/tmp/x.csv', message_id='m'), report)

    assert 'no se pudo determinar el país' in buf.getvalue()
    saved = runner_state.load()
    assert saved['last_success'] == {}
    assert runner_state.is_processed('m', saved), (
        'the email was still consumed - re-reading it would not help')


def test_runner_writes_currency_source():
    """Migration 0009 added the column so a future currency error leaves a
    trace. A column nothing writes is worse than no column - it looks like
    evidence."""
    src = open(os.path.join(_ROOT, 'runner', 'supabase_io.py'),
               encoding='utf-8').read()
    assert "'currency_source'" in src
    assert "'source'" in src


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
