#!/usr/bin/env python3
"""The backup and restore scripts, run for real against a fake Supabase.

Self-contained: run with plain `python tests/test_backup_pipeline.py`
(no pytest required), or via `pytest tests/test_backup_pipeline.py`.

Why this exists: scripts/backup-database.ps1 shipped without ever having been
executed. It failed on its first real run, at the second line of work, because
`git describe` writes to stderr on an untagged commit and PowerShell 5.1 turns
any native stderr into a terminating error under `$ErrorActionPreference =
'Stop'`. The Python half would have failed the same way one step later, since
dump_supabase.py reports progress on stderr by design.

Unit-testing the encryption was not enough. What was missing was running the
things end to end. This file does that for the Python half — the PowerShell
half needs a console for `Read-Host -AsSecureString` and is covered by
scripts/_crypto.ps1's own checks.

The server below stands in for PostgREST. It is deliberately larger than one
page in one table, so paging is exercised rather than assumed: a dump that
silently stops at 1000 rows is a backup that silently loses data.

All data here is fabricated — no real cardholder information, and nothing in
this file talks to a real project.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(os.path.dirname(_HERE), 'scripts')

KEY = 'sb_secret_local_test_key'
PAGE = 1000          # must match dump_supabase.PAGE

TABLES = {
    # 1200 > PAGE, so the dump has to ask for a second and third page.
    'analysis_runs': [
        {'id': 'run-%04d' % i, 'company_name': 'Comercio %d' % (i % 7),
         'run_by_email': 'analista@example.test'}
        for i in range(1200)
    ],
    'findings_history': [
        {'id': 'find-%03d' % i, 'run_id': 'run-0001',
         'payload': {'evidence': [{'card_bin': '411111',
                                   'card_last_digits': '%04d' % i}]}}
        for i in range(30)
    ],
    'fraud_indicators': [],          # empty must survive as 0, not vanish
    'runner_cycles': [{'id': 'cyc-1', 'status': 'ok'}],
    'watchlist_cards': [
        {'bin': '411111', 'last4': '%04d' % i, 'card_key': '411111-%04d' % i}
        for i in range(12)
    ],
    'watchlist_merchants': [{'company_name': 'Comercio 1',
                             'last_run_id': 'run-0001'}],
}

RECEIVED = []        # what restore_supabase.py posted back


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth_ok(self):
        return (self.headers.get('apikey') == KEY
                and self.headers.get('Authorization') == 'Bearer ' + KEY)

    def _send(self, code, body=b''):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):                                    # noqa: N802
        if not self._auth_ok():
            return self._send(401, b'{"message":"Invalid API key"}')
        parts = [p for p in urlparse(self.path).path.split('/') if p]
        if len(parts) != 3 or parts[:2] != ['rest', 'v1']:
            return self._send(404, b'{"message":"no such endpoint"}')
        if parts[2] not in TABLES:
            return self._send(404, b'{"message":"relation does not exist"}')

        rows = TABLES[parts[2]]
        rng = self.headers.get('Range')
        if rng:
            start, _, end = rng.partition('-')
            rows = rows[int(start):int(end) + 1]
        return self._send(200, json.dumps(rows).encode('utf-8'))

    def do_POST(self):                                   # noqa: N802
        if not self._auth_ok():
            return self._send(401, b'{"message":"Invalid API key"}')
        parsed = urlparse(self.path)
        n = int(self.headers.get('Content-Length') or 0)
        payload = json.loads(self.rfile.read(n) or b'[]')
        RECEIVED.append({
            'table': parsed.path.rsplit('/', 1)[-1],
            'count': len(payload),
            'on_conflict': parse_qs(parsed.query).get('on_conflict', [None])[0],
            'prefer': self.headers.get('Prefer'),
        })
        return self._send(201)


_SRV = HTTPServer(('127.0.0.1', 0), _Handler)
threading.Thread(target=_SRV.serve_forever, daemon=True).start()
BASE = 'http://127.0.0.1:%d' % _SRV.server_address[1]
_TMP = tempfile.mkdtemp(prefix='cubo-backup-pipeline-')
_DUMP = os.path.join(_TMP, 'dump.json')


def _run(script, env):
    e = dict(os.environ)
    e.update(env)
    return subprocess.run([sys.executable, os.path.join(_SCRIPTS, script)],
                          capture_output=True, text=True, env=e)


def _good_env(**extra):
    env = {'SUPABASE_URL': BASE, 'SUPABASE_SERVICE_KEY': KEY}
    env.update(extra)
    return env


def _dumped():
    """Run the dump once and cache it for the assertions that follow."""
    if not os.path.exists(_DUMP):
        r = _run('dump_supabase.py', _good_env(DUMP_OUT=_DUMP))
        assert r.returncode == 0, 'dump failed: %s' % (r.stderr or '')[-400:]
    with open(_DUMP, encoding='utf-8') as fh:
        return json.load(fh)


# ── Dump ─────────────────────────────────────────────────────────────────────

def test_dump_pages_past_the_first_thousand_rows():
    """PostgREST caps a response at 1000 rows. A dump that takes the first
    response as the whole table loses everything after it, silently, and you
    find out on the day you restore."""
    d = _dumped()
    assert d['meta']['row_counts']['analysis_runs'] == len(TABLES['analysis_runs']), \
        'got %s of %d rows' % (d['meta']['row_counts']['analysis_runs'],
                               len(TABLES['analysis_runs']))


def test_paging_neither_duplicates_nor_drops_rows():
    """Paging without a stable sort can repeat one row on two pages and lose
    another. dump_supabase.py orders by primary key for exactly this reason."""
    ids = [r['id'] for r in _dumped()['tables']['analysis_runs']]
    assert len(ids) == len(set(ids)), '%d rows but %d unique' % (len(ids), len(set(ids)))
    assert set(ids) == {r['id'] for r in TABLES['analysis_runs']}


def test_every_table_is_present_and_an_empty_one_stays():
    d = _dumped()
    assert set(d['meta']['row_counts']) == set(TABLES)
    assert d['meta']['row_counts']['fraud_indicators'] == 0
    assert d['tables']['fraud_indicators'] == []


def test_dump_records_its_format_so_restore_can_refuse_junk():
    assert _dumped()['meta']['format'] == 'cubo-fraud-engine-data-dump/1'


def test_row_content_survives_verbatim():
    d = _dumped()
    assert d['tables']['watchlist_cards'][0]['card_key'] == '411111-0000'
    nested = d['tables']['findings_history'][0]['payload']['evidence'][0]
    assert nested['card_bin'] == '411111'


def test_a_wrong_key_fails_with_a_sentence_not_a_traceback():
    r = _run('dump_supabase.py',
             {'SUPABASE_URL': BASE, 'SUPABASE_SERVICE_KEY': 'sb_secret_wrong',
              'DUMP_OUT': os.path.join(_TMP, 'never-written.json')})
    assert r.returncode == 1, 'expected a clean failure, got %d' % r.returncode
    assert 'HTTP 401' in r.stderr, r.stderr[-300:]
    assert 'Traceback' not in r.stderr, 'crashed instead of reporting'
    assert not os.path.exists(os.path.join(_TMP, 'never-written.json')), \
        'wrote a dump file despite failing'


def test_the_service_key_is_never_printed_in_full():
    """A backup script's error output gets pasted into tickets and chats. Six
    characters is enough to tell 'wrong key' from 'right key, wrong
    permissions'; the rest is a credential."""
    r = _run('dump_supabase.py',
             {'SUPABASE_URL': BASE, 'SUPABASE_SERVICE_KEY': 'sb_secret_wrong',
              'DUMP_OUT': os.path.join(_TMP, 'x.json')})
    assert 'sb_secret_wrong' not in r.stderr, r.stderr[-200:]
    assert 'sb_secret_wrong' not in r.stdout


def test_a_failed_console_paste_is_explained_not_traced():
    """Ctrl+V in the classic Windows console does not paste — it inserts the
    control character 0x16. That reached urllib as the whole URL and came back
    as a six-frame traceback ending in "unknown url type", thirty seconds and
    two prompts after the actual mistake. The person running a backup needs to
    be told what they did, not shown a stack."""
    for bad in ('\x16', '', '   ', 'abcdefgh.supabase.co', 'abcdefgh'):
        r = _run('dump_supabase.py',
                 {'SUPABASE_URL': bad, 'SUPABASE_SERVICE_KEY': KEY,
                  'DUMP_OUT': os.path.join(_TMP, 'bad-url.json')})
        assert r.returncode == 1, 'accepted %r as a URL' % bad
        assert 'Traceback' not in r.stderr, 'crashed on %r: %s' % (bad, r.stderr[-200:])
        assert 'must be set' in r.stderr or 'is not a URL' in r.stderr, \
            'unhelpful message for %r: %s' % (bad, r.stderr[-200:])


def test_missing_credentials_are_refused_before_any_work():
    r = _run('dump_supabase.py', {'SUPABASE_URL': '', 'SUPABASE_SERVICE_KEY': '',
                                  'DUMP_OUT': os.path.join(_TMP, 'y.json')})
    assert r.returncode == 1
    assert 'must be set' in r.stderr


# ── Restore ──────────────────────────────────────────────────────────────────

def _restored():
    if not RECEIVED:
        _dumped()
        r = _run('restore_supabase.py', _good_env(RESTORE_IN=_DUMP))
        assert r.returncode == 0, 'restore failed: %s' % (r.stderr or '')[-400:]
    return RECEIVED


def test_restore_writes_parents_before_children():
    """findings_history.run_id references analysis_runs(id). Written the other
    way round, Postgres rejects every child row."""
    order = list(dict.fromkeys(g['table'] for g in _restored()))
    assert order.index('analysis_runs') < order.index('findings_history'), order
    assert order.index('analysis_runs') < order.index('watchlist_merchants'), order


def test_restore_batches_a_large_table():
    got = [g for g in _restored() if g['table'] == 'analysis_runs']
    assert len(got) > 1, 'sent 1200 rows in a single request'
    assert sum(g['count'] for g in got) == len(TABLES['analysis_runs'])


def test_restore_upserts_rather_than_inserts():
    """A restore usually runs because rows were damaged, not deleted. Plain
    inserts would collide with every surviving row and abort."""
    assert all('merge-duplicates' in (g['prefer'] or '') for g in _restored())


def test_composite_key_table_conflicts_on_both_columns():
    """watchlist_cards is keyed on (bin, last4). Naming only one would merge
    unrelated cards that share a BIN — every card from one issuing bank."""
    cards = [g for g in _restored() if g['table'] == 'watchlist_cards']
    assert cards and all(g['on_conflict'] == 'bin,last4' for g in cards), cards


def test_restore_refuses_a_file_that_is_not_a_dump():
    junk = os.path.join(_TMP, 'junk.json')
    with open(junk, 'w', encoding='utf-8') as fh:
        fh.write('{"meta":{"format":"something-else"},"tables":{}}')
    r = _run('restore_supabase.py', _good_env(RESTORE_IN=junk))
    assert r.returncode == 1
    assert 'not a v1 data dump' in r.stderr


def test_restore_survives_a_byte_order_mark():
    """Anything that has been through Notepad or PowerShell's Set-Content
    picks up a BOM. Plain utf-8 dies on it with a traceback."""
    bom = os.path.join(_TMP, 'bom.json')
    with open(bom, 'w', encoding='utf-8-sig') as fh:
        json.dump(_dumped(), fh)
    r = _run('restore_supabase.py', _good_env(RESTORE_IN=bom))
    assert r.returncode == 0, (r.stderr or '')[-300:]
    assert 'Traceback' not in r.stderr


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failures = 0
    for t in tests:
        try:
            t()
            print('  PASS  %s' % t.__name__)
        except AssertionError as e:
            failures += 1
            print('  FAIL  %s: %s' % (t.__name__, e))
        except Exception as e:                            # noqa: BLE001
            failures += 1
            print('  ERROR %s: %s: %s' % (t.__name__, type(e).__name__, e))
    print('\n%d/%d passed' % (len(tests) - failures, len(tests)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
