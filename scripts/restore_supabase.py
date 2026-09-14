"""Write the rows from a dump file back into Supabase.

Upsert, not insert-or-delete. Two reasons:

  * A restore usually runs because a migration mangled existing rows, not
    because the table vanished. Upsert repairs those in place.
  * Deleting rows created after the backup was taken turns a recovery into a
    second outage. If a table genuinely must match the backup exactly, empty
    it deliberately first - that is a decision, not a side effect.

Order matters: analysis_runs before the tables whose foreign keys point at it,
or Postgres rejects the children.
"""

import json
import os
import sys
import urllib.error
import urllib.request

# Parents first. findings_history.run_id and both watchlist tables' last_run_id
# all reference analysis_runs(id).
ORDER = [
    'analysis_runs',
    'findings_history',
    'fraud_indicators',
    'runner_cycles',
    'watchlist_merchants',
    'watchlist_cards',
]

# PostgREST needs to be told which columns decide "same row" for an upsert.
CONFLICT = {
    'analysis_runs':       'id',
    'findings_history':    'id',
    'fraud_indicators':    'id',
    'runner_cycles':       'id',
    'watchlist_cards':     'bin,last4',
    'watchlist_merchants': 'company_name',
}

BATCH = 500


def fail(msg):
    print(f'ERROR: {msg}', file=sys.stderr)
    sys.exit(1)


def check_base_url(base):
    """Fail with a sentence, not a traceback, on a URL that cannot work.

    A failed console paste leaves a single invisible control character behind
    (Ctrl+V in the classic Windows console inserts 0x16 rather than pasting).
    urllib's own complaint about that is a six-frame traceback ending in
    "unknown url type", which tells the person running a backup nothing about
    what they did or how to fix it.
    """
    if not base.startswith(('http://', 'https://')):
        shown = repr(base) if base.strip() else '(empty)'
        fail(
            'SUPABASE_URL is not a URL: ' + shown + '\n'
            '       It should look like https://abcdefgh.supabase.co\n'
            '       If you pasted with Ctrl+V in a console window, that does '
            'not paste - use right-click instead.'
        )


def post(base, key, table, rows, on_conflict):
    body = json.dumps(rows, default=str).encode('utf-8')
    url = f'{base}/rest/v1/{table}?on_conflict={on_conflict}'
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'apikey':        key,
        'Authorization': f'Bearer {key}',
        'Content-Type':  'application/json',
        'Prefer':        'resolution=merge-duplicates,return=minimal',
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', errors='replace')[:300]
        fail(f'HTTP {e.code} upserting {table} (key {key[:6]}...): {detail}')
    except urllib.error.URLError as e:
        fail(f'Could not reach Supabase: {e.reason}')


def main():
    base = (os.environ.get('SUPABASE_URL') or '').rstrip('/')
    key  = os.environ.get('SUPABASE_SERVICE_KEY') or ''
    src  = os.environ.get('RESTORE_IN') or ''
    if not base or not key:
        fail('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set.')
    check_base_url(base)
    if not src:
        fail('RESTORE_IN must be set.')

    # utf-8-sig, not utf-8: it reads files with and without a byte-order mark.
    # Anything that has been through Notepad or PowerShell's Set-Content picks
    # up a BOM, and plain utf-8 dies on it with a traceback instead of a
    # sentence the person running a restore can act on.
    try:
        with open(src, encoding='utf-8-sig') as fh:
            payload = json.load(fh)
    except json.JSONDecodeError as e:
        fail(f'That file is not valid JSON ({e}). Is it really a dump?')
    except OSError as e:
        fail(f'Could not read {src}: {e}')

    if not isinstance(payload, dict) or payload.get('meta', {}).get('format') != 'cubo-fraud-engine-data-dump/1':
        fail('That file is not a v1 data dump.')
    if not isinstance(payload.get('tables'), dict):
        fail('That dump has no tables in it.')

    tables = payload['tables']
    for table in ORDER:
        rows = tables.get(table) or []
        if not rows:
            print(f'  {table:<22} nothing to write', file=sys.stderr)
            continue
        for i in range(0, len(rows), BATCH):
            post(base, key, table, rows[i:i + BATCH], CONFLICT[table])
        print(f'  {table:<22} {len(rows):>7,} rows upserted', file=sys.stderr)

    unknown = set(tables) - set(ORDER)
    if unknown:
        print('  NOTE: skipped unrecognised tables: ' + ', '.join(sorted(unknown)), file=sys.stderr)


if __name__ == '__main__':
    main()
