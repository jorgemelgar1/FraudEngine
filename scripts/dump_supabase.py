"""Pull every row of every application table out of Supabase into one JSON file.

Why not `supabase db dump`: that shells out to pg_dump inside a Docker
container, and Docker Desktop is not installed on the machine this runs on.
Why not psycopg: not installed either, and installing a build toolchain to take
a backup is backwards. urllib is in the standard library and the runner already
talks to Supabase this way - see runner/supabase_io.py, whose transport this
mirrors on purpose.

What this does NOT capture, and why it does not matter here:

  * the schema - supabase/migrations/*.sql is the schema, and it is tagged
  * sequence positions - every table's primary key is a uuid or a natural key,
    so there is no sequence to leave pointing at the wrong number
  * auth.users, storage, and the other platform schemas - those belong to
    Supabase, not to this application, and PostgREST does not expose them

Credentials come from the environment, never from the command line, because
arguments are visible to anything that can list processes.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Ordered by the primary key so paging is stable: without an ORDER BY, Postgres
# is free to hand back the same row on two pages and drop another entirely.
TABLES = {
    'analysis_runs':       'id',
    'findings_history':    'id',
    'fraud_indicators':    'id',
    'runner_cycles':       'id',
    'watchlist_cards':     'bin,last4',
    'watchlist_merchants': 'company_name',
}

PAGE = 1000   # PostgREST's own default ceiling; asking for more is ignored


def fail(msg):
    print(f'ERROR: {msg}', file=sys.stderr)
    sys.exit(1)


def get(url, key, headers=None):
    req = urllib.request.Request(url, headers={
        'apikey':        key,
        'Authorization': f'Bearer {key}',
        'Accept':        'application/json',
        **(headers or {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read() or b'[]'), resp.headers
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', errors='replace')[:300]
        # The key prefix only - enough to tell "wrong key" from "right key,
        # wrong permission", never enough to be a leak.
        fail(f'HTTP {e.code} from Supabase (key {key[:6]}...): {detail}')
    except urllib.error.URLError as e:
        fail(f'Could not reach Supabase: {e.reason}')


def dump_table(base, key, table, order):
    rows, offset = [], 0
    while True:
        q = urllib.parse.urlencode({'select': '*', 'order': order})
        page, _ = get(f'{base}/rest/v1/{table}?{q}', key,
                      {'Range-Unit': 'items',
                       'Range': f'{offset}-{offset + PAGE - 1}'})
        rows.extend(page)
        if len(page) < PAGE:
            return rows
        offset += PAGE
        if offset > 5_000_000:
            fail(f'{table} exceeded 5M rows - refusing to keep paging')


def main():
    base = (os.environ.get('SUPABASE_URL') or '').rstrip('/')
    key  = os.environ.get('SUPABASE_SERVICE_KEY') or ''
    out  = os.environ.get('DUMP_OUT') or ''
    if not base or not key:
        fail('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in the environment.')
    if not out:
        fail('DUMP_OUT must be set to the file to write.')

    data, counts = {}, {}
    for table, order in TABLES.items():
        rows = dump_table(base, key, table, order)
        data[table] = rows
        counts[table] = len(rows)
        print(f'  {table:<22} {len(rows):>7,} rows', file=sys.stderr)

    payload = {
        'meta': {
            'taken_at':    datetime.now(timezone.utc).isoformat(),
            'format':      'cubo-fraud-engine-data-dump/1',
            'row_counts':  counts,
            'note':        'Data only. The schema is supabase/migrations/*.sql at the matching git tag.',
        },
        'tables': data,
    }
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1, default=str)

    print(f'TOTAL {sum(counts.values()):,} rows', file=sys.stderr)


if __name__ == '__main__':
    main()
