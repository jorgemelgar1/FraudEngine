"""Concatenate the migrations into one file that recreates the schema.

Run this after tagging a release:

    git tag -a v1.1.0 -m "..."
    python scripts/build_schema_baseline.py

Why concatenation and not `supabase db dump --schema`: that command runs
pg_dump inside a Docker container, and Docker is not installed on the machine
that takes these backups. Concatenation needs nothing, and the migrations are
already written to be applied in order from an empty database.

The output is schema only. It is committed to a public repository, so it must
never contain a row of data - see the guard at the bottom.
"""

import glob
import io
import os
import re
import subprocess
import sys


def main():
    files = sorted(f for f in glob.glob('supabase/migrations/[0-9]*.sql'))
    if not files:
        print('ERROR: no migrations found. Run this from the repository root.', file=sys.stderr)
        return 1

    label = subprocess.run(['git', 'describe', '--tags', '--exact-match'],
                           capture_output=True, text=True).stdout.strip()
    if not label:
        print('ERROR: HEAD is not on a tag. Tag the release first, or the '
              'baseline cannot be matched to a version.', file=sys.stderr)
        return 1

    header = [
        f'-- Cubo Pago fraud engine - full schema baseline for {label}\n',
        '--\n',
        '-- GENERATED FILE. Do not edit it by hand; edit the migrations and rebuild:\n',
        '--   python scripts/build_schema_baseline.py\n',
        '--\n',
        '-- Every migration in supabase/migrations/ concatenated in order, so one\n',
        '-- file recreates an empty database from nothing. The migrations remain the\n',
        '-- source of truth - this exists so that recovering the schema does not\n',
        '-- depend on having this repository checked out at the right tag.\n',
        '--\n',
        '-- There is NO DATA here, deliberately. This file is committed to a PUBLIC\n',
        '-- repository. The data lives in an encrypted backup outside the repo - see\n',
        '-- scripts/README.md.\n',
        '--\n',
        f'-- Migrations included ({len(files)}):\n',
    ]
    header += [f'--   {os.path.basename(f)}\n' for f in files]
    header.append('\n')

    parts = [''.join(header)]
    for f in files:
        body = io.open(f, encoding='utf-8').read()
        bar = '=' * 74
        parts.append(f'\n-- {bar}\n-- {os.path.basename(f)}\n-- {bar}\n\n{body.rstrip()}\n')

    text = ''.join(parts)

    # A migration is allowed to seed reference rows; a dump of live data is not
    # allowed anywhere near a public repo. Flag anything that looks like the
    # latter so it is a decision rather than an accident.
    suspicious = re.findall(r'^\s*(?:INSERT INTO|COPY)\s+\S+', text, re.IGNORECASE | re.MULTILINE)
    if suspicious:
        print(f'NOTE: {len(suspicious)} INSERT/COPY statement(s) carried over from the '
              'migrations. Confirm they are reference data, not live rows:', file=sys.stderr)
        for s in sorted(set(suspicious))[:10]:
            print(f'  {s.strip()}', file=sys.stderr)

    out = f'supabase/schema-{label}.sql'
    io.open(out, 'w', encoding='utf-8', newline='\n').write(text)
    print(f'wrote {out} ({os.path.getsize(out):,} bytes from {len(files)} migrations)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
