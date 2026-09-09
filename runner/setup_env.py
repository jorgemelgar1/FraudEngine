"""Interactive first-time setup for runner/.env.

    python3 runner/setup_env.py            # create or replace runner/.env
    python3 runner/setup_env.py --check    # test an existing runner/.env

Writing that file by hand means hand-writing a regular expression and pasting
a service-role key on a command line, where it lands in shell history. Both are
easy to get wrong and one of them is a security problem, so this asks a few
questions instead.

What it protects you from:

  * pasting the ANON key where the SERVICE ROLE key belongs - they look
    identical and the failure is a confusing permissions error much later
  * a regex that does not actually match your report links, which would make
    the runner refuse every download with no obvious reason
  * the key appearing in `history`, in `ps`, or on screen behind you
  * a world-readable .env - the file is created 0600 before anything is
    written to it

Nothing typed here is sent anywhere. The report link you paste is used only to
work out the SHAPE of your links and is never stored, never printed back, and
never written to disk.
"""

import base64
import json
import os
import re
import sys
from getpass import getpass

_HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(_HERE, '.env')

IS_WINDOWS = sys.platform == 'win32'


# ── Small console helpers ────────────────────────────────────────────────────

def say(msg=''):
    print(msg, flush=True)


def heading(text):
    say()
    say(text)
    say('-' * len(text))


def ask(prompt, default=None, secret=False, allow_empty=False):
    """Prompt until the answer is non-empty (or a default is accepted)."""
    suffix = f' [{default}]' if default else ''
    while True:
        raw = (getpass(f'{prompt}{suffix}: ') if secret
               else input(f'{prompt}{suffix}: '))
        value = raw.strip()
        if not value and default:
            return default
        if value or allow_empty:
            return value
        say('  (required)')


def confirm(prompt):
    return input(f'{prompt} [y/N]: ').strip().lower() in ('y', 'yes', 's', 'si')


# ── Validation ───────────────────────────────────────────────────────────────

def check_supabase_url(url):
    url = url.strip().rstrip('/')
    if not url.startswith('https://'):
        return None, 'It must start with https://'
    if '/rest/v1' in url or '/dashboard' in url:
        return None, ('That looks like a full API or dashboard address. Use '
                      'just the Project URL, ending in .supabase.co')
    return url, None


def describe_key(key):
    """(role, note) for a Supabase key, so a wrong paste is caught here.

    Legacy keys are JWTs whose payload carries the role in plain sight. The
    newer `sb_secret_...` / `sb_publishable_...` keys say it in the prefix.
    """
    key = key.strip()
    if key.startswith('sb_secret_'):
        return 'service_role', None
    if key.startswith('sb_publishable_'):
        return 'anon', 'That is the PUBLISHABLE key. You need the SECRET one.'
    parts = key.split('.')
    if len(parts) == 3:
        try:
            seg = parts[1] + '=' * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(seg))
        except Exception:
            return None, 'That looks like a JWT but could not be read.'
        role = payload.get('role')
        if role == 'service_role':
            return 'service_role', None
        if role == 'anon':
            return 'anon', ('That is the ANON key - the one the website uses. '
                            'The runner needs the SERVICE ROLE key.')
        return role, f'Unexpected role in the key: {role!r}'
    return None, ('That does not look like a Supabase key. It should start '
                  'with sb_secret_ or eyJ')


UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                     r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')


def pattern_from_link(link):
    """Turn one real report link into a regex matching links of that shape.

    Deliberately strict: the host and path stay literal, and only the
    changing report id becomes a wildcard. The pattern is the runner's guard
    against downloading whatever a malformed or spoofed email contains, so a
    loose pattern would quietly remove that protection.
    """
    link = link.strip().strip('<>').strip('"').strip("'")
    if not link.startswith('http'):
        return None, 'That does not look like a link.'

    if '?' in link:
        base, _query = link.split('?', 1)
        note = ('The link had a ?query on the end. It has been dropped, which '
                'is usually right - but if downloads fail, tell me.')
        link = base
    else:
        note = None

    if not UUID_RE.search(link):
        return None, ('No report id found in that link. Expected something '
                      'like ...\\/8943090c-1111-2222-3333-444455556666.csv')

    # Escape everything, then re-open only the report id.
    escaped = re.escape(link)
    for match in set(UUID_RE.findall(link)):
        escaped = escaped.replace(re.escape(match), '[0-9a-fA-F-]{36}')

    if not re.fullmatch(escaped, link):
        return None, 'Built a pattern but it did not match the link. Tell me.'
    return escaped, note


# ── Connection test ──────────────────────────────────────────────────────────

def test_connection():
    """Prove the credentials work, before anything depends on them."""
    sys.path.insert(0, _HERE)
    for module in ('config', 'supabase_io'):
        sys.modules.pop(module, None)
    import config          # noqa: PLC0415
    import supabase_io     # noqa: PLC0415

    try:
        config.validate('url', 'supabase')
    except RuntimeError as e:
        say(f'  {e}')
        return False

    try:
        watchlist = supabase_io.load_watchlist()
        indicators = supabase_io.load_indicators()
    except supabase_io.SupabaseError as e:
        say(f'  Could not read from Supabase:\n  {e}')
        return False

    say(f'  Connected. {len(watchlist["merchants"])} merchants and '
        f'{len(watchlist["cards"])} cards on the watchlist, '
        f'{len(indicators)} active indicators.')

    # The runner is useless if migration 0011 has not been applied, and the
    # symptom (duplicate findings forever) appears only in production. Ask the
    # database directly instead of trusting that it was run.
    try:
        rows = supabase_io.sb_rest(
            'GET', 'findings_history?select=finding_key&limit=1')
        if rows and rows[0].get('finding_key') is None:
            say('  WARNING: findings_history.finding_key is empty. Apply '
                'supabase/migrations/0011_finding_key_generated.sql')
            return False
        say('  Migration 0011 looks applied (finding_key is populated).')
    except supabase_io.SupabaseError:
        say('  (could not verify migration 0011 - not fatal)')
    return True


# ── Main ─────────────────────────────────────────────────────────────────────

def collect():
    say(__doc__.strip().split('\n\n')[0])

    heading('1 of 4 - Supabase project URL')
    say('Supabase dashboard -> your project -> Settings -> Data API.')
    say('It looks like https://abcdefgh.supabase.co')
    while True:
        url, err = check_supabase_url(ask('Project URL'))
        if url:
            break
        say(f'  {err}')

    heading('2 of 4 - Supabase service role key')
    say('Same page, under API keys. It is the SECRET one, not the publishable')
    say('or anon key. It will not be shown as you type.')
    while True:
        key = ask('Service role key', secret=True)
        role, note = describe_key(key)
        if role == 'service_role':
            say('  Looks right (service_role).')
            break
        say(f'  {note}')
        if role is None and confirm('  Use it anyway?'):
            break

    heading('3 of 4 - Email to attribute automated runs to')
    say('Shown on the Historial screen so automated runs are distinguishable')
    say('from what a person uploaded.')
    email = ask('Runner email', default='runner@cubopago.com')

    heading('4 of 4 - A report link')
    say('Open one of the report emails and copy the CSV download link.')
    say('It is used ONLY to learn the shape of your links: it is not stored,')
    say('not printed back, and not written to any file.')
    while True:
        pattern, note = pattern_from_link(ask('Paste a report link', secret=True))
        if pattern:
            if note:
                say(f'  Note: {note}')
            # Show the shape, never the link it came from.
            say(f'  Pattern: {pattern[:60]}...' if len(pattern) > 60
                else f'  Pattern: {pattern}')
            break
        say(f'  {note}')

    return url, key, email, pattern


def write_env(url, key, email, pattern):
    """Create .env at 0600 BEFORE writing, so the key is never briefly
    world-readable between creation and chmod."""
    body = f"""# Written by runner/setup_env.py. Contains a live service-role key:
# never commit this file, never paste it anywhere. It is gitignored.

NEXT_PUBLIC_SUPABASE_URL={url}
SUPABASE_SERVICE_ROLE_KEY={key}
RUNNER_EMAIL={email}

# Only links matching this are ever downloaded. It is the runner's guard
# against a malformed or spoofed email; do not loosen it.
CUBO_CSV_URL_PATTERN={pattern}

# Days of lookback. 1 means "today + yesterday".
RUNNER_LOOKBACK_DAYS=1

# The CMS values below are needed only once the runner requests reports by
# itself (step 5 of runner/PLAN.md). Manual-URL mode does not use them:
# the report link is unauthenticated.
# CUBO_API_ROOT=
# CUBO_REPORT_PATH=
# CUBO_ORIGIN=
# CUBO_REFERER=
# CUBO_REPORT_SENDER=
"""
    if IS_WINDOWS:
        with open(ENV_PATH, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(body)
    else:
        fd = os.open(ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.chmod(ENV_PATH, 0o600)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if '--check' in argv:
        heading('Checking runner/.env')
        if not os.path.exists(ENV_PATH):
            say(f'  No file at {ENV_PATH}. Run this without --check first.')
            return 1
        return 0 if test_connection() else 1

    if os.path.exists(ENV_PATH):
        say(f'{ENV_PATH} already exists.')
        if not confirm('Replace it?'):
            say('Nothing changed.')
            return 0
        backup = ENV_PATH + '.backup'
        os.replace(ENV_PATH, backup)
        if not IS_WINDOWS:
            os.chmod(backup, 0o600)
        say(f'Previous file kept as {os.path.basename(backup)}')

    url, key, email, pattern = collect()
    write_env(url, key, email, pattern)

    heading('Written')
    say(f'  {ENV_PATH}')
    if not IS_WINDOWS:
        say('  permissions 0600 (only your user can read it)')

    heading('Testing the connection')
    ok = test_connection()

    say()
    if ok:
        say('Ready. Try a dry run:')
        say('  python3 runner/run.py --url "<link from a report email>" --dry-run')
    else:
        say('Setup finished but the check did not pass - see above.')
    return 0 if ok else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say('\nCancelled. Nothing was written.')
        sys.exit(130)
