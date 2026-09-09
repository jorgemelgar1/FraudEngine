"""Interactive first-time setup for runner/.env.

    python3 runner/setup_env.py            # create or update runner/.env
    python3 runner/setup_env.py --check    # test an existing runner/.env

Safe to re-run. Existing values are offered as defaults, and anything it does
not manage - the Gmail client id and secret, the CMS settings - is carried
across untouched.

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


def read_existing_env() -> dict:
    """Parse the current runner/.env, so re-running keeps what is already right.

    Same minimal parsing config.py does. A config tool that cannot be re-run
    without retyping a service-role key is a config tool people avoid running,
    and then the config drifts.
    """
    if not os.path.exists(ENV_PATH):
        return {}
    values = {}
    with open(ENV_PATH, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


# Everything this script asks about. Anything else in an existing .env is
# carried across untouched — the Gmail client id and secret are added by hand
# after this runs, and silently dropping them would break `gmail.py` with no
# indication that setup was the cause.
MANAGED_KEYS = (
    'NEXT_PUBLIC_SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
    'RUNNER_EMAIL',
    'CUBO_REPORT_SENDER',
    'CUBO_REPORT_LABEL',
    'CUBO_CSV_URL_PATTERN',
    'RUNNER_LOOKBACK_DAYS',
)


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

def collect(existing=None):
    """Ask the six questions, offering whatever is already configured."""
    existing = existing or {}
    have = {k: v for k, v in existing.items() if v}
    if have:
        say(f'Found an existing {os.path.basename(ENV_PATH)}. Press Enter at '
            f'any prompt to keep the current value.')

    heading('1 of 6 - Supabase project URL')
    say('Supabase dashboard -> your project -> Settings -> Data API.')
    say('It looks like https://abcdefgh.supabase.co')
    while True:
        url, err = check_supabase_url(
            ask('Project URL', default=have.get('NEXT_PUBLIC_SUPABASE_URL')))
        if url:
            break
        say(f'  {err}')

    heading('2 of 6 - Supabase service role key')
    current_key = have.get('SUPABASE_SERVICE_ROLE_KEY')
    if current_key:
        say(f'Currently set ({current_key[:9]}...{current_key[-4:]}).')
        say('Press Enter to keep it, or paste a new one.')
    else:
        say('Same page, under API keys. It is the SECRET one, not the')
        say('publishable or anon key. It will not be shown as you type.')
    while True:
        key = ask('Service role key', secret=True, allow_empty=bool(current_key))
        if not key and current_key:
            key = current_key
            say('  Keeping the existing key.')
            break
        role, note = describe_key(key)
        if role == 'service_role':
            say('  Looks right (service_role).')
            break
        say(f'  {note}')
        if role is None and confirm('  Use it anyway?'):
            break

    heading('3 of 6 - Email to attribute automated runs to')
    say('Shown on the Historial screen so automated runs are distinguishable')
    say('from what a person uploaded.')
    email = ask('Runner email',
                default=have.get('RUNNER_EMAIL') or 'runner@cubopago.com')

    heading('4 of 6 - Who the report emails come from')
    say('Open a report email and look at the sender address. In Gmail, click')
    say('the sender name to see the full address.')
    say('The runner treats this as the strong signal that a message really is')
    say('a report, so a lookalike email cannot feed it a link.')
    while True:
        sender = ask('Report sender address',
                     default=have.get('CUBO_REPORT_SENDER'))
        if looks_like_address(sender):
            break
        say('  That does not look like an email address.')

    heading('5 of 6 - Gmail label (optional)')
    say('If you filter report emails into a label, naming it here narrows the')
    say('search to that label. LEAVE IT BLANK unless the label already exists')
    say('in Gmail - a label that does not exist matches nothing, and the only')
    say('symptom is the runner reporting zero emails.')
    label = ask('Gmail label (Enter for none)',
                default=have.get('CUBO_REPORT_LABEL'), allow_empty=True)

    heading('6 of 6 - A report link')
    current_pattern = have.get('CUBO_CSV_URL_PATTERN')
    if current_pattern:
        say('A link pattern is already configured. Press Enter to keep it.')
    say('Open one of the report emails and copy the CSV download link.')
    say('It is used ONLY to learn the shape of your links: it is not stored,')
    say('not printed back, and not written to any file.')
    while True:
        pasted = ask('Paste a report link', secret=True,
                     allow_empty=bool(current_pattern))
        if not pasted and current_pattern:
            pattern = current_pattern
            say('  Keeping the existing pattern.')
            break
        pattern, note = pattern_from_link(pasted)
        if pattern:
            if note:
                say(f'  Note: {note}')
            # Show the shape, never the link it came from.
            say(f'  Pattern: {pattern[:60]}...' if len(pattern) > 60
                else f'  Pattern: {pattern}')
            break
        say(f'  {note}')

    return {
        'NEXT_PUBLIC_SUPABASE_URL': url,
        'SUPABASE_SERVICE_ROLE_KEY': key,
        'RUNNER_EMAIL': email,
        'CUBO_REPORT_SENDER': sender,
        'CUBO_REPORT_LABEL': label,
        'CUBO_CSV_URL_PATTERN': pattern,
        'RUNNER_LOOKBACK_DAYS': have.get('RUNNER_LOOKBACK_DAYS', '1'),
    }


def write_env(values, existing=None):
    """Create .env at 0600 BEFORE writing, so the key is never briefly
    world-readable between creation and chmod.

    Any key in the existing file that this script does not manage is carried
    across. The Gmail client id and secret are added by hand after this runs,
    and dropping them would break gmail.py with nothing pointing at setup as
    the cause.
    """
    body = f"""# Written by runner/setup_env.py. Contains a live service-role key:
# never commit this file, never paste it anywhere. It is gitignored.

NEXT_PUBLIC_SUPABASE_URL={values['NEXT_PUBLIC_SUPABASE_URL']}
SUPABASE_SERVICE_ROLE_KEY={values['SUPABASE_SERVICE_ROLE_KEY']}
RUNNER_EMAIL={values['RUNNER_EMAIL']}

# The sender address is what identifies a message as a report, so a lookalike
# email cannot feed the runner a link.
CUBO_REPORT_SENDER={values['CUBO_REPORT_SENDER']}

# Optional. Blank means "search the whole mailbox by sender", which always
# works. A label that does not exist in Gmail matches nothing, and the only
# symptom is the runner finding zero emails.
CUBO_REPORT_LABEL={values['CUBO_REPORT_LABEL']}

# Only links matching this are ever downloaded. It is the runner's guard
# against a malformed or spoofed email; do not loosen it.
CUBO_CSV_URL_PATTERN={values['CUBO_CSV_URL_PATTERN']}

# Days of lookback. 1 means "today + yesterday".
RUNNER_LOOKBACK_DAYS={values['RUNNER_LOOKBACK_DAYS']}
"""

    carried = {k: v for k, v in (existing or {}).items()
               if k not in MANAGED_KEYS and v}
    if carried:
        body += '\n# Kept from the previous file.\n'
        for key in sorted(carried):
            body += f'{key}={carried[key]}\n'

    if IS_WINDOWS:
        with open(ENV_PATH, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(body)
    else:
        fd = os.open(ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.chmod(ENV_PATH, 0o600)
    return sorted(carried)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if '--check' in argv:
        heading('Checking runner/.env')
        if not os.path.exists(ENV_PATH):
            say(f'  No file at {ENV_PATH}. Run this without --check first.')
            return 1
        return 0 if test_connection() else 1

    existing = read_existing_env()
    if existing:
        backup = ENV_PATH + '.backup'
        with open(ENV_PATH, encoding='utf-8') as src:
            content = src.read()
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     0o600) if not IS_WINDOWS else None
        if fd is None:
            with open(backup, 'w', encoding='utf-8', newline='\n') as dst:
                dst.write(content)
        else:
            with os.fdopen(fd, 'w', encoding='utf-8') as dst:
                dst.write(content)
        say(f'Previous file kept as {os.path.basename(backup)}')

    values = collect(existing)
    carried = write_env(values, existing)

    heading('Written')
    say(f'  {ENV_PATH}')
    if not IS_WINDOWS:
        say('  permissions 0600 (only your user can read it)')
    if carried:
        say(f'  kept from the previous file: {", ".join(carried)}')

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
