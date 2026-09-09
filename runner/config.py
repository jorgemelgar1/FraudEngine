"""Configuration for the automated report runner.

Every Cubo-specific value - hostnames, endpoint paths, the report sender -
is read from the environment, never hardcoded. This repository is public.
Publishing the code is fine; publishing a map of which internal host serves
which endpoint is not, and the two are easy to separate.

The rule: **code describes HOW, environment supplies WHERE.**

Set these in a local `.env` beside this file (gitignored) or as real
environment variables. `.env.example` lists every name with placeholders and
no real values, so the shape stays documented without the addresses.

Nothing here has a real default. A missing variable produces a clear error
from `validate()` at startup rather than a request to an empty URL.
"""

import os


# ── .env loading ─────────────────────────────────────────────────────────────

def _load_dotenv():
    """Read runner/.env into os.environ. Deliberately minimal - no dependency.

    Existing environment variables win, so a systemd unit or a scheduled task
    can override the file without editing it.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if not os.path.exists(path):
        return
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


def _env(name: str, default: str = '') -> str:
    return os.environ.get(name, default).strip()


# ── Cubo CMS API ─────────────────────────────────────────────────────────────
# Captured from the browser's own network tab; see runner/PLAN.md. The report
# endpoint returns 200 with an EMPTY body and mails the CSV - it is
# fire-and-forget, with no job id to poll and no downloads page in the CMS.

API_ROOT = _env('CUBO_API_ROOT')

# `{country_id}` is substituted per request.
REPORT_PATH = _env('CUBO_REPORT_PATH')

# Endpoint that lists countries, used to confirm the id -> name mapping rather
# than trusting a guess.
COUNTRIES_PATH = _env('CUBO_COUNTRIES_PATH')

# Replayed because the API may check them. Everything else Chrome sends
# (sec-ch-ua, User-Agent) is browser noise and is deliberately not sent.
ORIGIN = _env('CUBO_ORIGIN')
REFERER = _env('CUBO_REFERER')

# Something in front of the API filters on the User-Agent: `Python-urllib/...`
# gets a 403. Captured from the real browser request by import_curl.py; the
# default is a plain modern Chrome string so an existing .env keeps working
# without being re-imported.
USER_AGENT = _env(
    'CUBO_USER_AGENT',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36')

ACCEPT_LANGUAGE = _env('CUBO_ACCEPT_LANGUAGE', 'es-ES,es;q=0.9,en;q=0.8')


# ── Countries ────────────────────────────────────────────────────────────────
# Confirmed against the live countries endpoint, not guessed. The id is used
# only to ASK for a report; the authoritative country for a downloaded file is
# the `country_name` column inside the CSV itself. A wrong id therefore
# produces a mislabelled request, never mislabelled analysis.

COUNTRIES = {
    'SV': {'id': 1, 'name': 'El Salvador', 'currency': 'USD'},
    'PA': {'id': 2, 'name': 'Panamá',      'currency': 'USD'},
    'GT': {'id': 3, 'name': 'Guatemala',   'currency': 'GTQ'},
}

# One country per hour, rotating. Only one report is ever in flight, which is
# what makes matching an incoming email to its request unambiguous.
ROTATION = ['SV', 'PA', 'GT']


# ── Analysis window ──────────────────────────────────────────────────────────
# "Today + yesterday". At 01:00 that is ~25 hours of data; at 23:00 it is ~47.
# Always at least 24, which the engine's longest hard window (card fan-out,
# slow tier) requires, and enough for the zero-settlement gate - which needs
# 6+ attempts from a merchant before it will look - to accumulate them.
LOOKBACK_DAYS = int(_env('RUNNER_LOOKBACK_DAYS', '1'))


# ── Report email ─────────────────────────────────────────────────────────────
# Every report mail is identical: same sender, same subject, no country and no
# date range anywhere in it. They even thread together in Gmail. Attribution
# therefore comes from the CSV contents, never from the message.

REPORT_SENDER = _env('CUBO_REPORT_SENDER')
REPORT_SUBJECT = _env('CUBO_REPORT_SUBJECT')

# Gmail label the report mail is filtered into, so the runner polls a small
# labelled set instead of searching the whole mailbox.
# Optional, and deliberately WITHOUT a default. A label narrows the search to
# a small set instead of the whole mailbox, which is nice - but a default
# naming a label the user has not created makes every search match nothing,
# and "0 correos encontrados" gives no hint that a label is the reason. Empty
# means "search by sender across the mailbox", which always works.
REPORT_LABEL = _env('CUBO_REPORT_LABEL')

# Regex matching the CSV link in the email body. The link is UNAUTHENTICATED:
# anyone holding the URL can download a full transaction export, which is why
# it is treated as a credential everywhere in this codebase - never logged,
# never in an exception message.
CSV_URL_PATTERN = _env('CUBO_CSV_URL_PATTERN')

# The HTML part wraps links in click tracking; the direct link is in the
# plain-text part. Preferring the direct one avoids a third-party dependency
# and does not register phantom "clicks".
TRACKING_HOST = _env('CUBO_TRACKING_HOST')

# Observed delivery was under a minute, but reports are generated
# asynchronously and a busy queue could be slower.
EMAIL_TIMEOUT_SECONDS = int(_env('RUNNER_EMAIL_TIMEOUT', '900'))
EMAIL_POLL_SECONDS = int(_env('RUNNER_EMAIL_POLL', '30'))


# ── Local paths ──────────────────────────────────────────────────────────────
# Platform-aware; see token_store.default_state_dir().

def state_dir() -> str:
    from token_store import default_state_dir
    return _env('RUNNER_STATE_DIR') or default_state_dir()


def state_path() -> str:
    return os.path.join(state_dir(), 'runner-state.json')


def work_dir() -> str:
    """Downloaded CSVs land here and are deleted in the same run."""
    return os.path.join(state_dir(), 'work')


# ── Supabase ─────────────────────────────────────────────────────────────────
# The runner writes findings with the service-role key exactly as the Vercel
# function does. Acceptable because this runs on one trusted machine; it must
# never be bundled into the distributed desktop app.

SUPABASE_URL = _env('NEXT_PUBLIC_SUPABASE_URL')
SUPABASE_SERVICE_KEY = _env('SUPABASE_SERVICE_ROLE_KEY')
RUN_BY_EMAIL = _env('RUNNER_EMAIL')


# ── Gmail ────────────────────────────────────────────────────────────────────
# From a Google Cloud OAuth client of type "Desktop app". Neither value is
# really secret - a desktop client ships both inside the distributed binary,
# which is why the flow uses PKCE - but they still stay out of this
# repository. The refresh token, which IS a credential, is never in .env: it
# lives beside the CMS token, protected the same way.

GMAIL_CLIENT_ID = _env('GMAIL_CLIENT_ID')
GMAIL_CLIENT_SECRET = _env('GMAIL_CLIENT_SECRET')


# ── Startup validation ───────────────────────────────────────────────────────

# Grouped so each entry point demands only what it actually uses. Manual-URL
# mode needs no CMS credentials at all - the CDN link is unauthenticated - and
# refusing to start without them would be a lie about what is required.

GROUPS = {
    'cms': [
        ('CUBO_API_ROOT',    API_ROOT),
        ('CUBO_REPORT_PATH', REPORT_PATH),
        ('CUBO_ORIGIN',      ORIGIN),
        ('CUBO_REFERER',     REFERER),
    ],
    'mail': [
        ('CUBO_REPORT_SENDER', REPORT_SENDER),
    ],
    # Needed to *validate* a report link before fetching it, which is why it
    # is separate from 'cms': downloading needs the pattern, not the API.
    'url': [
        ('CUBO_CSV_URL_PATTERN', CSV_URL_PATTERN),
    ],
    'supabase': [
        ('NEXT_PUBLIC_SUPABASE_URL', SUPABASE_URL),
        ('SUPABASE_SERVICE_ROLE_KEY', SUPABASE_SERVICE_KEY),
    ],
    'gmail': [
        ('GMAIL_CLIENT_ID', GMAIL_CLIENT_ID),
        ('GMAIL_CLIENT_SECRET', GMAIL_CLIENT_SECRET),
    ],
}


class ConfigError(RuntimeError):
    """Something is missing from runner/.env.

    A subclass of RuntimeError so that every existing caller keeps catching
    it unchanged. It exists only so the scheduled cycle can record WHICH kind
    of failure happened (migration 0012) - "the .env is incomplete" and "the
    CMS refused us" need different responses, and both used to arrive as a
    bare RuntimeError that nothing could tell apart.
    """


def validate(*groups: str):
    """Raise with a readable list of what is missing, rather than failing
    later with a request to an empty URL.

        validate('url', 'supabase')     # manual-URL mode
        validate('cms', 'mail', 'url', 'supabase')   # the full cycle

    No arguments checks everything.
    """
    groups = groups or tuple(GROUPS)
    missing = []
    for group in groups:
        if group not in GROUPS:
            raise ValueError(f'Unknown config group {group!r}')
        missing += [name for name, value in GROUPS[group] if not value]
    if missing:
        raise ConfigError(
            'Missing configuration: ' + ', '.join(missing) + '\n'
            'Copy runner/.env.example to runner/.env and fill it in. '
            'Real values are deliberately absent from this repository.'
        )


def country_by_code(code: str) -> dict:
    code = (code or '').strip().upper()
    if code not in COUNTRIES:
        raise ValueError(
            f'Unknown country {code!r}. Known: {", ".join(sorted(COUNTRIES))}'
        )
    return COUNTRIES[code]


def country_for_hour(hour: int) -> str:
    """Which country this hour's slot belongs to.

    Derived from the clock rather than stored, so the rotation is stateless
    and a missed run does not shift the schedule - that country simply picks
    up at its next slot.
    """
    return ROTATION[hour % len(ROTATION)]
