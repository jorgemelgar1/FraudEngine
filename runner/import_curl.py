"""Configure the CMS side of the runner from one browser cURL.

    python3 runner/import_curl.py                 # paste, then Ctrl+D
    python3 runner/import_curl.py --file curl.txt
    python3 runner/import_curl.py --dry-run       # show, change nothing

Chrome's "Copy as cURL" on the report request already contains everything the
runner needs: the API host, the report path, the Origin and Referer the API
may check, and the bearer token. Reading it out by hand means noticing that
one path segment is a country id and replacing it with a placeholder - which
is exactly the sort of step that gets done wrong once and then produces a 404
nobody can explain.

So it is done here instead. The token goes into the platform keystore (never
into .env), and the four settings are written into runner/.env leaving every
other line of that file alone.

The token is never printed. Only its fingerprint and expiry are shown.
"""

import argparse
import os
import re
import shlex
import sys
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import token_store     # noqa: E402

ENV_PATH = os.path.join(_HERE, '.env')

IS_WINDOWS = sys.platform == 'win32'

# The four settings a report request tells us. Everything else in .env is
# left exactly as it is.
CMS_KEYS = ('CUBO_API_ROOT', 'CUBO_REPORT_PATH',
            'CUBO_ORIGIN', 'CUBO_REFERER')


class CurlError(RuntimeError):
    """A parsing failure whose message is safe to print - never the token."""


# ── Parsing ──────────────────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """Join the line continuations every browser adds, in either dialect."""
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub(r'\\\n', ' ', text)      # bash / macOS
    text = re.sub(r'\^\n', ' ', text)      # cmd.exe
    return ' '.join(text.split())


def parse_curl(text: str) -> dict:
    """Return {'url': str, 'headers': {lowercased name: value}}."""
    text = _normalize(text)
    if 'curl' not in text:
        raise CurlError(
            'That does not look like a cURL command. In the browser: F12 -> '
            'Network -> right-click the request -> Copy -> Copy as cURL.')

    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as e:
        raise CurlError(f'Could not read the command ({e}).') from None

    url, headers = None, {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in ('-H', '--header') and i + 1 < len(tokens):
            name, _, value = tokens[i + 1].partition(':')
            headers[name.strip().lower()] = value.strip()
            i += 2
            continue
        if token in ('--url',) and i + 1 < len(tokens):
            url = tokens[i + 1]
            i += 2
            continue
        # Chrome puts the URL as the first bare argument after `curl`.
        if url is None and token.startswith('http'):
            url = token
        i += 1

    if not url:
        raise CurlError('No URL found in that command.')
    return {'url': url, 'headers': headers}


def token_from_headers(headers: dict) -> str:
    """The bearer token, cleaned. Raises if the capture was anonymous."""
    raw = headers.get('authorization') or headers.get('Authorization') or ''
    token = token_store._clean(raw)
    if not token:
        raise CurlError(
            'That request carried no Authorization header, so there is no '
            'token in it. Copy a request made while logged in - the report '
            'request itself is the right one.')
    if len(token) < 40:
        raise CurlError(
            f'The token in that request is only {len(token)} characters, '
            f'which is too short to be real. The copy probably got truncated.')
    return token


def templatize(url: str) -> dict:
    """Split a report URL into the four settings, or explain why it cannot be.

    The country id appears twice - once as a path segment and once as the
    `countryId` query parameter. Reading it from the query is what makes
    replacing the right path segment reliable rather than a guess at which
    number in the path is a country.
    """
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise CurlError(f'That URL has no host: {url[:60]}')

    query = urllib.parse.parse_qs(parts.query)
    country_id = (query.get('countryId') or [None])[0]

    segments = parts.path.split('/')
    if country_id:
        if country_id not in segments:
            raise CurlError(
                f'The URL says countryId={country_id} but no path segment '
                f'equals it, so the country cannot be substituted safely. '
                f'Path: {parts.path}')
        segments = ['{country_id}' if s == country_id else s for s in segments]
    else:
        # Fall back to a lone 1/2/3 segment, and say so - a silent guess here
        # would send every request to one country forever.
        candidates = [s for s in segments if s in ('1', '2', '3')]
        if len(candidates) != 1:
            raise CurlError(
                'Could not tell which part of the path is the country id. '
                'Capture the REPORT request (the one that emails you a CSV) '
                'rather than another endpoint.')
        segments = ['{country_id}' if s == candidates[0] else s
                    for s in segments]
        country_id = candidates[0]

    path = '/'.join(segments)
    return {
        'CUBO_API_ROOT': f'{parts.scheme}://{parts.netloc}',
        'CUBO_REPORT_PATH': path,
        'country_id_seen': country_id,
        'looks_like_report': 'report' in path.lower(),
    }


def origins_from_headers(headers: dict, api_root: str) -> dict:
    """Origin and Referer, falling back to the API host if absent."""
    origin = headers.get('origin') or ''
    referer = headers.get('referer') or headers.get('referrer') or ''
    if not origin and referer:
        parts = urllib.parse.urlsplit(referer)
        origin = f'{parts.scheme}://{parts.netloc}'
    if not referer and origin:
        referer = origin + '/'
    if not origin:
        origin, referer = api_root, api_root + '/'
    return {'CUBO_ORIGIN': origin, 'CUBO_REFERER': referer}


def settings_from_curl(text: str) -> tuple:
    """(settings dict, token, notes list) from a pasted cURL."""
    parsed = parse_curl(text)
    token = token_from_headers(parsed['headers'])

    shape = templatize(parsed['url'])
    settings = {
        'CUBO_API_ROOT': shape['CUBO_API_ROOT'],
        'CUBO_REPORT_PATH': shape['CUBO_REPORT_PATH'],
    }
    settings.update(
        origins_from_headers(parsed['headers'], shape['CUBO_API_ROOT']))

    notes = []
    if not shape['looks_like_report']:
        notes.append(
            'The path does not contain the word "report". If you copied a '
            'different request, the runner will ask the wrong endpoint.')
    notes.append(f'Country id seen in the URL: {shape["country_id_seen"]} '
                 f'(replaced with a placeholder, so all three work)')
    return settings, token, notes


# ── Writing .env ─────────────────────────────────────────────────────────────

def upsert_env(updates: dict, path: str = None) -> list:
    """Set these keys in .env, leaving every other line untouched.

    Line-based rather than a rewrite, so comments, ordering and the values
    this script knows nothing about all survive. A config file people edit by
    hand should not be reformatted by a tool that only owns four lines of it.
    """
    path = path or ENV_PATH
    lines = []
    if os.path.exists(path):
        with open(path, encoding='utf-8') as fh:
            lines = fh.read().split('\n')

    changed = []
    remaining = dict(updates)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        key = stripped.partition('=')[0].strip()
        if key in remaining:
            new = f'{key}={remaining.pop(key)}'
            if line != new:
                lines[index] = new
                changed.append(key)

    if remaining:
        if lines and lines[-1].strip():
            lines.append('')
        lines.append('# Added by runner/import_curl.py from a browser cURL.')
        for key in CMS_KEYS:
            if key in remaining:
                lines.append(f'{key}={remaining.pop(key)}')
                changed.append(key)
        for key in sorted(remaining):
            lines.append(f'{key}={remaining[key]}')
            changed.append(key)

    body = '\n'.join(lines)
    if not body.endswith('\n'):
        body += '\n'

    if IS_WINDOWS:
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(body)
    else:
        # 0600 before any content lands, then again in case the file existed
        # with looser permissions.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.chmod(path, 0o600)
    return changed


# ── CLI ──────────────────────────────────────────────────────────────────────

def read_input(file_path: str = None) -> str:
    if file_path:
        with open(file_path, encoding='utf-8', errors='replace') as fh:
            return fh.read()
    print('Pega el cURL completo y luego pulsa Ctrl+D:')
    print('  (F12 -> Network -> clic derecho en la petición del reporte')
    print('   -> Copy -> Copy as cURL)')
    print()
    return sys.stdin.read()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='runner/import_curl.py',
        description='Configure the CMS settings and token from a browser cURL.')
    parser.add_argument('--file', help='read the cURL from a file')
    parser.add_argument('--dry-run', action='store_true',
                        help='show what would be set, change nothing')
    args = parser.parse_args(argv)

    try:
        settings, token, notes = settings_from_curl(read_input(args.file))
    except CurlError as e:
        print(f'\nERROR: {e}')
        return 1
    except OSError as e:
        print(f'\nERROR: {e}')
        return 1

    print()
    print('Configuración encontrada:')
    for key in CMS_KEYS:
        print(f'  {key}={settings[key]}')
    print()
    print(f'  Token: {token_store.fingerprint(token)}')
    expires_at, seconds_left = token_store.expiry(token)
    if expires_at:
        print(f'         caduca {expires_at:%Y-%m-%d %H:%M} UTC '
              f'({seconds_left / 86400:.0f} días)')
        if seconds_left <= 0:
            print('         YA CADUCÓ - captura uno nuevo desde el navegador.')
            return 1
    else:
        print('         (no es un JWT; no se puede leer la caducidad)')

    for note in notes:
        print(f'\n  Nota: {note}')

    if args.dry_run:
        print('\nDRY RUN - no se escribió nada.')
        return 0

    changed = upsert_env(settings)
    stored = token_store.write_token(token)

    print()
    print(f'Escrito en {ENV_PATH}: {", ".join(changed) or "sin cambios"}')
    print(f'Token guardado en {stored}')
    if not IS_WINDOWS:
        print('  (permisos 0600 en ambos archivos)')
    print()
    print('Comprueba el ciclo completo con:')
    print('  python3 runner/cycle.py --country GT --dry-run')
    return 0


if __name__ == '__main__':
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError):
            pass
    sys.exit(main())
