"""Read report emails from Gmail over the API, using nothing but the stdlib.

    python3 runner/gmail.py --authorize    # one time, interactive
    python3 runner/gmail.py --check        # is it working?
    python3 runner/gmail.py --latest       # find the newest report link

`google-api-python-client` would do this too, but it drags in a large
dependency tree for what is three HTTP calls, and the runner's whole
dependency set today is pandas + numpy. OAuth is a form POST, refresh is a
form POST, and reading a message is a GET. So: urllib, like everything else
here.

**Scope is `gmail.readonly`.** The runner can read mail and nothing else - it
cannot send, delete, or modify anything, and Google enforces that rather than
this code promising it.

Three secrets are involved and none of them is ever printed:

  client id / secret   identify the app. Not really secret for a desktop
                       client (they ship inside distributed apps), but they
                       live in runner/.env rather than in this repository.
  refresh token        long-lived, stored the same way the CMS token is:
                       DPAPI on Windows, a 0600 file on Linux.
  access token         one hour, kept in memory only, never written down.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config          # noqa: E402
import report_mail     # noqa: E402
import state as runner_state   # noqa: E402
import token_store     # noqa: E402


AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
API_ROOT = 'https://gmail.googleapis.com/gmail/v1/users/me'

# Read-only. The narrowest scope that can see a message body.
SCOPE = 'https://www.googleapis.com/auth/gmail.readonly'

# Any loopback port is valid for a Desktop-app client. Nothing has to be
# listening on it: the browser lands on a "can't connect" page whose ADDRESS
# BAR holds the authorization code, and that is what gets pasted back. This
# works on a Pi with no browser and no port forwarding.
REDIRECT_URI = 'http://localhost:8080/'


class GmailError(RuntimeError):
    """A failure whose message is safe to print - never contains a token."""


def _token_path() -> str:
    """Beside the CMS token, protected the same way."""
    ext = 'dpapi' if token_store.IS_WINDOWS else 'token'
    return os.path.join(config.state_dir(), f'gmail-refresh.{ext}')


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _post_form(url: str, fields: dict, timeout: int = 30) -> dict:
    data = urllib.parse.urlencode(fields).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise GmailError(_explain(e)) from None
    except urllib.error.URLError as e:
        raise GmailError(f'No se pudo contactar a Google: {e.reason}') from None


def _get_json(url: str, access_token: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        url, headers={'Authorization': f'Bearer {access_token}'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise GmailError(_explain(e)) from None
    except urllib.error.URLError as e:
        raise GmailError(f'No se pudo contactar a Gmail: {e.reason}') from None


def _explain(err) -> str:
    """Turn a Google error body into something actionable.

    Google's OAuth errors are terse and the interesting part is which of a
    handful of well-known mistakes was made, so they are named here rather
    than left for a search engine.
    """
    try:
        body = err.read().decode('utf-8', errors='replace')
        parsed = json.loads(body)
    except Exception:
        body, parsed = '(sin cuerpo)', {}

    code = parsed.get('error')
    if isinstance(code, dict):                      # API errors nest it
        code = code.get('status') or code.get('message')
    desc = parsed.get('error_description') or ''

    hints = {
        'invalid_grant': (
            'El refresh token ya no sirve. Casi siempre es una de dos cosas:\n'
            '  - la app de Google sigue en "Testing", donde los tokens '
            'caducan a los 7 días. Publícala como "In production".\n'
            '  - se revocó el acceso desde la cuenta de Google.\n'
            'Vuelve a autorizar: python3 runner/gmail.py --authorize'),
        'invalid_client': (
            'GMAIL_CLIENT_ID o GMAIL_CLIENT_SECRET están mal. Cópialos otra '
            'vez desde Google Cloud → APIs y servicios → Credenciales.'),
        'redirect_uri_mismatch': (
            f'El cliente de OAuth debe ser de tipo "Aplicación de escritorio" '
            f'(Desktop app) para aceptar {REDIRECT_URI}'),
        'access_denied': 'Se canceló la autorización en la pantalla de Google.',
    }
    if err.code == 403 and 'Gmail API has not been used' in body:
        return ('La API de Gmail no está habilitada en el proyecto. '
                'Google Cloud → APIs y servicios → Habilitar APIs → Gmail API.')
    if err.code == 401:
        return 'Google rechazó el token de acceso (HTTP 401).'

    hint = hints.get(code)
    if hint:
        return f'{code}: {hint}'
    return f'Google respondió HTTP {err.code} ({code or "?"}). {desc or body[:200]}'


# ── One-time authorization ───────────────────────────────────────────────────

def _pkce():
    """PKCE verifier + S256 challenge.

    A desktop client's secret ships inside the app and is not really secret,
    so PKCE is what actually binds the returned code to this session.
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip('=')
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip('=')
    return verifier, challenge


def authorization_url(client_id: str, challenge: str, state_token: str) -> str:
    params = {
        'client_id': client_id,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': SCOPE,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': state_token,
        # Required to be given a refresh token at all, and `prompt=consent`
        # forces a new one even if this account authorized before - otherwise
        # re-authorizing returns an access token and no refresh token, and
        # the failure appears days later.
        'access_type': 'offline',
        'prompt': 'consent',
    }
    return f'{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}'


def code_from_redirect(pasted: str, expect_state: str = None) -> str:
    """Pull ?code= out of whatever the browser ended up showing.

    Accepts the whole redirected URL (what people actually copy) or a bare
    code, because both are things a reasonable person pastes here.
    """
    pasted = (pasted or '').strip().strip('"').strip("'")
    if not pasted:
        raise GmailError('No se pegó nada.')

    if pasted.startswith('http://') or pasted.startswith('https://'):
        query = urllib.parse.urlparse(pasted).query
        params = urllib.parse.parse_qs(query)
        if 'error' in params:
            raise GmailError(
                f'Google devolvió un error: {params["error"][0]}. '
                'Si dice access_denied, se canceló la pantalla de permisos.')
        codes = params.get('code')
        if not codes:
            raise GmailError(
                'Esa URL no trae ?code=. Copia la barra de direcciones '
                'completa de la página a la que te redirigió Google '
                '(aunque diga que no se pudo conectar).')
        got_state = (params.get('state') or [None])[0]
        if expect_state and got_state != expect_state:
            raise GmailError(
                'El parámetro "state" no coincide. Vuelve a empezar la '
                'autorización; no uses un enlace viejo.')
        return codes[0]

    if re.fullmatch(r'[A-Za-z0-9._~%/-]{20,}', pasted):
        return pasted
    raise GmailError('Eso no parece ni una URL ni un código de autorización.')


def exchange_code(client_id, client_secret, code, verifier) -> dict:
    payload = _post_form(TOKEN_ENDPOINT, {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'code_verifier': verifier,
        'grant_type': 'authorization_code',
        'redirect_uri': REDIRECT_URI,
    })
    if not payload.get('refresh_token'):
        raise GmailError(
            'Google no devolvió un refresh token. Suele pasar cuando la '
            'cuenta ya había autorizado esta app: quita el acceso en '
            'https://myaccount.google.com/permissions y vuelve a intentar.')
    return payload


def authorize(argv=None) -> int:
    """Interactive one-time setup. Stores only the refresh token."""
    config.validate('gmail')
    client_id, client_secret = config.GMAIL_CLIENT_ID, config.GMAIL_CLIENT_SECRET

    verifier, challenge = _pkce()
    state_token = secrets.token_urlsafe(24)
    url = authorization_url(client_id, challenge, state_token)

    print()
    print('1. Abre este enlace en cualquier navegador (tu laptop sirve):')
    print()
    print(f'   {url}')
    print()
    print('2. Inicia sesión con la cuenta que recibe los reportes y acepta.')
    print('   Si aparece "Google no ha verificado esta aplicación", entra en')
    print('   Configuración avanzada -> Ir a (no seguro). Es tu propia app.')
    print()
    print('3. El navegador terminará en una página que dice que NO SE PUDO')
    print('   CONECTAR. Eso es lo esperado: no hay nada escuchando en')
    print(f'   {REDIRECT_URI}. Copia la barra de direcciones completa.')
    print()

    pasted = input('Pega aquí la URL completa: ')
    code = code_from_redirect(pasted, expect_state=state_token)

    payload = exchange_code(client_id, client_secret, code, verifier)
    refresh = payload['refresh_token']
    path = token_store.write_token(refresh, path=_token_path())

    print()
    print(f'Guardado: {path}')
    print(f'  {token_store.fingerprint(refresh)}')
    print()
    print('Probando la conexión...')
    return 0 if check() else 1


# ── Using it ─────────────────────────────────────────────────────────────────

_cached = {'token': None, 'expires_at': None}


def access_token(force: bool = False) -> str:
    """A valid access token, refreshing at most once an hour.

    Cached in memory only. A run lasts seconds, so this is really about not
    making two token calls when one will do.
    """
    now = datetime.now(timezone.utc)
    if not force and _cached['token'] and _cached['expires_at'] and \
            now < _cached['expires_at'] - timedelta(seconds=60):
        return _cached['token']

    config.validate('gmail')
    try:
        refresh = token_store.read_token(_token_path())
    except FileNotFoundError:
        raise GmailError(
            'No hay autorización de Gmail todavía. Ejecuta:\n'
            '  python3 runner/gmail.py --authorize') from None

    payload = _post_form(TOKEN_ENDPOINT, {
        'client_id': config.GMAIL_CLIENT_ID,
        'client_secret': config.GMAIL_CLIENT_SECRET,
        'refresh_token': refresh,
        'grant_type': 'refresh_token',
    })
    token = payload.get('access_token')
    if not token:
        raise GmailError('Google no devolvió un access token.')
    _cached['token'] = token
    _cached['expires_at'] = now + timedelta(seconds=int(payload.get('expires_in', 3600)))
    return token


def search(query: str, max_results: int = 10) -> list:
    """Message ids matching a Gmail search, newest first."""
    url = (f'{API_ROOT}/messages?'
           + urllib.parse.urlencode({'q': query, 'maxResults': max_results}))
    payload = _get_json(url, access_token())
    return [m['id'] for m in (payload.get('messages') or [])]


def fetch_raw(message_id: str):
    """(raw_rfc822_bytes, received_at) for one message.

    `format=raw` on purpose: it gives the same bytes IMAP would, so
    report_mail parses identically no matter how the message was fetched.
    """
    url = f'{API_ROOT}/messages/{message_id}?format=raw'
    payload = _get_json(url, access_token())
    raw_b64 = payload.get('raw')
    if not raw_b64:
        raise GmailError(f'El mensaje {message_id} no trae contenido.')
    raw = base64.urlsafe_b64decode(raw_b64 + '=' * (-len(raw_b64) % 4))

    # internalDate is when GOOGLE received it. The Date header is written by
    # the sender, and a wrong clock at the other end would make a fresh
    # report look old - or an old one look fresh.
    received = None
    if payload.get('internalDate'):
        received = datetime.fromtimestamp(
            int(payload['internalDate']) / 1000, tz=timezone.utc)
    return raw, received


def find_report(after: datetime = None, skip_processed: bool = True,
                max_results: int = 10):
    """The newest usable report link, or None.

    Returns (message_id, url, received_at). The url is a credential: it is
    never logged here and callers use cubo_api.redact_url().
    """
    query = report_mail.search_query(after=after)
    ids = search(query, max_results=max_results)
    if not ids:
        return None

    st = runner_state.load() if skip_processed else None

    candidates = []
    for message_id in ids:
        if st is not None and runner_state.is_processed(message_id, st):
            continue
        raw, received = fetch_raw(message_id)
        candidates.append((message_id, received, raw))

    for message_id, received, raw in report_mail.newest_first(candidates):
        # A report queued before we asked belongs to an earlier cycle. Without
        # this, a stale mail sitting in the label would be consumed as though
        # it answered the request we just made.
        if after and received and received < after:
            continue
        url, _why = report_mail.link_from_raw(raw)
        if url:
            return message_id, url, received
    return None


def wait_for_report(requested_at: datetime, timeout: int = None,
                    poll: int = None, on_wait=None):
    """Poll until a report newer than `requested_at` shows up, or give up.

    Giving up is the correct ending. Re-triggering inside the same cycle would
    queue a duplicate report and a duplicate email; that country simply waits
    for its next slot, and the overlapping window means nothing is lost.
    """
    timeout = timeout if timeout is not None else config.EMAIL_TIMEOUT_SECONDS
    poll = poll if poll is not None else config.EMAIL_POLL_SECONDS
    deadline = time.monotonic() + timeout

    while True:
        found = find_report(after=requested_at)
        if found:
            return found
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if on_wait:
            on_wait(int(remaining))
        time.sleep(min(poll, remaining))


# ── Diagnostics ──────────────────────────────────────────────────────────────

def check() -> bool:
    try:
        token = access_token()
    except GmailError as e:
        print(f'  {e}')
        return False
    profile = _get_json(f'{API_ROOT}/profile', token)
    print(f'  Conectado como {profile.get("emailAddress")} '
          f'({profile.get("messagesTotal", 0):,} mensajes en la cuenta)')

    query = report_mail.search_query()
    ids = search(query, max_results=5)
    print(f'  Búsqueda: {query}')
    if not ids:
        print('  No se encontraron correos de reporte todavía. Si ya te llegó')
        print('  uno, revisa CUBO_REPORT_SENDER y CUBO_REPORT_LABEL.')
        return True

    print(f'  {len(ids)} correo(s) de reporte encontrados.')
    raw, received = fetch_raw(ids[0])
    url, why = report_mail.link_from_raw(raw)
    when = f'{received:%Y-%m-%d %H:%M} UTC' if received else 'sin fecha'
    print(f'  El más reciente ({when}): {why}')
    return url is not None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='runner/gmail.py',
        description='Authorize and read Cubo report emails from Gmail.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--authorize', action='store_true',
                       help='one-time interactive setup')
    group.add_argument('--check', action='store_true',
                       help='verify the stored authorization works')
    group.add_argument('--latest', action='store_true',
                       help='find the newest report link (prints it redacted)')
    args = parser.parse_args(argv)

    try:
        # Reading mail needs to know which mail is a report and what a valid
        # link looks like; authorizing does not. Demand only what is used.
        if not args.authorize:
            config.validate('gmail', 'mail', 'url')
        if args.authorize:
            return authorize()
        if args.check:
            return 0 if check() else 1
        if args.latest:
            import cubo_api  # noqa: PLC0415
            found = find_report(skip_processed=False)
            if not found:
                print('No se encontró ningún reporte con enlace usable.')
                return 1
            message_id, url, received = found
            print(f'  mensaje  {message_id}')
            print(f'  recibido {received:%Y-%m-%d %H:%M} UTC' if received
                  else '  recibido sin fecha')
            print(f'  enlace   {cubo_api.redact_url(url)}')
            return 0
    except GmailError as e:
        print(f'ERROR: {e}')
        return 1
    return 0


if __name__ == '__main__':
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError):
            pass
    sys.exit(main())
