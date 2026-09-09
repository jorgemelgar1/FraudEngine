"""Store and read the CMS bearer token, on Windows or Linux.

Written behind one interface from the start rather than retrofitted, because
the runner is being built on Windows and will move to a Raspberry Pi. Getting
this wrong is how "we'll move it to the Pi eventually" becomes "it still runs
on Jorge's laptop two years later".

  Windows   DPAPI (CryptUnprotectData) via ctypes - no pywin32 needed, so the
            runner keeps the engine's dependency set (pandas + numpy).
            Decryptable only by the Windows account that wrote it.

  Linux     a 0600 file under $XDG_DATA_HOME. On a dedicated single-purpose
            Pi this is roughly equivalent in practice: DPAPI's real value is
            protecting against OTHER users on a shared machine, and a Pi that
            does nothing else has none. In both cases the actual protection is
            "nobody else has access to the box".

Neither protects against something running AS the runner's own user. That is
inherent to unattended automation: a scheduled job must read the token with no
human present, so anything in that session can too. A passphrase would be
stronger and would also defeat the entire purpose.

The token is a live CMS credential valid for 90 days. Never log the value -
use fingerprint() for anything that reaches a log or a screen.
"""

import os
import sys


IS_WINDOWS = sys.platform == 'win32'


def default_state_dir() -> str:
    """Per-platform directory for runner state."""
    if IS_WINDOWS:
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
        return os.path.join(base, 'CuboFraudEngine')
    base = os.environ.get('XDG_DATA_HOME') or os.path.join(
        os.path.expanduser('~'), '.local', 'share')
    return os.path.join(base, 'cubo-fraud-engine')


def default_token_path() -> str:
    ext = 'dpapi' if IS_WINDOWS else 'token'
    return os.path.join(default_state_dir(), f'cms-token.{ext}')


# ── Windows: DPAPI ───────────────────────────────────────────────────────────

def _win_unprotect(blob: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    blob_in = _Blob(len(blob),
                    ctypes.cast(ctypes.create_string_buffer(blob),
                                ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()

    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError(
            'CryptUnprotectData failed - the token was encrypted by a '
            'different Windows account or on a different machine.'
        )
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _win_protect(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    blob_in = _Blob(len(data),
                    ctypes.cast(ctypes.create_string_buffer(data),
                                ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()

    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError('CryptProtectData failed.')
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ── Public interface ─────────────────────────────────────────────────────────

def read_token(path: str = None) -> str:
    """Return the bearer token in plain text, in memory only."""
    path = path or default_token_path()
    if not os.path.exists(path):
        raise FileNotFoundError(
            f'No stored token at {path}.\n'
            f'  Windows: probe-report-api.ps1 -FromCurlFile <curl.txt>\n'
            f'  Linux:   runner/token_store.py --save (reads stdin)'
        )

    if IS_WINDOWS:
        with open(path, 'r', encoding='ascii') as fh:
            hex_blob = fh.read().strip()
        try:
            blob = bytes.fromhex(hex_blob)
        except ValueError:
            raise ValueError(
                f'{path} is not the expected hex DPAPI blob. Was it written '
                f'by PowerShell ConvertFrom-SecureString?'
            )
        # PowerShell stores SecureString contents as UTF-16LE.
        return _win_unprotect(blob).decode('utf-16-le').strip()

    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read().strip()


def write_token(token: str, path: str = None) -> str:
    """Store the token as securely as the platform allows. Returns the path."""
    token = _clean(token)
    if not token:
        raise ValueError('Refusing to store an empty token.')

    path = path or default_token_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if IS_WINDOWS:
        blob = _win_protect(token.encode('utf-16-le'))
        with open(path, 'w', encoding='ascii') as fh:
            fh.write(blob.hex().upper())
        return path

    # Linux: create with 0600 BEFORE writing, so the secret is never briefly
    # world-readable between creation and chmod.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(token)
    except Exception:
        os.close(fd)
        raise
    os.chmod(path, 0o600)
    return path


def _clean(raw: str) -> str:
    """Strip curl artifacts, an Authorization prefix, and control characters.

    Control characters are the specific failure that produced ".NET: the value
    has invalid control characters" when a token was pasted into a masked
    prompt - a CR sneaks in and cannot legally go in an HTTP header.
    """
    if not raw:
        return ''
    t = raw.replace('^', '').strip().strip('"').strip("'")
    for prefix in ('Authorization:', 'authorization:'):
        if t.startswith(prefix):
            t = t[len(prefix):].strip()
    if t.lower().startswith('bearer '):
        t = t[7:].strip()
    return ''.join(ch for ch in t if 33 <= ord(ch) <= 126)


def fingerprint(token: str) -> str:
    """Safe to log. Never log the token itself."""
    n = len(token or '')
    if n < 12:
        return f'<{n} chars - suspiciously short, the capture probably failed>'
    return f'{token[:4]}...{token[-4:]} ({n} chars)'


def expiry(token: str):
    """(expires_at, seconds_remaining) if the token is a JWT, else (None, None).

    The CMS token is a 90-day JWT. Checking before a run turns "no findings
    appeared for a week" into a clear error - a silently expired token looks
    exactly like a clean fraud report.
    """
    import base64
    import json
    from datetime import datetime, timezone

    parts = (token or '').split('.')
    if len(parts) != 3:
        return None, None
    try:
        seg = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return None, None
    exp = payload.get('exp')
    if not exp:
        return None, None
    dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    return dt, (dt - datetime.now(timezone.utc)).total_seconds()


if __name__ == '__main__':
    # Linux capture path: pipe the token in so it never appears in shell
    # history the way an argument would.
    #   printf '%s' "$TOKEN" | python3 runner/token_store.py --save
    if '--save' in sys.argv:
        written = write_token(sys.stdin.read())
        print(f'Stored: {written}')
        print(f'  {fingerprint(read_token(written))}')
    else:
        tok = read_token()
        print(f'  {fingerprint(tok)}')
        when, left = expiry(tok)
        if when:
            print(f'  expires {when:%Y-%m-%d %H:%M} UTC '
                  f'({left / 86400:.1f} days remaining)')
        else:
            print('  opaque token - expiry not readable')
