"""One full unattended cycle: ask for a report, wait for it, analyze it.

    python3 runner/cycle.py                 # country chosen by the clock
    python3 runner/cycle.py --country GT    # a specific one
    python3 runner/cycle.py --dry-run       # ask for nothing, write nothing
    python3 runner/cycle.py --health        # is the runner actually alive?

This is what cron calls. Everything after the download is runner/run.py's
pipeline, reused rather than copied.

    IDLE
      -> TRIGGERED      GET the report endpoint. 200 with an empty body; the
                        email is the only signal it worked.
      -> AWAITING_MAIL  poll the Gmail label for a message that arrived AFTER
                        we asked. 15 minutes, then give up.
      -> DOWNLOADED     the CDN link from the message body.
      -> ANALYZED       country read from the CSV, never from what we asked for.
      -> SYNCED         de-duplicated, then written.
      -> CLEANED        the CSV is deleted. Happens even if a step above threw.

**Giving up is a correct ending.** If the mail never arrives, the job stops and
that country waits for its next slot three hours later. Re-triggering inside
the same cycle would queue a duplicate report and a duplicate email, and
because every report mail is identical, there would then be no way to tell
which one answered which request.

Only ever one report in flight. That is what makes matching a message to a
request unambiguous, and it is a property of the schedule, not of this code -
so the schedule is one country per hour, never a burst.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config          # noqa: E402
import cubo_api        # noqa: E402
import run as runner   # noqa: E402
import state as runner_state   # noqa: E402
import token_store     # noqa: E402

log = runner.log


# A token with less than this left is worth shouting about while there is
# still time to replace it calmly, rather than discovering it expired during
# a weekend.
TOKEN_WARN_DAYS = 7


def check_token() -> str:
    """Return the CMS token, refusing to start if it is unusable.

    An expired token produces an empty report queue and no findings - which
    is indistinguishable from a genuinely quiet day. Checking here converts a
    silent, weeks-long failure into a message on the first run.
    """
    try:
        token = token_store.read_token()
    except FileNotFoundError as e:
        raise RuntimeError(
            f'{e}\nSin token del CMS no se puede pedir un reporte. '
            f'Usa runner/run.py --from-email mientras tanto.') from None

    expires_at, seconds_left = token_store.expiry(token)
    if expires_at is None:
        log(f'Token del CMS: {token_store.fingerprint(token)} '
            f'(no se puede leer la caducidad)')
        return token

    days = seconds_left / 86400
    if seconds_left <= 0:
        raise RuntimeError(
            f'El token del CMS caducó el {expires_at:%Y-%m-%d}. '
            f'Captúralo de nuevo desde el navegador; hasta entonces el runner '
            f'no puede pedir reportes.')
    if days < TOKEN_WARN_DAYS:
        log(f'AVISO: el token del CMS caduca en {days:.1f} días '
            f'({expires_at:%Y-%m-%d}). Renuévalo pronto.')
    else:
        log(f'Token del CMS válido {days:.0f} días más.')
    return token


def choose_country(explicit: str = None, now: datetime = None) -> str:
    """Which country this slot belongs to.

    Derived from the clock rather than stored, so the rotation is stateless
    and self-correcting: a missed run does not shift the schedule, that
    country simply picks up at its next slot.
    """
    if explicit:
        config.country_by_code(explicit)      # raises on an unknown code
        return explicit.upper()
    now = now or datetime.now()
    return config.country_for_hour(now.hour)


def health(now: datetime = None) -> int:
    """Report which countries have gone quiet. Exit 1 if any have.

    Overlapping windows mean no single miss loses data, so nothing here is an
    emergency - but a country that has not completed in half a day is not
    working, and nothing else would ever say so.
    """
    now = now or datetime.now(timezone.utc)
    print(runner_state.describe())
    stale = runner_state.stale_countries(now=now)
    if not stale:
        print('\nTodos los países han corrido en las últimas '
              f'{int(runner_state.STALE_AFTER.total_seconds() // 3600)} horas.')
        return 0
    print()
    for code, when in stale:
        detail = 'nunca ha corrido' if when is None else (
            f'último éxito hace {(now - when).total_seconds() / 3600:.1f} h')
        print(f'ATRASADO: {code} - {detail}')
    return 1


def show_request(country: str = None, lookback_days: int = None) -> int:
    """Print the exact request the runner would send, token redacted.

    A 403 from this API is a header problem, and the only way to settle which
    header is to compare what the runner sends against what the browser sent.
    Guessing costs a round trip each time; this makes it a diff.
    """
    country = choose_country(country)
    meta = config.country_by_code(country)
    date_from, date_to = cubo_api.date_window(lookback_days)
    url = cubo_api.report_url(meta['id'], date_from, date_to)

    try:
        token = token_store.read_token()
    except FileNotFoundError:
        token = ''
        print('AVISO: no hay token guardado; se muestra sin Authorization.')

    print()
    print(f'GET {url}')
    print()
    print('Cabeceras:')
    for name, value in sorted(cubo_api._headers(token).items()):
        if name == 'Authorization':
            length = len(token)
            value = f'Bearer <{length} caracteres, oculto>'
        print(f'  {name}: {value}')
    print()
    print('Compara esto con el cURL del navegador. Si el navegador manda una')
    print('cabecera que aquí falta, esa es la que el API está revisando:')
    print('  python3 runner/import_curl.py --show-headers')
    return 0


def run_cycle(country: str, dry_run: bool = False,
              lookback_days: int = None) -> int:
    import gmail  # noqa: PLC0415  (importing costs nothing until this mode)

    meta = config.country_by_code(country)
    date_from, date_to = cubo_api.date_window(lookback_days)
    log(f'País {country} ({meta["name"]}), ventana {date_from} → {date_to}')

    if dry_run:
        log('DRY RUN - no se pide ningún reporte y no se escribe nada.')
        log('  (pedir un reporte no se puede simular: genera un correo real)')
        return 0

    token = check_token()

    # Everything from here is timed against `requested_at`. A report that
    # arrived BEFORE we asked belongs to an earlier cycle; consuming it would
    # analyze the wrong window and look entirely successful doing it.
    requested_at = datetime.now(timezone.utc)
    result = cubo_api.trigger_report(token, meta['id'], date_from, date_to)
    log(f'Reporte solicitado (HTTP {result["status"]}, '
        f'{result["body_bytes"]} bytes de respuesta). Esperando el correo...')

    def waiting(seconds_left):
        log(f'  ...sin correo todavía, quedan {seconds_left // 60} min')

    found = gmail.wait_for_report(requested_at, on_wait=waiting)
    if not found:
        minutes = config.EMAIL_TIMEOUT_SECONDS // 60
        log(f'El correo no llegó en {minutes} min. Se termina el ciclo; '
            f'{country} lo reintentará en su próximo turno.')
        # Not an error exit: this is the designed behaviour, and a cron job
        # that mails you on every slow report is a cron job you stop reading.
        return 0

    message_id, url, received = found
    when = f'{received:%H:%M} UTC' if received else 'sin fecha'
    log(f'Correo recibido ({when}), mensaje {message_id}')

    source = runner.Source(runner._download(url), delete_after=True,
                           message_id=message_id)
    runner.process(source, dry_run=False, run_source='auto')
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='runner/cycle.py',
        description='One scheduled cycle: request a report, wait, analyze.')
    parser.add_argument('--country', help='SV, PA or GT (default: by the hour)')
    parser.add_argument('--dry-run', action='store_true',
                        help='show what would happen; request nothing')
    parser.add_argument('--health', action='store_true',
                        help='report countries that have gone quiet, then exit')
    parser.add_argument('--show-request', action='store_true',
                        help='print the exact request that would be sent')
    parser.add_argument('--lookback-days', type=int, default=None,
                        help='override the window (default: today + yesterday)')
    args = parser.parse_args(argv)

    if args.health:
        return health()

    if args.show_request:
        # Only the CMS block is needed to build the request, and demanding
        # Gmail or Supabase here would block the very diagnostic someone
        # reaches for when the CMS call is what is broken.
        config.validate('cms')
        return show_request(args.country, args.lookback_days)

    try:
        config.validate('cms', 'mail', 'url', 'supabase', 'gmail')
        country = choose_country(args.country)
        return run_cycle(country, dry_run=args.dry_run,
                         lookback_days=args.lookback_days)
    except Exception as e:                                  # noqa: BLE001
        return runner.report_failure(e)


if __name__ == '__main__':
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError):
            pass
    sys.exit(main())
