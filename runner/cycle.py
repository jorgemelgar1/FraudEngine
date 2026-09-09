"""One full unattended cycle: ask for a report, wait for it, analyze it.

    python3 runner/cycle.py                 # country chosen by the clock
    python3 runner/cycle.py --country GT    # a specific one
    python3 runner/cycle.py --dry-run       # ask for nothing, write nothing
    python3 runner/cycle.py --health        # is the runner actually alive?

This is what cron calls. Everything after the download is runner/run.py's
pipeline, reused rather than copied.

    IDLE
      -> RECORDED       a runner_cycles row opens as 'running' (migration
                        0012). Written BEFORE anything is attempted, so a
                        cycle that dies mid-flight leaves a stuck row - which
                        is a different diagnosis from no row at all, and the
                        app has no other way to tell them apart.
      -> TRIGGERED      GET the report endpoint. 200 with an empty body; the
                        email is the only signal it worked.
      -> AWAITING_MAIL  poll the Gmail label for a message that arrived AFTER
                        we asked. 15 minutes, then give up.
      -> DOWNLOADED     the CDN link from the message body.
      -> ANALYZED       country read from the CSV, never from what we asked for.
      -> SYNCED         de-duplicated, then written.
      -> CLEANED        the CSV is deleted. Happens even if a step above threw.
      -> CLOSED         the cycle row is stamped with its outcome. EVERY
                        ending goes through here, including the ones that are
                        not errors - a silently broken runner and a quiet
                        fraud week produce identical output, and this is what
                        makes them tell apart.

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
import socket
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config          # noqa: E402
import cubo_api        # noqa: E402
import run as runner   # noqa: E402
import slack           # noqa: E402
import state as runner_state   # noqa: E402
import supabase_io     # noqa: E402
import token_store     # noqa: E402

log = runner.log


# A token with less than this left is worth shouting about while there is
# still time to replace it calmly, rather than discovering it expired during
# a weekend.
TOKEN_WARN_DAYS = 7


class NoReportEmail(RuntimeError):
    """The report never arrived inside the timeout.

    This exists so that "gave up waiting" can travel up to main() as its own
    thing. It is NOT a failure - it is the designed ending, and main() turns
    it into exit 0 so cron stays quiet. But it is also not a success, and
    recording it as one would put a green tick on the dashboard for a slot
    that produced no analysis at all.

    Raised rather than returned because every other ending of run_cycle is
    an exception too, and one function that sometimes signals by return value
    and sometimes by raising is how a caller comes to handle only half of
    them.
    """


def check_token() -> str:
    """Return the CMS token, refusing to start if it is unusable.

    An expired token produces an empty report queue and no findings - which
    is indistinguishable from a genuinely quiet day. Checking here converts a
    silent, weeks-long failure into a message on the first run.
    """
    try:
        token = token_store.read_token()
    except FileNotFoundError as e:
        raise token_store.TokenError(
            f'{e}\nSin token del CMS no se puede pedir un reporte. '
            f'Usa runner/run.py --from-email mientras tanto.') from None

    expires_at, seconds_left = token_store.expiry(token)
    if expires_at is None:
        log(f'Token del CMS: {token_store.fingerprint(token)} '
            f'(no se puede leer la caducidad)')
        return token

    days = seconds_left / 86400
    if seconds_left <= 0:
        raise token_store.TokenError(
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


# Only the cycle that runs at this local hour reports a soon-to-expire token
# to Slack. The check itself happens every cycle, but the runner wakes 24
# times a day and a warning repeated 24 times a day for a week is not a
# warning, it is wallpaper. A fixed hour gives exactly one message a day and
# needs nothing stored to remember whether it already sent one.
TOKEN_ALERT_HOUR = 9

# And the review-queue nudge, an hour later so the two never land together as
# a wall of bot messages at the same minute.
QUEUE_ALERT_HOUR = 10


def alert_failure_streak(country: str, outcome: str):
    """Tell Slack when a country has stopped working, once.

    Fires on the cycle where the streak EQUALS the threshold, not where it
    exceeds it, so a country that stays broken produces one message rather
    than one an hour. Recovering resets the count, which re-arms it.

    'no_email' counts toward the streak even though a single one is normal:
    three cycles in a row with no report arriving means the reports are not
    coming, which is a real problem wearing the costume of a designed
    behaviour.
    """
    if outcome == 'ok' or not config.slack_enabled(country):
        return

    row = next((h for h in supabase_io.runner_health()
                if h.get('country_code') == country), None)
    if not row:
        return

    streak = row.get('consecutive_failures') or 0
    if streak != config.SLACK_FAILURE_STREAK:
        return

    name = config.country_by_code(country)['name']
    slack.send_health(
        f'{name} lleva {streak} ciclos sin completarse',
        detail=row.get('last_detail') or f'Último resultado: {outcome}',
        fix='Abre la pestaña Runner en la app para ver los ciclos y el '
            'comando que corresponde a este error.',
        level='bad', country_code=country)


def alert_token_expiry(token: str, now: datetime = None):
    """One message a day while the CMS token is close to expiring."""
    now = now or datetime.now()
    if now.hour != TOKEN_ALERT_HOUR or not config.slack_enabled():
        return

    expires_at, seconds_left = token_store.expiry(token)
    if expires_at is None or seconds_left is None:
        return
    days = seconds_left / 86400
    if days >= TOKEN_WARN_DAYS:
        return

    slack.send_health(
        f'el token del CMS vence en {days:.0f} día(s)',
        detail=f'Caduca el {expires_at:%Y-%m-%d}. Sin token, el runner no '
               f'puede pedir reportes y dejará de encontrar fraude en '
               f'silencio.',
        fix='Captura de nuevo el cURL del navegador y pásalo por '
            'python3 runner/import_curl.py',
        level='warn')


def alert_pending_queue(now: datetime = None):
    """One reminder a day about the review queue.

    Same fixed-hour trick as the token warning, for the same reason: the runner
    wakes 24 times a day, and a nudge repeated 24 times a day is not a nudge.
    Sending it from the hourly job rather than adding a second cron line keeps
    the schedule to one entry someone has to understand.
    """
    now = now or datetime.now()
    if now.hour != QUEUE_ALERT_HOUR or not config.slack_enabled():
        return

    pending, oldest = supabase_io.pending_summary()
    if not pending:
        return

    days = None
    if oldest:
        try:
            when = datetime.fromisoformat(str(oldest).replace('Z', '+00:00'))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - when).total_seconds() / 86400
        except (TypeError, ValueError):
            days = None

    slack.send_queue_reminder(pending, days)


def token_expiry_iso():
    """The CMS token's expiry as an ISO string, or None if unreadable.

    Deliberately silent about every failure: this is only a field on the
    cycle row, put there so the token countdown can appear in the app instead
    of living solely in a log file on the Pi. check_token() is what refuses
    to run, loudly and with a message.
    """
    try:
        token = token_store.read_token()
    except Exception:                                       # noqa: BLE001
        return None
    expires_at, _ = token_store.expiry(token)
    return expires_at.isoformat() if expires_at else None


def run_cycle(country: str, dry_run: bool = False,
              lookback_days: int = None, cycle_id: str = None,
              window=None) -> int:
    import gmail  # noqa: PLC0415  (importing costs nothing until this mode)

    meta = config.country_by_code(country)
    # main() computes the window before opening the cycle row and passes it
    # in, so the dates STORED are provably the dates REQUESTED. Computing it
    # twice would let a cycle that starts at 23:59:59 record one window and
    # ask for another - and the whole reason the window is stored is that a
    # bug in exactly these dates once shipped unnoticed.
    date_from, date_to = window or cubo_api.date_window(lookback_days)
    log(f'País {country} ({meta["name"]}), ventana {date_from} → {date_to}')

    if dry_run:
        log('DRY RUN - no se pide ningún reporte y no se escribe nada.')
        log('  (pedir un reporte no se puede simular: genera un correo real)')
        return 0

    token = check_token()
    alert_token_expiry(token)
    alert_pending_queue()

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
        # Not an error exit - main() turns this into exit 0, because this is
        # the designed behaviour and a cron job that mails you on every slow
        # report is a cron job you stop reading. It is raised rather than
        # returned so that the cycle row records 'no_email' instead of a
        # green tick for a slot that produced no analysis.
        raise NoReportEmail(
            f'El correo no llegó en {minutes} min. Se termina el ciclo; '
            f'{country} lo reintentará en su próximo turno.')

    message_id, url, received = found
    when = f'{received:%H:%M} UTC' if received else 'sin fecha'
    log(f'Correo recibido ({when}), mensaje {message_id}')

    source = runner.Source(runner._download(url), delete_after=True,
                           message_id=message_id)
    runner.process(source, dry_run=False, run_source='auto',
                   cycle_id=cycle_id)
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
    parser.add_argument('--slack-test', action='store_true',
                        help='send one test message to Slack, then exit')
    args = parser.parse_args(argv)

    if args.health:
        return health()

    if args.slack_test:
        if not config.slack_enabled(args.country):
            print('Slack no está configurado. Añade SLACK_WEBHOOK_URL a '
                  'runner/.env.\nSin él, el runner funciona igual pero en '
                  'silencio.')
            return 1
        ok = slack.send_test(args.country)
        print('Mensaje enviado.' if ok
              else 'No se pudo enviar; revisa el detalle de arriba.')
        return 0 if ok else 1

    if args.show_request:
        # Only the CMS block is needed to build the request, and demanding
        # Gmail or Supabase here would block the very diagnostic someone
        # reaches for when the CMS call is what is broken.
        config.validate('cms')
        return show_request(args.country, args.lookback_days)

    # A dry run writes nothing anywhere, and that includes no cycle row:
    # recording "the runner ran" for a slot that deliberately did nothing
    # would put a success on the dashboard that never happened.
    if args.dry_run:
        try:
            config.validate('cms', 'mail', 'url', 'supabase', 'gmail')
            return run_cycle(choose_country(args.country), dry_run=True,
                             lookback_days=args.lookback_days)
        except Exception as e:                              # noqa: BLE001
            return runner.report_failure(e)

    # Both initialised before the try, because the handlers below read them
    # and either assignment can be skipped by an exception - a NameError in
    # an error handler would replace the real failure with a fake one.
    cycle_id = None
    country = None
    try:
        # Supabase is validated first and on its own, because it is the
        # minimum needed to record anything at all. Validating everything up
        # front would mean a missing CUBO_ORIGIN produced no cycle row - so
        # the easiest failure to fix would also be the only one invisible in
        # the app, which is backwards.
        config.validate('supabase')
        country = choose_country(args.country)
        date_from, date_to = cubo_api.date_window(args.lookback_days)

        cycle_id = supabase_io.cycle_start(
            country,
            window_start=date_from, window_end=date_to,
            token_expires_at=token_expiry_iso(),
            host=socket.gethostname())

        config.validate('cms', 'mail', 'url', 'gmail')
        code = run_cycle(country, lookback_days=args.lookback_days,
                         cycle_id=cycle_id, window=(date_from, date_to))
        supabase_io.cycle_finish(cycle_id, 'ok' if code == 0 else 'unexpected')
        return code

    except NoReportEmail as e:
        supabase_io.cycle_finish(cycle_id, 'no_email', str(e))
        log(str(e))
        # A single slow report is normal; three in a row is not, and only the
        # streak knows the difference.
        alert_failure_streak(country, 'no_email')
        return 0

    except Exception as e:                                  # noqa: BLE001
        outcome, _, detail = runner.classify_failure(e)
        supabase_io.cycle_finish(cycle_id, outcome, detail)
        if country:
            alert_failure_streak(country, outcome)
        return runner.report_failure(e)


if __name__ == '__main__':
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError):
            pass
    sys.exit(main())
