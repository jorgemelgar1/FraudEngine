"""Tests for runner/report_mail.py and runner/state.py.

These are the two pieces that are the same whether the mailbox is read over
IMAP or through the Gmail API, so they are worth getting right before either
transport exists.

The parsing tests are mostly about the ways a real mail client mangles a long
URL - quoted-printable soft breaks, HTML entities, click-tracking wrappers -
because each of those produces a link that looks fine to a human and does not
match a pattern.

Run with plain python (no pytest needed):

    python tests/test_report_mail.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

# Set before importing config: it snapshots the environment at import time,
# and existing variables win over runner/.env - so this is deterministic even
# on a machine that has a real .env.
_STATE_DIR = tempfile.mkdtemp(prefix='runner-state-test-')
os.environ['RUNNER_STATE_DIR'] = _STATE_DIR
os.environ['CUBO_REPORT_SENDER'] = 'reports@example.internal'
os.environ['CUBO_REPORT_SUBJECT'] = ''
os.environ['CUBO_REPORT_LABEL'] = 'cubo-reports'
os.environ['CUBO_CSV_URL_PATTERN'] = (
    r'https://cdn\.example\.internal/reports/csv/[0-9a-fA-F-]{36}\.csv')

for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config          # noqa: E402
import report_mail     # noqa: E402
import state           # noqa: E402


LINK = ('https://cdn.example.internal/reports/csv/'
        '8943090c-1111-2222-3333-444455556666.csv')
SENDER = 'reports@example.internal'


def _mail(plain=None, html_body=None, sender=SENDER,
          subject='Reporte de transacciones', cte=None):
    msg = EmailMessage()
    msg['From'] = f'Cubo Reports <{sender}>'
    msg['To'] = 'jmelgar@example.com'
    msg['Subject'] = subject
    msg['Date'] = 'Tue, 09 Sep 2026 14:03:11 -0600'
    if plain is not None:
        msg.set_content(plain, cte=cte) if cte else msg.set_content(plain)
    if html_body is not None:
        if plain is None:
            msg.set_content('')
        msg.add_alternative(html_body, subtype='html')
    return msg.as_bytes()


# ── The happy path ───────────────────────────────────────────────────────────

def test_plain_text_link_is_found():
    url, why = report_mail.link_from_raw(
        _mail(plain=f'Su reporte está listo:\n\n{LINK}\n\nGracias.'))
    assert url == LINK
    assert LINK not in why, 'the link must never reach a log line'


def test_quoted_printable_soft_break_is_rejoined():
    """A report link is long enough that quoted-printable splits it across
    lines with a trailing '='. Read naively that is two broken halves, and
    the runner would report 'no link' on a perfectly good email."""
    body = f'Su reporte:\n{LINK}\n' + ('relleno ' * 40)
    url, _ = report_mail.link_from_raw(_mail(plain=body, cte='quoted-printable'))
    assert url == LINK


def test_base64_body_is_decoded():
    url, _ = report_mail.link_from_raw(
        _mail(plain=f'Reporte: {LINK}', cte='base64'))
    assert url == LINK


def test_html_entities_are_unescaped():
    entity_link = LINK.replace('/', '&#47;', 1)
    url, _ = report_mail.link_from_raw(
        _mail(html_body=f'<p>Reporte: <a href="{entity_link}">Descargar</a></p>'))
    assert url == LINK


def test_plain_part_wins_over_the_tracking_wrapper():
    """The HTML part wraps links in click tracking. Preferring plain text
    avoids depending on that service and avoids registering a phantom click
    on a link that is itself a credential."""
    tracked = ('https://links.example.internal/ls/click?upn=' + 'A' * 40)
    url, _ = report_mail.link_from_raw(_mail(
        plain=f'Reporte: {LINK}',
        html_body=f'<a href="{tracked}">Descargar</a>'))
    assert url == LINK


def test_html_only_mail_still_works():
    url, _ = report_mail.link_from_raw(
        _mail(html_body=f'<a href="{LINK}">Descargar</a>'))
    assert url == LINK


# ── Refusals ─────────────────────────────────────────────────────────────────

def test_wrong_sender_is_not_a_report():
    url, why = report_mail.link_from_raw(
        _mail(plain=f'Reporte: {LINK}', sender='someone@elsewhere.com'))
    assert url is None and 'no es un reporte' in why


def test_link_to_another_host_is_ignored():
    """The pattern pins the host. A spoofed mail that reaches the label must
    not turn the runner into a fetch-anything tool."""
    evil = ('https://evil.example.com/reports/csv/'
            '8943090c-1111-2222-3333-444455556666.csv')
    url, why = report_mail.link_from_raw(_mail(plain=f'Reporte: {evil}'))
    assert url is None and 'no trae un enlace' in why


def test_report_without_a_link_is_reported_as_such():
    url, why = report_mail.link_from_raw(
        _mail(plain='Su reporte falló, intente de nuevo.'))
    assert url is None and 'no trae un enlace' in why


def test_attachment_is_not_treated_as_the_body():
    msg = EmailMessage()
    msg['From'] = SENDER
    msg['Subject'] = 'Reporte'
    msg['Date'] = 'Tue, 09 Sep 2026 14:03:11 -0600'
    msg.set_content('Sin enlace en el cuerpo.')
    msg.add_attachment(f'Reporte anterior: {LINK}'.encode(),
                       maintype='text', subtype='plain',
                       filename='anterior.txt')
    url, _ = report_mail.link_from_raw(msg.as_bytes())
    assert url is None, 'a forwarded or attached old report is not this report'


def test_missing_pattern_refuses_rather_than_guesses():
    original = config.CSV_URL_PATTERN
    config.CSV_URL_PATTERN = ''
    try:
        try:
            report_mail.find_csv_url(report_mail.parse(_mail(plain=LINK)))
        except report_mail.MailError as e:
            assert 'CUBO_CSV_URL_PATTERN' in str(e)
        else:
            raise AssertionError('should have refused with no pattern set')
    finally:
        config.CSV_URL_PATTERN = original


def test_missing_sender_refuses_rather_than_guesses():
    try:
        report_mail.is_report(report_mail.parse(_mail(plain=LINK)), sender='')
    except report_mail.MailError as e:
        assert 'CUBO_REPORT_SENDER' in str(e)
    else:
        raise AssertionError('should have refused with no sender configured')


# ── Subject matching ─────────────────────────────────────────────────────────

def test_subject_is_matched_loosely_when_configured():
    raw = _mail(plain=f'Reporte: {LINK}', subject='Reporte de Transaciones')
    msg = report_mail.parse(raw)
    assert report_mail.is_report(msg, subject='reporte de transaciones')
    assert not report_mail.is_report(msg, subject='factura mensual')


# ── Metadata ─────────────────────────────────────────────────────────────────

def test_sent_at_is_parsed_as_utc():
    when = report_mail.sent_at(report_mail.parse(_mail(plain=LINK)))
    assert when is not None and when.tzinfo is not None
    assert when.astimezone(timezone.utc).hour == 20  # 14:03 -0600


def test_newest_first_puts_undated_last():
    now = datetime.now(timezone.utc)
    items = [('a', now - timedelta(hours=2), b''),
             ('b', None, b''),
             ('c', now, b'')]
    assert [i[0] for i in report_mail.newest_first(items)] == ['c', 'a', 'b']


def test_search_query_includes_sender_and_label():
    q = report_mail.search_query(after=datetime(2026, 9, 8, tzinfo=timezone.utc))
    assert f'from:{SENDER}' in q and 'label:cubo-reports' in q
    assert 'after:2026/09/08' in q


# ── State ────────────────────────────────────────────────────────────────────

def _fresh_state():
    path = config.state_path()
    if os.path.exists(path):
        os.remove(path)
    return state.load()


def test_state_roundtrip():
    st = _fresh_state()
    st = state.mark_processed('msg-1', st)
    st = state.record_success('GT', datetime(2026, 9, 9, 12, tzinfo=timezone.utc), st)
    state.save(st)

    reloaded = state.load()
    assert state.is_processed('msg-1', reloaded)
    assert not state.is_processed('msg-2', reloaded)
    assert state.last_success('GT', reloaded).hour == 12


def test_marking_twice_does_not_duplicate():
    st = _fresh_state()
    st = state.mark_processed('msg-1', st)
    st = state.mark_processed('msg-1', st)
    assert st['processed_ids'].count('msg-1') == 1


def test_processed_ids_are_trimmed():
    """Otherwise the file grows without limit for the life of the machine."""
    st = _fresh_state()
    for i in range(state.MAX_PROCESSED_IDS + 50):
        st = state.mark_processed(f'msg-{i}', st)
    state.save(st)

    reloaded = state.load()
    assert len(reloaded['processed_ids']) == state.MAX_PROCESSED_IDS
    # The oldest go, the newest stay.
    assert not state.is_processed('msg-0', reloaded)
    assert state.is_processed(
        f'msg-{state.MAX_PROCESSED_IDS + 49}', reloaded)


def test_corrupt_state_file_does_not_stop_a_run():
    """State is bookkeeping. Refusing to run because it is damaged would turn
    a trivial problem into an outage; the cost of losing it is one possible
    duplicate report."""
    path = config.state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('{ this is not json')
    loaded = state.load()
    assert loaded['processed_ids'] == [] and loaded['last_success'] == {}


def test_a_country_that_never_ran_is_stale():
    """A runner installed last week where one country silently never worked
    looks exactly like a quiet week for that country."""
    st = _fresh_state()
    st = state.record_success('SV', datetime.now(timezone.utc), st)
    stale = state.stale_countries(state=st)
    codes = [c for c, _ in stale]
    assert 'SV' not in codes
    assert 'PA' in codes and 'GT' in codes


def test_an_old_success_goes_stale():
    now = datetime.now(timezone.utc)
    st = _fresh_state()
    for code in config.ROTATION:
        st = state.record_success(code, now, st)
    st = state.record_success('GT', now - timedelta(hours=20), st)

    codes = [c for c, _ in state.stale_countries(now=now, state=st)]
    assert codes == ['GT']


def test_describe_never_raises_on_empty_state():
    text = state.describe(_fresh_state())
    assert 'nunca' in text


# ── Runner ───────────────────────────────────────────────────────────────────

def _run_all():
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith('test_') and callable(o)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f'FAIL {name}: {e}')
        except Exception as e:                              # noqa: BLE001
            failed += 1
            print(f'ERROR {name}: {type(e).__name__}: {e}')
    print(f'{passed}/{len(tests)} passed'
          + (f', {failed} failed' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(_run_all())
