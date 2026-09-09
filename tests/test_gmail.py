"""Tests for runner/gmail.py — the OAuth flow and message selection.

Network calls are stubbed. What is actually tested is the part that decides
WHICH email answers the request we just made, and the part where a person
pastes something into a prompt — both of which fail in ways that are hard to
notice: the wrong email produces a correct-looking analysis of the wrong data,
and a mis-parsed paste produces an error days after the real mistake.

Run with plain python (no pytest needed):

    python tests/test_gmail.py
"""

import base64
import hashlib
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

# Before importing config, which snapshots the environment at import time.
os.environ['RUNNER_STATE_DIR'] = tempfile.mkdtemp(prefix='gmail-test-')
os.environ['CUBO_REPORT_SENDER'] = 'reports@example.internal'
os.environ['CUBO_REPORT_SUBJECT'] = ''
os.environ['CUBO_REPORT_LABEL'] = 'cubo-reports'
os.environ['CUBO_CSV_URL_PATTERN'] = (
    r'https://cdn\.example\.internal/reports/csv/[0-9a-fA-F-]{36}\.csv')
os.environ['GMAIL_CLIENT_ID'] = 'test-client.apps.googleusercontent.com'
os.environ['GMAIL_CLIENT_SECRET'] = 'test-secret'

for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config              # noqa: E402
import gmail               # noqa: E402
import state as runner_state   # noqa: E402


LINK = ('https://cdn.example.internal/reports/csv/'
        '8943090c-1111-2222-3333-444455556666.csv')
NOW = datetime(2026, 9, 9, 14, 0, tzinfo=timezone.utc)


def _raw(link=LINK, sender='reports@example.internal'):
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = 'jmelgar@example.com'
    msg['Subject'] = 'Reporte de transacciones'
    msg['Date'] = 'Wed, 09 Sep 2026 14:00:00 +0000'
    msg.set_content(f'Su reporte está listo:\n\n{link}\n')
    return msg.as_bytes()


# ── PKCE and the authorization URL ───────────────────────────────────────────

def test_pkce_challenge_is_the_sha256_of_the_verifier():
    """A desktop client's secret ships inside the app and is not really
    secret, so PKCE is what actually binds the returned code to this
    session. A wrong challenge means Google rejects the exchange."""
    verifier, challenge = gmail._pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('ascii')).digest()).decode().rstrip('=')
    assert challenge == expected
    assert '=' not in challenge, 'padding must be stripped for base64url'


def test_authorization_url_asks_for_offline_access_and_consent():
    """Without access_type=offline there is no refresh token at all, and
    without prompt=consent a re-authorization silently returns none - a
    failure that only appears when the old token finally expires."""
    url = gmail.authorization_url('cid', 'chal', 'st')
    for required in ('access_type=offline', 'prompt=consent',
                     'code_challenge_method=S256', 'response_type=code'):
        assert required in url, required


def test_scope_stays_read_only():
    """The runner must never be able to send, delete or modify mail. Google
    enforces this, but only if the scope stays what it is."""
    assert gmail.SCOPE == 'https://www.googleapis.com/auth/gmail.readonly'
    assert 'gmail.readonly' in gmail.authorization_url('c', 'ch', 's')
    for forbidden in ('gmail.modify', 'gmail.send', 'mail.google.com'):
        assert forbidden not in gmail.SCOPE


def test_refresh_token_is_stored_apart_from_the_cms_token():
    """Two unrelated credentials. Sharing a file would mean re-authorizing
    one silently destroys the other."""
    import token_store
    assert gmail._token_path() != token_store.default_token_path()
    assert 'gmail' in os.path.basename(gmail._token_path())


# ── Pasting the redirect back ────────────────────────────────────────────────

def test_full_redirect_url_is_accepted():
    pasted = ('http://localhost:8080/?state=abc123&code=4/0AY0e-g7xyz_ABC-def'
              '&scope=https://www.googleapis.com/auth/gmail.readonly')
    assert gmail.code_from_redirect(pasted, expect_state='abc123') == \
        '4/0AY0e-g7xyz_ABC-def'


def test_bare_code_is_accepted():
    """People paste the code alone about as often as the whole URL."""
    assert gmail.code_from_redirect('4/0AY0e-g7xyz_ABCdefGHIjklMNO') == \
        '4/0AY0e-g7xyz_ABCdefGHIjklMNO'


def test_state_mismatch_is_refused():
    """Otherwise a stale link from an abandoned attempt quietly authorizes
    against a different session's PKCE verifier and fails confusingly."""
    pasted = 'http://localhost:8080/?state=WRONG&code=4/0AY0e-g7xyz_ABC'
    try:
        gmail.code_from_redirect(pasted, expect_state='abc123')
    except gmail.GmailError as e:
        assert 'state' in str(e)
    else:
        raise AssertionError('a mismatched state must be refused')


def test_access_denied_is_explained():
    try:
        gmail.code_from_redirect('http://localhost:8080/?error=access_denied')
    except gmail.GmailError as e:
        assert 'access_denied' in str(e)
    else:
        raise AssertionError('an error redirect must be refused')


def test_url_without_a_code_is_explained():
    try:
        gmail.code_from_redirect('http://localhost:8080/')
    except gmail.GmailError as e:
        assert 'code=' in str(e)
    else:
        raise AssertionError('a URL with no code must be refused')


def test_empty_and_garbage_are_refused():
    for bad in ('', '   ', 'yes', 'ok done'):
        try:
            gmail.code_from_redirect(bad)
        except gmail.GmailError:
            pass
        else:
            raise AssertionError(f'accepted {bad!r}')


# ── Choosing the right message ───────────────────────────────────────────────

class _Inbox:
    """Stands in for Gmail. Messages are (id, received_at, raw)."""

    def __init__(self, messages):
        self.messages = messages
        self.queries = []

    def install(self):
        self._search, self._fetch = gmail.search, gmail.fetch_raw
        gmail.search = self._do_search
        gmail.fetch_raw = self._do_fetch

    def remove(self):
        gmail.search, gmail.fetch_raw = self._search, self._fetch

    def _do_search(self, query, max_results=10):
        self.queries.append(query)
        return [m[0] for m in self.messages][:max_results]

    def _do_fetch(self, message_id):
        for mid, received, raw in self.messages:
            if mid == message_id:
                return raw, received
        raise AssertionError(f'fetched unknown message {message_id}')


def _with_inbox(messages, fn):
    inbox = _Inbox(messages)
    inbox.install()
    try:
        return fn(inbox)
    finally:
        inbox.remove()


def _clear_state():
    path = config.state_path()
    if os.path.exists(path):
        os.remove(path)


def test_newest_report_wins():
    """A retry can leave two report mails sitting there. The newest is the
    one that answers the request we just made."""
    _clear_state()
    old_link = LINK.replace('8943090c', 'aaaaaaaa')
    messages = [
        ('old', NOW - timedelta(hours=3), _raw(old_link)),
        ('new', NOW - timedelta(minutes=2), _raw(LINK)),
    ]
    found = _with_inbox(messages, lambda _: gmail.find_report())
    assert found is not None
    assert found[0] == 'new' and found[1] == LINK


def test_mail_older_than_the_request_is_ignored():
    """The central attribution rule. A report queued before we asked belongs
    to an earlier cycle; consuming it would analyse the wrong window and look
    entirely successful doing it."""
    _clear_state()
    messages = [('stale', NOW - timedelta(hours=6), _raw(LINK))]
    found = _with_inbox(
        messages, lambda _: gmail.find_report(after=NOW - timedelta(minutes=5)))
    assert found is None


def test_already_processed_mail_is_skipped():
    """A delayed report must not be consumed twice."""
    _clear_state()
    st = runner_state.mark_processed('seen', runner_state.load())
    runner_state.save(st)

    messages = [('seen', NOW, _raw(LINK))]
    assert _with_inbox(messages, lambda _: gmail.find_report()) is None
    # ...but the same message is fair game when we explicitly ask for it.
    found = _with_inbox(
        messages, lambda _: gmail.find_report(skip_processed=False))
    assert found is not None and found[0] == 'seen'


def test_mail_from_the_wrong_sender_is_not_used():
    _clear_state()
    messages = [('spoof', NOW, _raw(LINK, sender='attacker@evil.com'))]
    assert _with_inbox(messages, lambda _: gmail.find_report()) is None


def test_link_to_another_host_is_not_used():
    _clear_state()
    evil = ('https://evil.example.com/reports/csv/'
            '8943090c-1111-2222-3333-444455556666.csv')
    messages = [('bad', NOW, _raw(evil))]
    assert _with_inbox(messages, lambda _: gmail.find_report()) is None


def test_search_is_scoped_to_sender_and_label():
    """Polling a small labelled set rather than the whole mailbox."""
    _clear_state()
    messages = [('m', NOW, _raw(LINK))]

    def check(inbox):
        gmail.find_report()
        return inbox.queries

    queries = _with_inbox(messages, check)
    assert queries and 'from:reports@example.internal' in queries[0]
    assert 'label:cubo-reports' in queries[0]


# ── Giving up ────────────────────────────────────────────────────────────────

def test_wait_returns_none_instead_of_retriggering():
    """Ending the job is the correct behaviour on timeout. Re-firing inside
    the same cycle would queue a duplicate report and a duplicate email."""
    _clear_state()
    result = _with_inbox([], lambda _: gmail.wait_for_report(
        NOW, timeout=0, poll=1))
    assert result is None


# ── Error messages ───────────────────────────────────────────────────────────

def test_invalid_grant_explains_the_seven_day_trap():
    """The single most likely way this breaks: the OAuth app is left in
    'Testing', where Google expires refresh tokens weekly."""
    import io
    import urllib.error

    body = io.BytesIO(b'{"error":"invalid_grant"}')
    err = urllib.error.HTTPError('u', 400, 'Bad Request', {}, body)
    message = gmail._explain(err)
    assert '7 días' in message and 'production' in message.lower()
    assert '--authorize' in message


def test_gmail_api_disabled_is_explained():
    import io
    import urllib.error

    body = io.BytesIO(b'{"error":{"message":"Gmail API has not been used '
                      b'in project 123 before or it is disabled"}}')
    err = urllib.error.HTTPError('u', 403, 'Forbidden', {}, body)
    assert 'Habilitar' in gmail._explain(err)


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
