"""Find the CSV link inside a report email.

Takes a raw RFC822 message and returns the download link, or None. That is the
whole job, and it is deliberately independent of how the message was fetched:
IMAP hands you RFC822 directly, and the Gmail API will too if you ask for
`format=raw`. Keeping the parsing here means the transport can change without
touching the part that is easy to get subtly wrong.

Every report mail is identical - same sender, same subject, no country and no
date range anywhere in it. They even thread together in Gmail. So this module
can tell a report from other mail, but it cannot tell WHICH report: attribution
comes from the `country_name` column inside the CSV, never from the message.

**The link it returns is a credential.** It is unauthenticated - possession of
the URL is authorization to download a full transaction export. It is never
logged here, never put in an exception message, and never written to state.
"""

import email
import email.policy
import email.utils
import html
import re
from datetime import datetime, timezone

import config
import cubo_api


class MailError(RuntimeError):
    """A parsing failure whose message is safe to print."""


def parse(raw) -> email.message.EmailMessage:
    """Parse RFC822 bytes into a message.

    `policy.default` matters: it decodes quoted-printable and base64 parts for
    us. Report links are long enough that quoted-printable splits them across
    lines with a soft `=` break, and a naive reader sees two broken halves.
    """
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='replace')
    try:
        return email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as e:
        raise MailError(f'Could not parse the message ({type(e).__name__}).') from None


def sender_of(msg) -> str:
    """The bare address from the From header, lowercased."""
    _name, addr = email.utils.parseaddr(str(msg.get('From', '')))
    return addr.strip().lower()


def subject_of(msg) -> str:
    return str(msg.get('Subject', '') or '').strip()


def sent_at(msg):
    """When the sender says it was sent, as an aware UTC datetime, or None.

    Only a fallback. Prefer the server's own arrival time (IMAP INTERNALDATE,
    Gmail internalDate): the Date header is written by the sender and a wrong
    clock at the other end would make a fresh report look old.
    """
    raw = msg.get('Date')
    if not raw:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(str(raw))
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_report(msg, sender: str = None, subject: str = None) -> bool:
    """Does this message look like a report mail?

    Sender is the strong signal and is required. Subject is checked only when
    configured, and loosely - the observed subject contains a typo, and a
    subject match that breaks the day someone fixes it would be worse than no
    subject match at all.
    """
    want_sender = (sender if sender is not None else config.REPORT_SENDER).strip().lower()
    if not want_sender:
        raise MailError(
            'CUBO_REPORT_SENDER is not set, so any message could be treated '
            'as a report. Refusing to guess.'
        )
    if sender_of(msg) != want_sender:
        return False

    want_subject = (subject if subject is not None else config.REPORT_SUBJECT).strip()
    if want_subject:
        return want_subject.lower() in subject_of(msg).lower()
    return True


def _text_parts(msg):
    """Body texts, plain before HTML.

    Plain first because the HTML part wraps every link in click tracking.
    Preferring plain means the runner neither depends on that service staying
    up nor registers phantom 'clicks' on the report link.
    """
    plain, rich = [], []
    if not msg.is_multipart():
        try:
            content = msg.get_content()
        except (LookupError, ValueError):
            return []
        target = plain if msg.get_content_type() == 'text/plain' else rich
        target.append(str(content))
        return plain + rich

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if ctype not in ('text/plain', 'text/html'):
            continue
        # An attached .eml or a forwarded copy is not the body.
        if (part.get_content_disposition() or '') == 'attachment':
            continue
        try:
            content = str(part.get_content())
        except (LookupError, ValueError):
            continue
        (plain if ctype == 'text/plain' else rich).append(content)
    return plain + rich


def find_csv_url(msg) -> str:
    """The report download link, or None.

    Matches against CUBO_CSV_URL_PATTERN, which pins the host and path. That
    is what stops a malformed or spoofed message turning the runner into a
    fetch-anything tool, so the pattern is required rather than defaulted.
    """
    if not config.CSV_URL_PATTERN:
        raise MailError(
            'CUBO_CSV_URL_PATTERN is not set, so any link in the message '
            'would be downloaded. Refusing to guess.'
        )
    for text in _text_parts(msg):
        # HTML entity-encodes URLs (&amp;), and some senders wrap them in
        # angle brackets. Unescaping first means the pattern sees the URL as
        # it will actually be requested.
        found = cubo_api.extract_csv_url(html.unescape(text))
        if found:
            return found
    return None


def link_from_raw(raw, sender: str = None, subject: str = None):
    """(url, why) for one raw message. `url` is None when it is not usable.

    `why` is safe to log - it never contains the link.
    """
    msg = parse(raw)
    if not is_report(msg, sender=sender, subject=subject):
        return None, f'no es un reporte (de {sender_of(msg) or "?"})'
    url = find_csv_url(msg)
    if not url:
        return None, 'es un reporte pero no trae un enlace CSV reconocible'
    return url, f'enlace encontrado {cubo_api.redact_url(url)}'


def newest_first(messages):
    """Sort (id, received_at, raw) triples newest first, undated last.

    A retry can produce two report mails; the newest is the one that matches
    the window we just asked for.
    """
    def key(item):
        received = item[1]
        if received is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        return received if received.tzinfo else received.replace(tzinfo=timezone.utc)
    return sorted(messages, key=key, reverse=True)


def search_query(sender: str = None, after: datetime = None) -> str:
    """A Gmail/IMAP-style search string for report mail.

    Kept here so both transports ask the same question of the server.
    """
    sender = (sender if sender is not None else config.REPORT_SENDER).strip()
    parts = [f'from:{sender}'] if sender else []
    if config.REPORT_LABEL:
        parts.append(f'label:{config.REPORT_LABEL}')
    if after:
        # Gmail's after: is date-granular and interpreted in the account's
        # timezone, so it is a coarse pre-filter only. The precise
        # "newer than when we asked" comparison happens on received_at.
        parts.append(f'after:{after:%Y/%m/%d}')
    return ' '.join(parts)


_ADDR_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def looks_like_address(value: str) -> bool:
    return bool(_ADDR_RE.match((value or '').strip()))
