"""Talk to the Cubo CMS API and fetch report CSVs.

Two operations, both proven against the live API:

  trigger_report()  GET the report endpoint. Returns 200 with an EMPTY body
                    and queues an email. There is no job id and nothing to
                    poll - the mail is the only signal that it worked.

  download_csv()    Plain GET of the CDN link from the email. No auth:
                    possession of the URL IS the authorization, which is why
                    it must never be logged.

urllib rather than requests, so the runner needs nothing beyond the engine's
own dependencies.
"""

import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import config


class CmsError(RuntimeError):
    """API failure whose message is safe to show - never contains the token."""


def _headers(token: str) -> dict:
    return {
        'Accept': '*/*',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Origin': config.ORIGIN,
        'Referer': config.REFERER,
    }


def date_window(lookback_days: int = None, end: datetime = None):
    """Return (from_date, to_date) as YYYY-MM-DD strings.

    Inclusive of today by default. The API takes the range as `createdAt`
    repeated twice - first occurrence is the start, second is the end.
    """
    lookback_days = lookback_days or config.LOOKBACK_DAYS
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    return start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d')


def trigger_report(token: str, country_id: int, date_from: str, date_to: str,
                   timeout: int = 60) -> dict:
    """Ask the CMS to generate a transactions report. Returns request metadata.

    A 200 here means "queued", not "ready". The caller must then wait for the
    email. Raises CmsError on anything else.
    """
    path = config.REPORT_PATH.format(country_id=country_id)
    # createdAt intentionally appears twice - that is how the API expresses a
    # range. urlencode with doseq preserves the repetition.
    query = urllib.parse.urlencode([
        ('createdAt', date_from),
        ('createdAt', date_to),
        ('isAEVIRTUAL', 'false'),
        ('countryId', str(country_id)),
        ('depositStatusFilter', 'ALL'),
    ])
    url = f'{config.API_ROOT}{path}?{query}'

    req = urllib.request.Request(url, headers=_headers(token), method='GET')
    requested_at = datetime.now(timezone.utc)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return {
                'status': resp.status,
                'body_bytes': len(body),
                'requested_at': requested_at,
                'country_id': country_id,
                'date_from': date_from,
                'date_to': date_to,
            }
    except urllib.error.HTTPError as e:
        hint = {
            401: 'Token rejected - it expired or was revoked. Re-capture it.',
            403: 'Forbidden - the API may be checking Origin/Referer, or scope.',
            404: f'No report endpoint for country id {country_id}.',
            429: 'Rate limited - too many report requests.',
        }.get(e.code, 'Unexpected status.')
        raise CmsError(f'Report request failed (HTTP {e.code}). {hint}')
    except urllib.error.URLError as e:
        raise CmsError(f'Could not reach the CMS API: {e.reason}')


def extract_csv_url(text: str) -> str:
    """Pull the direct CDN link out of an email body.

    Deliberately does NOT follow the SendGrid tracking wrapper: that would
    register a click, add a dependency on a third party staying up, and the
    direct URL is available in the plain-text part anyway.
    """
    if not text:
        return None
    m = re.search(config.CSV_URL_PATTERN, text)
    return m.group(0) if m else None


def download_csv(url: str, dest_path: str, timeout: int = 300) -> int:
    """Download a report CSV. Returns bytes written.

    No Authorization header: the CDN link is unauthenticated. The URL is the
    secret, so it is never included in exception messages.
    """
    if not re.fullmatch(config.CSV_URL_PATTERN, url or ''):
        # Refuse anything that is not a report link. Without this the runner
        # would happily GET whatever a malformed or spoofed email contained.
        raise CmsError(
            'Refusing to download: URL does not match CUBO_CSV_URL_PATTERN.'
        )

    os.makedirs(os.path.dirname(dest_path) or '.', exist_ok=True)
    req = urllib.request.Request(url, headers={'Accept': '*/*'}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, \
                open(dest_path, 'wb') as out:
            written = 0
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                written += len(chunk)
    except urllib.error.HTTPError as e:
        # Note the absence of `url` here - it is a credential.
        raise CmsError(f'CSV download failed (HTTP {e.code}).')
    except urllib.error.URLError as e:
        raise CmsError(f'CSV download failed: {e.reason}')

    if written == 0:
        raise CmsError('CSV download produced an empty file.')
    return written


def redact_url(url: str) -> str:
    """Log-safe form of a report URL: keeps the shape, drops the secret."""
    if not url:
        return '<none>'
    m = re.search(r'/([0-9a-fA-F-]{36})\.csv', url)
    if not m:
        return '<report url>'
    # Enough to correlate two log lines, not enough to fetch the file.
    return f'<report {m.group(1)[:8]}...>'
