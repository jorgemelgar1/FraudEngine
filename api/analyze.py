"""
Vercel Python Serverless Function — fraud-analysis endpoint.

Flow per request:
  1.  Validate the caller's Supabase JWT and email domain.
  2.  Pull the current watchlist (merchants + cards) from Supabase.
  3.  Stage the watchlist + the uploaded CSV in /tmp (per-request RAM, wiped after).
  4.  Invoke the existing analyze.py exactly as the CLI does.
  5.  Sync the updated watchlist + audit row + findings back to Supabase.
  6.  Return the findings JSON to the browser. The CSV is never persisted.

All Supabase access goes through urllib (no supabase-py) so this works
with both legacy 'eyJ...' JWT keys and the newer 'sb_secret_...' format.
"""

import json
import os
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler

# Make the project-root analyze.py importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyze as fraud_engine  # noqa: E402


SUPABASE_URL          = os.environ.get('NEXT_PUBLIC_SUPABASE_URL', '')
SUPABASE_ANON_KEY     = os.environ.get('NEXT_PUBLIC_SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY  = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')
ALLOWED_EMAIL_DOMAIN  = os.environ.get('ALLOWED_EMAIL_DOMAIN', 'cubopago.com').lower()

# Hard cap on accepted upload size. Vercel's request-body limit is ~4.5 MB on
# Hobby; we mirror the client-side limit so a forged request can't OOM pandas
# or run the function out of memory before the body finishes streaming.
MAX_UPLOAD_BYTES = 4 * 1024 * 1024


class ConfigError(RuntimeError):
    """Configuration / infrastructure error whose message is safe to return
    to the client. Use this for env-var misconfiguration, Supabase REST
    failures, schema mismatches, and similar — never for anything where the
    message could contain CSV-derived row data."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

def verify_user(auth_header):
    """Return (user_id, email) on success; raise ValueError otherwise.

    Calls Supabase's /auth/v1/user endpoint directly via urllib so the raw
    error response is visible if validation fails.
    """
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError('Missing bearer token')
    token = auth_header[len('Bearer '):]

    if not SUPABASE_URL:
        raise ValueError('Server config: NEXT_PUBLIC_SUPABASE_URL not set in Vercel')
    if not SUPABASE_ANON_KEY:
        raise ValueError(
            'Server config: NEXT_PUBLIC_SUPABASE_ANON_KEY not set in Vercel '
            '(this is the same value the frontend uses)'
        )

    key_hint = SUPABASE_ANON_KEY[:6] + '...'

    req = urllib.request.Request(
        f'{SUPABASE_URL.rstrip("/")}/auth/v1/user',
        headers={
            'Authorization': f'Bearer {token}',
            'apikey': SUPABASE_ANON_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            user = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8', errors='replace')[:300]
        except Exception:
            body = '(no body)'
        raise ValueError(
            f'Supabase rejected token (HTTP {e.code}, anon key prefix {key_hint}): {body}'
        )
    except Exception as e:
        raise ValueError(
            f'Could not reach Supabase to validate token (anon key prefix {key_hint}): '
            f'{type(e).__name__}: {e}'
        )

    email = (user.get('email') or '').lower()
    user_id = user.get('id')
    if not email or not user_id:
        raise ValueError('Token missing email or user id in /auth/v1/user response')
    parts = email.split('@')
    if len(parts) != 2 or parts[1] != ALLOWED_EMAIL_DOMAIN:
        raise ValueError(f'Email domain not allowed (must be @{ALLOWED_EMAIL_DOMAIN})')
    return user_id, email


# ─────────────────────────────────────────────────────────────────────────────
# Supabase REST (PostgREST) — direct urllib calls, no supabase-py
# ─────────────────────────────────────────────────────────────────────────────

def sb_rest(method: str, path: str, body=None, prefer: str = ''):
    """Direct call to Supabase's PostgREST endpoint at /rest/v1/<path>.

    Bypasses supabase-py so we work with both legacy 'eyJ...' and new
    'sb_secret_...' service-role key formats.
    """
    if not SUPABASE_URL:
        raise ConfigError('Server config: NEXT_PUBLIC_SUPABASE_URL not set in Vercel')
    if not SUPABASE_SERVICE_KEY:
        raise ConfigError('Server config: SUPABASE_SERVICE_ROLE_KEY not set in Vercel')

    url = f'{SUPABASE_URL.rstrip("/")}/rest/v1/{path}'
    headers = {
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type':  'application/json',
    }
    if prefer:
        headers['Prefer'] = prefer

    data = json.dumps(body, default=str).encode('utf-8') if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read()
            if not content:
                return None
            return json.loads(content)
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode('utf-8', errors='replace')[:300]
        except Exception:
            body_text = '(no body)'
        key_hint = SUPABASE_SERVICE_KEY[:6] + '...'
        raise ConfigError(
            f'Supabase REST {method} {path} failed '
            f'(HTTP {e.code}, service key prefix {key_hint}): {body_text}'
        )


# ─────────────────────────────────────────────────────────────────────────────
# Watchlist + audit + findings sync
# ─────────────────────────────────────────────────────────────────────────────

def load_watchlist_from_supabase() -> dict:
    """Build the same dict shape analyze.py expects from the two SQL tables.

    The explicit limit overrides PostgREST's 1000-row default — without it,
    older watchlist entries silently drop off and the fraud detectors lose
    their 'is this a known offender?' signal once the watchlist grows past
    1000 rows.
    """
    merchants = sb_rest('GET', 'watchlist_merchants?select=*&limit=100000') or []
    cards     = sb_rest('GET', 'watchlist_cards?select=*&limit=100000') or []

    wl = {'merchants': {}, 'cards': {}}
    for m in merchants:
        wl['merchants'][m['company_name']] = {
            'first_flagged':   m['first_flagged'],
            'last_flagged':    m['last_flagged'],
            'flag_count':      m.get('flag_count', 1),
            'company_id':      m.get('company_id', '') or '',
            'last_risk_score': m.get('last_risk_score', 0) or 0,
        }
    for c in cards:
        ck = c['card_key']  # generated as bin || '-' || last4
        wl['cards'][ck] = {
            'first_flagged': c['first_flagged'],
            'last_flagged':  c['last_flagged'],
            'flag_count':    c.get('flag_count', 1),
        }
    return wl


def insert_run_audit(user_id: str, email: str, csv_filename: str, findings: dict) -> str:
    summary = findings.get('summary', {})
    # `chargeback_exposure_usd` is a legacy column name from when the engine
    # only handled Panama CSVs. It now holds whatever currency the CSV is
    # denominated in; the currency code is stored alongside it in
    # `chargeback_exposure_currency` (added in migration 0003).
    payload = {
        'run_by_email':                  email,
        'run_by_user_id':                user_id,
        'csv_filename':                  csv_filename,
        'csv_date_start':                (summary.get('date_range') or {}).get('start'),
        'csv_date_end':                  (summary.get('date_range') or {}).get('end'),
        'total_rows':                    summary.get('total_rows'),
        'unique_transactions':           summary.get('unique_transactions'),
        'critical_findings_count':       summary.get('total_critical_findings'),
        'monitor_findings_count':        summary.get('total_monitor_findings'),
        'chargeback_exposure_usd':       summary.get('estimated_chargeback_exposure'),
        'chargeback_exposure_currency':  summary.get('currency', 'USD'),
        'summary':                       summary,
    }
    res = sb_rest('POST', 'analysis_runs',
                  body=payload, prefer='return=representation')
    if not res or len(res) == 0:
        raise ConfigError('analysis_runs insert returned no row')
    return res[0]['id']


def insert_findings_history(run_id: str, findings: dict):
    summary_currency = (findings.get('summary') or {}).get('currency', 'USD')
    rows = []
    for f in findings.get('critical_findings', []) + findings.get('monitor_findings', []):
        confidence = f.get('confidence')
        # Critical findings need human review before they update the watchlist
        # (migration 0004). Monitor findings never wrote to the watchlist, so
        # they're marked not_applicable to keep them out of the pending queue.
        review_status = 'pending' if confidence == 'Critical' else 'not_applicable'
        rows.append({
            'run_id':                       run_id,
            'company_name':                 f.get('company_name'),
            'company_id':                   f.get('company_id'),
            'finding_type':                 f.get('type'),
            'confidence':                   confidence,
            'risk_score':                   f.get('risk_score'),
            'fingerprints':                 f.get('fingerprints', []),
            'action_code':                  f.get('action_code'),
            'chargeback_exposure_usd':      f.get('estimated_chargeback_exposure'),
            # Per-finding currency falls back to the run's currency. Monitor
            # findings don't carry an exposure, so the currency is informational
            # but kept for query-time joins.
            'chargeback_exposure_currency': f.get('currency') or summary_currency,
            'description_es':               f.get('description_es'),
            'review_status':                review_status,
            'payload':                      f,
        })
    if rows:
        inserted = sb_rest(
            'POST', 'findings_history',
            body=rows, prefer='return=representation',
        )
        # PostgREST returns inserted rows in the same order we sent them
        # (critical first, then monitor — see the loop above). Attach each
        # row's id back onto the in-memory finding object so the report
        # screen can call /api/findings without re-fetching.
        if inserted and len(inserted) == len(rows):
            critical = findings.get('critical_findings', [])
            monitor  = findings.get('monitor_findings', [])
            for i, row in enumerate(inserted):
                if i < len(critical):
                    critical[i]['finding_id'] = row['id']
                else:
                    monitor[i - len(critical)]['finding_id'] = row['id']


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler
# ─────────────────────────────────────────────────────────────────────────────

def parse_multipart(body: bytes, boundary: bytes):
    """Minimal multipart/form-data parser — extracts the single file part.

    Rejects bodies that contain more than one file part rather than silently
    using the first one, so a caller that thinks they're uploading two files
    finds out instead of getting partial processing.

    Hardenings vs. naive split:
    - Tolerates the leading CRLF that spec-compliant bodies put before each
      boundary delimiter.
    - Strips the closing '--' of the final boundary if it ends up on the part.
    - Caller is expected to have already stripped surrounding quotes from the
      boundary token (RFC permits `boundary="abc"`).
    """
    sep = b'--' + boundary
    parts = body.split(sep)
    found = []
    for part in parts:
        if b'filename=' not in part:
            continue
        # Spec-compliant bodies put a CRLF immediately after each delimiter,
        # so the part begins with \r\n. Strip it if present.
        if part.startswith(b'\r\n'):
            part = part[2:]
        try:
            header_end = part.index(b'\r\n\r\n')
        except ValueError:
            continue
        headers = part[:header_end].decode('utf-8', errors='replace')
        content = part[header_end + 4:]
        # Trailing artifacts from the closing delimiter '\r\n--<boundary>--\r\n'.
        # After the split on `--<boundary>`, the file content ends with one of:
        #   '\r\n--'  (end-of-stream marker present, last part)
        #   '\r\n'    (regular part terminator)
        #   ''        (truncated body)
        if content.endswith(b'\r\n--'):
            content = content[:-4]
        elif content.endswith(b'\r\n'):
            content = content[:-2]
        elif content.endswith(b'--'):
            content = content[:-2]
        filename = 'upload.csv'
        for line in headers.split('\r\n'):
            if 'filename=' in line:
                filename = line.split('filename=')[1].strip().strip('"')
                break
        found.append((filename, content))
    if not found:
        raise ValueError('No file part found in multipart body')
    if len(found) > 1:
        raise ValueError(
            f'Expected exactly one file in upload, got {len(found)}. '
            f'Upload one CSV at a time.'
        )
    return found[0]


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            user_id, email = verify_user(self.headers.get('Authorization', ''))
        except ValueError as e:
            self._send_json(401, {'error': str(e)})
            return

        # Per-request id used to correlate sanitized client-side errors with
        # the (intentionally minimal) server log line for the same request.
        request_id = uuid.uuid4().hex[:8]

        try:
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                self._send_json(400, {'error': 'Expected multipart/form-data upload'})
                return
            # RFC permits `boundary="abc"`; strip optional quotes so the
            # delimiter we use to split matches what's actually in the body.
            boundary_raw = content_type.split('boundary=')[1].split(';')[0].strip()
            boundary = boundary_raw.strip('"').encode('utf-8')
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0:
                self._send_json(400, {'error': 'Empty upload'})
                return
            if length > MAX_UPLOAD_BYTES:
                # Client enforces the same limit in the UI; this catches forged
                # requests that bypass the browser-side check.
                self._send_json(413, {
                    'error': f'Upload too large ({length} bytes). Limit is '
                             f'{MAX_UPLOAD_BYTES} bytes (~4 MB). For monthly '
                             f'files, run analyze.py locally.',
                })
                return
            body = self.rfile.read(length)

            try:
                filename, csv_bytes = parse_multipart(body, boundary)
            except ValueError as parse_err:
                # parse_multipart raises ValueError for malformed bodies (no
                # file part, multiple parts). These are 400s, not 500s.
                self._send_json(400, {'error': str(parse_err)})
                return

            wl = load_watchlist_from_supabase()

            with tempfile.TemporaryDirectory() as tmpdir:
                csv_path = os.path.join(tmpdir, 'input.csv')
                wl_path  = os.path.join(tmpdir, 'wl.json')
                with open(csv_path, 'wb') as f:
                    f.write(csv_bytes)
                with open(wl_path, 'w') as f:
                    json.dump(wl, f, default=str)

                # Wrap the pandas/numpy analysis in a tight try/except.
                # Pandas exceptions can embed CSV row values in their messages
                # and stack traces (e.g., "could not convert '4111...' to int").
                # We log only the exception type + request id — never the
                # message and never the traceback — to keep CSV-derived data
                # out of Vercel function logs.
                try:
                    findings = fraud_engine.analyze(csv_path, watchlist_path=wl_path)
                except Exception as analysis_err:
                    print(
                        f'[req {request_id}] Analysis failed: '
                        f'{type(analysis_err).__name__}'
                    )
                    raise ConfigError(
                        f'CSV analysis failed (ref: {request_id}). '
                        f'Contact the engineer with this reference.'
                    )

            # As of migration 0004 the watchlist is no longer auto-updated
            # from the analysis output. Findings land in findings_history
            # as 'pending' (Critical) or 'not_applicable' (Monitor); a team
            # member reviews and accepts each via /api/findings.
            run_id = insert_run_audit(user_id, email, filename, findings)
            insert_findings_history(run_id, findings)

            findings['run_id'] = run_id
            self._send_json(200, findings)

        except ConfigError as e:
            # ConfigError is built from sanitized strings (env-var problems,
            # Supabase REST failures, the analysis-failure ref above). Safe
            # to surface to the client and useful for debugging. We do NOT
            # print the traceback — the caller already logged what's needed.
            self._send_json(500, {'error': f'ConfigError: {e}'})

        except Exception as e:
            # Anything else: log the trace (only reachable for non-pandas
            # paths now — auth/multipart/Supabase REST exceptions) and return
            # a generic message. Pandas errors are caught earlier and never
            # reach here.
            traceback.print_exc()
            err_type = type(e).__name__
            self._send_json(500, {
                'error': f'Internal error ({err_type}, ref: {request_id}). '
                         f'Check Vercel function logs.',
            })
