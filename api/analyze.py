"""
Vercel Python Serverless Function — fraud-analysis endpoint.

Flow per request:
  1.  Validate the caller's Supabase JWT and email domain.
  2.  Pull the current watchlist (merchants + cards) from Supabase.
  3.  Stage the watchlist + the uploaded CSV in /tmp (per-request RAM, wiped after).
  4.  Invoke the existing analyze.py exactly as the CLI does.
  5.  Sync the updated watchlist + audit row + findings back to Supabase.
  6.  Return the findings JSON to the browser. The CSV is never persisted.
"""

import json
import os
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler

# Make the project-root analyze.py importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyze as fraud_engine  # noqa: E402

from supabase import create_client, Client  # noqa: E402


SUPABASE_URL          = os.environ.get('NEXT_PUBLIC_SUPABASE_URL', '')
SUPABASE_ANON_KEY     = os.environ.get('NEXT_PUBLIC_SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY  = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')
ALLOWED_EMAIL_DOMAIN  = os.environ.get('ALLOWED_EMAIL_DOMAIN', 'cubopago.com').lower()


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

def verify_user(auth_header):
    """Return (user_id, email) on success; raise ValueError otherwise.

    Calls Supabase's /auth/v1/user endpoint directly via urllib so the raw
    error response is visible if validation fails — easier to debug than
    supabase-py's wrapped exceptions.
    """
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError('Missing bearer token')
    token = auth_header[len('Bearer '):]

    # Surface env-var problems clearly instead of letting them turn into
    # cryptic "Invalid API key" responses from Supabase.
    if not SUPABASE_URL:
        raise ValueError('Server config: NEXT_PUBLIC_SUPABASE_URL not set in Vercel')
    if not SUPABASE_ANON_KEY:
        raise ValueError(
            'Server config: NEXT_PUBLIC_SUPABASE_ANON_KEY not set in Vercel '
            '(this is the same value the frontend uses)'
        )

    # Hint about the key shape so config typos surface in the error message.
    # Only the first 6 chars — enough to distinguish "eyJh..." (legacy JWT
    # format) from "sb_pu..." (new format) without leaking the secret.
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
    # Exact-suffix check: reject crafted addresses like "evil@x.com@cubopago.com".
    parts = email.split('@')
    if len(parts) != 2 or parts[1] != ALLOWED_EMAIL_DOMAIN:
        raise ValueError(f'Email domain not allowed (must be @{ALLOWED_EMAIL_DOMAIN})')
    return user_id, email


# ─────────────────────────────────────────────────────────────────────────────
# Supabase ↔ watchlist dict
# ─────────────────────────────────────────────────────────────────────────────

def supabase_client() -> Client:
    if not SUPABASE_SERVICE_KEY:
        raise RuntimeError(
            'Server config: SUPABASE_SERVICE_ROLE_KEY not set in Vercel'
        )
    try:
        return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    except Exception as e:
        key_hint = SUPABASE_SERVICE_KEY[:6] + '...'
        raise RuntimeError(
            f'SUPABASE_SERVICE_ROLE_KEY rejected by supabase-py (prefix {key_hint}): {e}. '
            f'If the key starts with "sb_" (new format), use the legacy JWT-format '
            f'service_role key instead — Supabase → Settings → API → Legacy API keys, '
            f'starts with "eyJ".'
        )


def load_watchlist_from_supabase(sb: Client) -> dict:
    """Build the same dict shape analyze.py expects from the two SQL tables."""
    merchants = sb.table('watchlist_merchants').select('*').execute().data or []
    cards     = sb.table('watchlist_cards').select('*').execute().data or []

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


def sync_watchlist_to_supabase(sb: Client, wl: dict, run_id: str):
    """Upsert merchants + cards. Permanent: never deletes."""
    if wl.get('merchants'):
        rows = [{
            'company_name':    name,
            'company_id':      entry.get('company_id') or None,
            'first_flagged':   entry.get('first_flagged'),
            'last_flagged':    entry.get('last_flagged'),
            'flag_count':      int(entry.get('flag_count', 1)),
            'last_risk_score': int(entry.get('last_risk_score', 0) or 0),
            'last_run_id':     run_id,
        } for name, entry in wl['merchants'].items()]
        sb.table('watchlist_merchants').upsert(rows, on_conflict='company_name').execute()

    if wl.get('cards'):
        rows = []
        for ck, entry in wl['cards'].items():
            try:
                bin_, last4 = ck.split('-', 1)
            except ValueError:
                continue
            rows.append({
                'bin':           bin_,
                'last4':         last4,
                'first_flagged': entry.get('first_flagged'),
                'last_flagged':  entry.get('last_flagged'),
                'flag_count':    int(entry.get('flag_count', 1)),
                'last_run_id':   run_id,
            })
        if rows:
            sb.table('watchlist_cards').upsert(rows, on_conflict='bin,last4').execute()


def insert_run_audit(sb: Client, user_id: str, email: str, csv_filename: str, findings: dict) -> str:
    summary = findings.get('summary', {})
    payload = {
        'run_by_email':            email,
        'run_by_user_id':          user_id,
        'csv_filename':            csv_filename,
        'csv_date_start':          (summary.get('date_range') or {}).get('start'),
        'csv_date_end':            (summary.get('date_range') or {}).get('end'),
        'total_rows':              summary.get('total_rows'),
        'unique_transactions':     summary.get('unique_transactions'),
        'critical_findings_count': summary.get('total_critical_findings'),
        'monitor_findings_count':  summary.get('total_monitor_findings'),
        'chargeback_exposure_usd': summary.get('estimated_chargeback_exposure'),
        'summary':                 summary,
    }
    res = sb.table('analysis_runs').insert(payload).execute()
    return res.data[0]['id']


def insert_findings_history(sb: Client, run_id: str, findings: dict):
    rows = []
    for f in findings.get('critical_findings', []) + findings.get('monitor_findings', []):
        rows.append({
            'run_id':                  run_id,
            'company_name':            f.get('company_name'),
            'company_id':              f.get('company_id'),
            'finding_type':            f.get('type'),
            'confidence':              f.get('confidence'),
            'risk_score':              f.get('risk_score'),
            'fingerprints':            f.get('fingerprints', []),
            'action_code':             f.get('action_code'),
            'chargeback_exposure_usd': f.get('estimated_chargeback_exposure'),
            'description_es':          f.get('description_es'),
            'payload':                 f,
        })
    if rows:
        sb.table('findings_history').insert(rows).execute()


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler
# ─────────────────────────────────────────────────────────────────────────────

def parse_multipart(body: bytes, boundary: bytes):
    """Minimal multipart/form-data parser — extracts the first file part as bytes."""
    sep = b'--' + boundary
    parts = body.split(sep)
    for part in parts:
        if b'filename=' not in part:
            continue
        try:
            header_end = part.index(b'\r\n\r\n')
        except ValueError:
            continue
        headers = part[:header_end].decode('utf-8', errors='replace')
        content = part[header_end + 4:]
        if content.endswith(b'\r\n'):
            content = content[:-2]
        filename = 'upload.csv'
        for line in headers.split('\r\n'):
            if 'filename=' in line:
                filename = line.split('filename=')[1].strip().strip('"')
                break
        return filename, content
    raise ValueError('No file part found in multipart body')


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

        try:
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                self._send_json(400, {'error': 'Expected multipart/form-data upload'})
                return
            boundary = content_type.split('boundary=')[1].encode('utf-8')
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0:
                self._send_json(400, {'error': 'Empty upload'})
                return
            body = self.rfile.read(length)

            filename, csv_bytes = parse_multipart(body, boundary)

            sb = supabase_client()
            wl = load_watchlist_from_supabase(sb)

            with tempfile.TemporaryDirectory() as tmpdir:
                csv_path = os.path.join(tmpdir, 'input.csv')
                wl_path  = os.path.join(tmpdir, 'wl.json')
                with open(csv_path, 'wb') as f:
                    f.write(csv_bytes)
                with open(wl_path, 'w') as f:
                    json.dump(wl, f, default=str)

                findings = fraud_engine.analyze(csv_path, watchlist_path=wl_path)

                with open(wl_path) as f:
                    updated_wl = json.load(f)

            run_id = insert_run_audit(sb, user_id, email, filename, findings)
            sync_watchlist_to_supabase(sb, updated_wl, run_id)
            insert_findings_history(sb, run_id, findings)

            findings['run_id'] = run_id
            self._send_json(200, findings)

        except Exception as e:
            # Full trace stays in Vercel server logs.
            traceback.print_exc()
            err_type = type(e).__name__
            err_module = type(e).__module__ or ''
            msg = str(e)[:400]
            # Surface details for safe-to-show types: our own RuntimeErrors
            # (config issues with explicit, sanitized messages) and exceptions
            # from Supabase/Postgrest/GoTrue (auth/db errors that don't
            # contain CSV data). Pandas/numpy errors stay generic since their
            # messages can include row values.
            safe_to_surface = (
                err_type == 'RuntimeError'
                or 'supabase' in err_module
                or 'postgrest' in err_module
                or 'gotrue' in err_module
            )
            if safe_to_surface and msg:
                self._send_json(500, {'error': f'{err_type}: {msg}'})
            else:
                self._send_json(500, {
                    'error': f'Internal error ({err_type}). Check Vercel function logs for details.',
                })
