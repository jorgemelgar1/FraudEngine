"""
Vercel Python Serverless Function — findings review endpoint.

Two operations on /api/findings:

  GET /api/findings?status=pending[&section=exposure|zero_settlement]
  GET /api/findings?status=history[&section=exposure|zero_settlement]
      List findings filtered by review state. Pending excludes Monitor
      (those are marked not_applicable on insert by /api/analyze).
      Both report sections are returned unless `section` narrows it:
      'exposure' is the chargeback-exposure model, 'zero_settlement' is
      the card-testing detector (migration 0007).

  POST /api/findings
      Body: { "action": "accept" | "reject" | "undo", "finding_ids": [uuid, ...] }
      Bulk-applies the action via the review_findings RPC. Returns the
      per-id result so the UI can show partial-success state.

All Supabase access goes through urllib (no supabase-py) to stay compatible
with both legacy 'eyJ...' JWT keys and the newer 'sb_secret_...' format,
matching /api/analyze.
"""

import json
import os
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler


SUPABASE_URL          = os.environ.get('NEXT_PUBLIC_SUPABASE_URL', '')
SUPABASE_ANON_KEY     = os.environ.get('NEXT_PUBLIC_SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY  = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')
ALLOWED_EMAIL_DOMAIN  = os.environ.get('ALLOWED_EMAIL_DOMAIN', 'cubopago.com').lower()


class ConfigError(RuntimeError):
    """Sanitized error safe to return to the client."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Auth — duplicated from api/analyze.py rather than imported, because Vercel
# Python serverless deploys each file as an independent function and shared
# modules complicate the sys.path setup. The two copies must stay in sync.
# ─────────────────────────────────────────────────────────────────────────────

def verify_user(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError('Missing bearer token')
    token = auth_header[len('Bearer '):]
    if not SUPABASE_URL:
        raise ValueError('Server config: NEXT_PUBLIC_SUPABASE_URL not set')
    if not SUPABASE_ANON_KEY:
        raise ValueError('Server config: NEXT_PUBLIC_SUPABASE_ANON_KEY not set')

    req = urllib.request.Request(
        f'{SUPABASE_URL.rstrip("/")}/auth/v1/user',
        headers={
            'Authorization': f'Bearer {token}',
            'apikey':        SUPABASE_ANON_KEY,
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
        raise ValueError(f'Supabase rejected token (HTTP {e.code}): {body}')
    except Exception as e:
        raise ValueError(f'Could not reach Supabase: {type(e).__name__}: {e}')

    email = (user.get('email') or '').lower()
    user_id = user.get('id')
    if not email or not user_id:
        raise ValueError('Token missing email or user id')
    parts = email.split('@')
    if len(parts) != 2 or parts[1] != ALLOWED_EMAIL_DOMAIN:
        raise ValueError(f'Email domain not allowed (must be @{ALLOWED_EMAIL_DOMAIN})')
    return user_id, email


# ─────────────────────────────────────────────────────────────────────────────
# Supabase REST
# ─────────────────────────────────────────────────────────────────────────────

def sb_rest(method: str, path: str, body=None, prefer: str = ''):
    if not SUPABASE_URL:
        raise ConfigError('Server config: NEXT_PUBLIC_SUPABASE_URL not set')
    if not SUPABASE_SERVICE_KEY:
        raise ConfigError('Server config: SUPABASE_SERVICE_ROLE_KEY not set')

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
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read()
            if not content:
                return None
            return json.loads(content)
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode('utf-8', errors='replace')[:500]
        except Exception:
            body_text = '(no body)'
        key_hint = SUPABASE_SERVICE_KEY[:6] + '...'
        raise ConfigError(
            f'Supabase REST {method} {path} failed '
            f'(HTTP {e.code}, service key prefix {key_hint}): {body_text}'
        )


# ─────────────────────────────────────────────────────────────────────────────
# List queries
# ─────────────────────────────────────────────────────────────────────────────

# Columns we surface to the UI. The full `payload` is heavy (5–50 KB / row)
# but the review UI needs description_es + recommended_action_es + the
# fingerprints + the evidence card list, so we include it. If page loads
# get slow at scale, paginate or trim payload here.
_LIST_SELECT = (
    'id,run_id,company_name,company_id,finding_type,confidence,risk_score,'
    'fingerprints,action_code,section,chargeback_exposure_usd,'
    'chargeback_exposure_currency,description_es,review_status,reviewed_at,'
    'reviewed_by_email,review_notes,watchlist_delta,payload,'
    'analysis_runs(run_at,run_by_email,csv_filename,csv_date_start,csv_date_end)'
)

# Sections a caller may filter on. Anything else is rejected rather than
# passed through to PostgREST, so a crafted `section=` value can't be used
# to smuggle operators into the query string.
_VALID_SECTIONS = ('exposure', 'zero_settlement')


def _section_filter(section):
    """Return the PostgREST filter fragment for an optional section filter.

    None / '' / 'all' means "both sections" and produces no filter, which is
    the default the review screens use.
    """
    if not section or section == 'all':
        return ''
    if section not in _VALID_SECTIONS:
        raise ValueError(f'Unknown section: {section!r}')
    return f'&section=eq.{section}'


def list_pending(section=None):
    """Critical findings awaiting review, newest run first.

    Covers both sections: the exposure model and the zero-settlement
    card-testing detector both emit Critical findings that need a human
    decision before they reach the watchlist. `section` narrows the list to
    one of them; the default returns both.
    """
    rows = sb_rest(
        'GET',
        f'findings_history?select={_LIST_SELECT}'
        f'&review_status=eq.pending'
        f'&confidence=eq.Critical'
        f'{_section_filter(section)}'
        f'&order=run_id.desc,risk_score.desc'
        f'&limit=500',
    )
    return rows or []


def list_history(section=None):
    """Most-recent reviewed findings (accepted or rejected), both sections."""
    rows = sb_rest(
        'GET',
        f'findings_history?select={_LIST_SELECT}'
        f'&review_status=in.(accepted,rejected)'
        f'&confidence=eq.Critical'
        f'{_section_filter(section)}'
        f'&order=reviewed_at.desc'
        f'&limit=500',
    )
    return rows or []


# ─────────────────────────────────────────────────────────────────────────────
# Review RPC
# ─────────────────────────────────────────────────────────────────────────────

def review_findings(finding_ids, action, user_id, user_email):
    """Bulk dispatch to the Postgres review_findings function."""
    if action not in ('accept', 'reject', 'undo'):
        raise ValueError(f'Invalid action: {action}')
    if not finding_ids:
        raise ValueError('finding_ids must be a non-empty list')

    # Validate each id is a uuid string so an attacker can't smuggle arbitrary
    # SQL through PostgREST's parameter coercion.
    clean_ids = []
    for fid in finding_ids:
        try:
            clean_ids.append(str(uuid.UUID(str(fid))))
        except (ValueError, AttributeError):
            raise ValueError(f'Invalid finding id: {fid!r}')

    return sb_rest('POST', 'rpc/review_findings', body={
        'p_finding_ids': clean_ids,
        'p_action':      action,
        'p_user_id':     user_id,
        'p_user_email':  user_email,
    })


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler
# ─────────────────────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload):
        body = json.dumps(payload, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        try:
            return verify_user(self.headers.get('Authorization', ''))
        except ValueError as e:
            self._send_json(401, {'error': str(e)})
            return None

    def do_GET(self):
        auth = self._auth()
        if auth is None:
            return

        request_id = uuid.uuid4().hex[:8]
        try:
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            status = (params.get('status') or ['pending'])[0]
            section = (params.get('section') or [None])[0]
            try:
                if status == 'pending':
                    self._send_json(200, {'findings': list_pending(section)})
                elif status == 'history':
                    self._send_json(200, {'findings': list_history(section)})
                else:
                    self._send_json(400, {'error': f'Unknown status: {status!r}'})
            except ValueError as e:
                # Raised by _section_filter for an unrecognized section.
                self._send_json(400, {'error': str(e)})
        except ConfigError as e:
            self._send_json(500, {'error': f'ConfigError: {e}'})
        except Exception as e:
            traceback.print_exc()
            self._send_json(500, {
                'error': f'Internal error ({type(e).__name__}, ref: {request_id})',
            })

    def do_POST(self):
        auth = self._auth()
        if auth is None:
            return
        user_id, email = auth

        request_id = uuid.uuid4().hex[:8]
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 64 * 1024:
                # 64 KB cap is generous: a bulk action on every finding from
                # a year of daily runs fits easily.
                self._send_json(400, {'error': 'Empty or oversized JSON body'})
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError as e:
                self._send_json(400, {'error': f'Invalid JSON: {e}'})
                return

            action = payload.get('action')
            finding_ids = payload.get('finding_ids') or []

            try:
                results = review_findings(finding_ids, action, user_id, email)
            except ValueError as e:
                self._send_json(400, {'error': str(e)})
                return

            self._send_json(200, {'results': results})

        except ConfigError as e:
            self._send_json(500, {'error': f'ConfigError: {e}'})
        except Exception as e:
            traceback.print_exc()
            self._send_json(500, {
                'error': f'Internal error ({type(e).__name__}, ref: {request_id})',
            })
