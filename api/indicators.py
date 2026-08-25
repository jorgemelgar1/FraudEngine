"""
Vercel Python Serverless Function — confirmed-fraud indicator management.

  GET  /api/indicators[?include_inactive=1]
       List indicators, newest first, with hit counts.

  POST /api/indicators
       Body: { "indicator_type": "...", "value_raw": "...",
               "match_mode": "exact"|"fuzzy"|"both",
               "source": "...", "source_company_name": "...", "notes": "..." }
       Accepts a list of values under "values" instead of "value_raw" for
       bulk paste — ops arrives with twenty cards from a chargeback report,
       not one at a time.

  POST /api/indicators  { "action": "deactivate", "id": "<uuid>", "reason": "..." }
       Deactivates rather than deletes, so the audit trail of what was
       matched against survives.

  POST /api/indicators  { "action": "preview", "indicator_type": "...", "values": [...] }
       Dry run: normalizes each value, reports why any would be rejected,
       and counts how often it appears in stored finding evidence. This is
       the guardrail against someone indexing "gmail.com".

Validation and the preview use analyze.py's normalizers, so what this endpoint
accepts is exactly what the engine will later match. The stored `value_norm`
column is NOT written here — a trigger owns it (migration 0008) so this
function and the desktop client cannot disagree on the unique key.

Auth is duplicated from api/analyze.py for the same reason api/findings.py
duplicates it: Vercel deploys each file as an independent function.
"""

import json
import os
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyze as fraud_engine  # noqa: E402


SUPABASE_URL          = os.environ.get('NEXT_PUBLIC_SUPABASE_URL', '')
SUPABASE_ANON_KEY     = os.environ.get('NEXT_PUBLIC_SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY  = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')
ALLOWED_EMAIL_DOMAIN  = os.environ.get('ALLOWED_EMAIL_DOMAIN', 'cubopago.com').lower()

# A single paste is capped so one mistake can't load thousands of rows.
MAX_BULK_VALUES = 200


class ConfigError(RuntimeError):
    """Sanitized error safe to return to the client."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Auth — duplicated from api/analyze.py; Vercel deploys each file separately.
# ─────────────────────────────────────────────────────────────────────────────

def verify_user(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError('Missing bearer token')
    token = auth_header[len('Bearer '):]
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise ValueError('Server config: Supabase URL or anon key not set in Vercel')

    req = urllib.request.Request(
        f'{SUPABASE_URL.rstrip("/")}/auth/v1/user',
        headers={'Authorization': f'Bearer {token}', 'apikey': SUPABASE_ANON_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            user = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(f'Supabase rejected token (HTTP {e.code})')
    except Exception as e:
        raise ValueError(f'Could not reach Supabase to validate token: {type(e).__name__}')

    email = (user.get('email') or '').lower()
    user_id = user.get('id')
    if not email or not user_id:
        raise ValueError('Token missing email or user id')
    parts = email.split('@')
    if len(parts) != 2 or parts[1] != ALLOWED_EMAIL_DOMAIN:
        raise ValueError(f'Email domain not allowed (must be @{ALLOWED_EMAIL_DOMAIN})')
    return user_id, email


def sb_rest(method: str, path: str, body=None, prefer: str = ''):
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
            return json.loads(content) if content else None
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode('utf-8', errors='replace')[:300]
        except Exception:
            body_text = '(no body)'
        raise ConfigError(f'Supabase REST {method} {path} failed (HTTP {e.code}): {body_text}')


# ─────────────────────────────────────────────────────────────────────────────
# Operations
# ─────────────────────────────────────────────────────────────────────────────

_LIST_SELECT = (
    'id,indicator_type,value_raw,value_norm,match_mode,source,'
    'source_company_name,notes,added_by_email,added_at,active,expires_at,'
    'hit_count,last_hit_at,last_hit_company'
)


def list_indicators(include_inactive: bool):
    q = f'fraud_indicators?select={_LIST_SELECT}&order=added_at.desc&limit=2000'
    if not include_inactive:
        q += '&active=eq.true'
    return sb_rest('GET', q) or []


def _evidence_occurrences(indicator_type: str, value_norm: str) -> int:
    """How often this value already appears in stored finding evidence.

    This is the only historical corpus available — transactions are never
    stored — and it is uneven: critical/monitor evidence has carried the
    payer fields only since the indicator release, while zero-settlement
    evidence has had them all along. So a zero here means 'not seen in what
    we kept', not 'never happened'. The UI says so.
    """
    rows = sb_rest(
        'GET',
        'findings_history?select=payload&order=id.desc&limit=500',
    ) or []

    columns = fraud_engine.INDICATOR_SOURCE_COLUMNS.get(indicator_type, [])
    # Evidence keys don't always match CSV column names.
    key_map = {
        'client_email': 'client_email',
        'client_phone': 'client_phone',
        'ip': 'ip',
        'card_holder': 'card_holder',
        'client_name': 'client_name',
        'company_name': 'company_name',
        'company_id': 'company_id',
    }

    def evidence_values(ev):
        """Candidate values from one evidence row for this indicator type."""
        if indicator_type == 'card_key':
            # Evidence stores the two halves separately; the engine's
            # card_key column is built during load and never persisted.
            b, l4 = ev.get('card_bin'), ev.get('card_last_digits')
            return [f'{b}-{l4}'] if b and l4 else []
        return [ev.get(key_map.get(col, col)) for col in columns]

    count = 0
    for row in rows:
        payload = row.get('payload') or {}
        for ev in payload.get('evidence', []) or []:
            for raw in evidence_values(ev):
                if raw is None:
                    continue
                if fraud_engine.normalize_indicator_value(indicator_type, raw) == value_norm:
                    count += 1
                    break
    return count


def preview_values(indicator_type: str, values: list) -> list:
    """Normalize each candidate and report whether it is usable."""
    if indicator_type not in fraud_engine.INDICATOR_SOURCE_COLUMNS:
        raise ValueError(f'Unknown indicator_type: {indicator_type!r}')

    out = []
    for raw in values[:MAX_BULK_VALUES]:
        norm = fraud_engine.normalize_indicator_value(indicator_type, raw)
        if indicator_type == 'card_key':
            reason = fraud_engine.card_key_input_error(raw)
        else:
            reason = fraud_engine.indicator_rejection_reason(indicator_type, norm)
        entry = {
            'value_raw': raw,
            'value_norm': norm,
            'ok': reason is None,
            'reason': reason,
            'evidence_hits': 0,
        }
        if reason is None:
            try:
                entry['evidence_hits'] = _evidence_occurrences(indicator_type, norm)
            except ConfigError:
                entry['evidence_hits'] = None   # lookup failed; not a blocker
        out.append(entry)
    return out


def create_indicators(payload: dict, user_email: str) -> dict:
    itype = payload.get('indicator_type')
    if itype not in fraud_engine.INDICATOR_SOURCE_COLUMNS:
        raise ValueError(f'Unknown indicator_type: {itype!r}')

    match_mode = payload.get('match_mode', 'exact')
    if match_mode not in ('exact', 'fuzzy', 'both'):
        raise ValueError(f'Invalid match_mode: {match_mode!r}')
    if match_mode in ('fuzzy', 'both') and itype not in fraud_engine.FUZZY_CAPABLE_TYPES:
        raise ValueError(
            f'{itype} does not support fuzzy matching — a near-miss on this '
            f'field is simply a different value.'
        )

    values = payload.get('values')
    if not values:
        single = payload.get('value_raw')
        values = [single] if single else []
    if not values:
        raise ValueError('No values provided')
    if len(values) > MAX_BULK_VALUES:
        raise ValueError(f'Too many values at once (max {MAX_BULK_VALUES})')

    rows, rejected = [], []
    seen = set()
    for raw in values:
        raw = (str(raw) if raw is not None else '').strip()
        if not raw:
            continue
        norm = fraud_engine.normalize_indicator_value(itype, raw)
        if itype == 'card_key':
            reason = fraud_engine.card_key_input_error(raw)
        else:
            reason = fraud_engine.indicator_rejection_reason(itype, norm)
        if reason:
            rejected.append({'value_raw': raw, 'reason': reason})
            continue
        if norm in seen:
            continue           # same value twice in one paste
        seen.add(norm)
        rows.append({
            'indicator_type':      itype,
            # Cards are stored canonically ('411111-1234') regardless of the
            # separator pasted, so '411111 1234' and '411111/1234' collapse
            # to one row rather than three.
            'value_raw':           norm if itype == 'card_key' else raw,
            # value_norm is deliberately NOT sent: a BEFORE INSERT trigger
            # computes it (migration 0008) so this function and the desktop
            # client cannot disagree on the unique key. `norm` above is still
            # used for validation and the duplicate check within this batch.
            'match_mode':          match_mode,
            'source':              payload.get('source') or None,
            'source_company_name': payload.get('source_company_name') or None,
            'notes':               payload.get('notes') or None,
            'added_by_email':      user_email,
            'expires_at':          payload.get('expires_at') or None,
            'active':              True,
        })

    inserted = []
    if rows:
        # merge-duplicates: re-adding a value that already exists refreshes
        # it instead of failing the whole batch on the unique constraint.
        # on_conflict names the constraint columns so PostgREST resolves
        # against the right unique index.
        inserted = sb_rest(
            'POST', 'fraud_indicators?on_conflict=indicator_type,value_norm',
            body=rows,
            prefer='return=representation,resolution=merge-duplicates',
        ) or []

    return {'inserted': inserted, 'rejected': rejected}


def deactivate(indicator_id: str, user_email: str, reason: str):
    try:
        clean = str(uuid.UUID(str(indicator_id)))
    except (ValueError, AttributeError):
        raise ValueError(f'Invalid indicator id: {indicator_id!r}')
    return sb_rest('POST', 'rpc/deactivate_indicator', body={
        'p_indicator_id': clean,
        'p_user_email':   user_email,
        'p_reason':       reason or None,
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
        if self._auth() is None:
            return
        request_id = uuid.uuid4().hex[:8]
        try:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            include_inactive = (params.get('include_inactive') or ['0'])[0] in ('1', 'true')
            self._send_json(200, {
                'indicators': list_indicators(include_inactive),
                'types': list(fraud_engine.INDICATOR_SOURCE_COLUMNS.keys()),
                'fuzzy_capable': sorted(fraud_engine.FUZZY_CAPABLE_TYPES),
                'fuzzy_scoring_enabled': fraud_engine.ENABLE_FUZZY_INDICATOR_SCORING,
            })
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
        _user_id, email = auth

        request_id = uuid.uuid4().hex[:8]
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 256 * 1024:
                self._send_json(400, {'error': 'Empty or oversized JSON body'})
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError as e:
                self._send_json(400, {'error': f'Invalid JSON: {e}'})
                return

            action = payload.get('action', 'create')
            try:
                if action == 'create':
                    self._send_json(200, create_indicators(payload, email))
                elif action == 'preview':
                    self._send_json(200, {
                        'preview': preview_values(
                            payload.get('indicator_type'),
                            payload.get('values') or [payload.get('value_raw')],
                        ),
                    })
                elif action == 'deactivate':
                    self._send_json(200, {
                        'result': deactivate(payload.get('id'), email,
                                             payload.get('reason')),
                    })
                else:
                    self._send_json(400, {'error': f'Unknown action: {action!r}'})
            except ValueError as e:
                self._send_json(400, {'error': str(e)})

        except ConfigError as e:
            self._send_json(500, {'error': f'ConfigError: {e}'})
        except Exception as e:
            traceback.print_exc()
            self._send_json(500, {
                'error': f'Internal error ({type(e).__name__}, ref: {request_id})',
            })
