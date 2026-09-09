"""Everything the runner reads from and writes to Supabase.

Deliberately a mirror of `api/analyze.py`'s Supabase layer rather than an
import of it: Vercel deploys each function file independently, so that module
cannot import shared code, and copying its *shape* here keeps the two obviously
comparable. The one thing that is genuinely shared is `build_findings_rows` -
see runner/run.py for why that one is imported rather than duplicated.

urllib, not `requests` or `supabase-py`, so the runner needs nothing beyond the
engine's own dependencies (pandas + numpy). It also works with both the legacy
`eyJ...` service keys and the newer `sb_secret_...` format, which supabase-py
did not at the time this was written.

Every function here is I/O. The decisions are in dedup.py, which is pure.
"""

import json
import urllib.error
import urllib.request

import config


class SupabaseError(RuntimeError):
    """A Supabase failure whose message is safe to print.

    Never contains the service key (only a 6-character prefix, enough to tell
    "wrong key" from "right key, wrong permissions") and never contains CSV
    row data.
    """


# ── Transport ────────────────────────────────────────────────────────────────

def sb_rest(method: str, path: str, body=None, prefer: str = '', timeout: int = 30):
    """Call PostgREST at /rest/v1/<path> with the service-role key."""
    if not config.SUPABASE_URL or not config.SUPABASE_SERVICE_KEY:
        raise SupabaseError(
            'Supabase is not configured. Set NEXT_PUBLIC_SUPABASE_URL and '
            'SUPABASE_SERVICE_ROLE_KEY in runner/.env'
        )

    url = f'{config.SUPABASE_URL.rstrip("/")}/rest/v1/{path}'
    headers = {
        'apikey':        config.SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {config.SUPABASE_SERVICE_KEY}',
        'Content-Type':  'application/json',
    }
    if prefer:
        headers['Prefer'] = prefer

    data = json.dumps(body, default=str).encode('utf-8') if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            return json.loads(content) if content else None
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode('utf-8', errors='replace')[:400]
        except Exception:
            detail = '(no body)'
        hint = config.SUPABASE_SERVICE_KEY[:6] + '...'
        raise SupabaseError(
            f'Supabase {method} {path} failed (HTTP {e.code}, key {hint}): {detail}'
        ) from None
    except urllib.error.URLError as e:
        raise SupabaseError(f'Could not reach Supabase: {e.reason}') from None


def sb_rpc(name: str, body: dict, timeout: int = 30):
    return sb_rest('POST', f'rpc/{name}', body=body, timeout=timeout)


# ── Reads: the inputs analyze.py needs ───────────────────────────────────────

def load_watchlist() -> dict:
    """Build the dict shape analyze.py expects from the two watchlist tables.

    The explicit limit overrides PostgREST's 1000-row default. Without it the
    watchlist silently truncates as it grows and the detectors quietly lose
    their "known offender" signal - a failure that looks like a clean report.
    """
    # `removed_at=is.null` is load-bearing, not tidiness: a merchant taken
    # off the watchlist (migration 0014) must stop matching, or removal is
    # purely cosmetic and a wrongly-frozen merchant stays flagged forever.
    merchants = sb_rest('GET', 'watchlist_merchants?select=*&removed_at=is.null&limit=100000') or []
    cards     = sb_rest('GET', 'watchlist_cards?select=*&removed_at=is.null&limit=100000') or []

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
        wl['cards'][c['card_key']] = {
            'first_flagged': c['first_flagged'],
            'last_flagged':  c['last_flagged'],
            'flag_count':    c.get('flag_count', 1),
        }
    return wl


def load_indicators() -> list:
    """Active confirmed-fraud indicators, shaped for analyze.py."""
    return sb_rest(
        'GET',
        'fraud_indicators'
        '?select=id,indicator_type,value_raw,value_norm,match_mode,source,'
        'source_company_name,added_by_email,added_at,expires_at,active,notes'
        '&active=eq.true'
        '&limit=100000',
    ) or []


# ── Writes: the run audit row ────────────────────────────────────────────────

def insert_run(summary: dict, csv_filename: str, source: str = 'auto',
               run_by_email: str = None) -> str:
    """Insert the analysis_runs row and return its id.

    `source` is what lets anyone later ask "was this my upload or the robot's?"
    - the first question when a number looks wrong (migration 0010).
    """
    date_range = summary.get('date_range') or {}
    payload = {
        'run_by_email':   run_by_email or config.RUN_BY_EMAIL,
        'csv_filename':   csv_filename,
        'csv_date_start': date_range.get('start'),
        'csv_date_end':   date_range.get('end'),
        'total_rows':                    summary.get('total_rows'),
        'unique_transactions':           summary.get('unique_transactions'),
        'critical_findings_count':       summary.get('total_critical_findings'),
        'monitor_findings_count':        summary.get('total_monitor_findings'),
        'zero_settlement_findings_count':
            summary.get('total_suspicious_rejected_merchants'),
        # Legacy column name from when the engine only handled Panama files;
        # it holds whatever currency the CSV is denominated in.
        'chargeback_exposure_usd':      summary.get('estimated_chargeback_exposure'),
        'chargeback_exposure_currency': summary.get('currency'),
        # The country the currency was derived from (migration 0009). Country
        # reaches storage nowhere else, which is exactly why the four-month
        # currency bug left no trace to diagnose from.
        'currency_source':              summary.get('currency_source'),
        'source':                       source,
        'summary':                      summary,
    }
    res = sb_rest('POST', 'analysis_runs', body=payload,
                  prefer='return=representation')
    if not res:
        raise SupabaseError('analysis_runs insert returned no row')
    return res[0]['id']


# ── Writes: findings ─────────────────────────────────────────────────────────

def lookup_open_finding(finding_key: str):
    """The current finding for this key, or None.

    Returns closed findings too (accepted / rejected) - the runner needs them
    in order to suppress, not just to update.
    """
    rows = sb_rpc('lookup_open_finding', {'p_finding_key': finding_key})
    if not rows:
        return None
    # PostgREST returns a list for a set-returning function.
    return rows[0] if isinstance(rows, list) else rows


def insert_findings(rows: list) -> list:
    """Insert new findings. Returns the inserted rows, in the order sent.

    `finding_key`, `first_seen_at` and `last_seen_at` are deliberately absent
    from the payload: migration 0011 makes the first a generated column and
    defaults the other two, so the database fills all three regardless of
    which of the three clients wrote the row.
    """
    if not rows:
        return []
    inserted = sb_rest('POST', 'findings_history', body=rows,
                       prefer='return=representation') or []

    # If migration 0011 has NOT been applied, finding_key comes back null:
    # nothing populates it, so lookup_open_finding matches nothing, so every
    # run re-inserts every finding. Sixteen copies of each within two days,
    # and no error anywhere - the runner would look like it was working.
    #
    # The returned representation already contains the column, so this costs
    # nothing and turns the worst failure mode into a one-line message.
    if inserted and not inserted[0].get('finding_key'):
        raise SupabaseError(
            'findings_history.finding_key came back empty, so de-duplication '
            'cannot work and every run would re-insert every finding.\n'
            'Apply supabase/migrations/0011_finding_key_generated.sql in the '
            'Supabase SQL Editor, then run this again.'
        )
    return inserted


def touch_finding(finding_id: str, row: dict, promote: bool = False) -> dict:
    """Refresh an already-open finding in place, bumping times_seen.

    `row` is the same dict that would have been inserted, so a re-detected
    finding can never end up showing a new score beside stale evidence.
    """
    return sb_rpc('touch_finding', {
        'p_id':      finding_id,
        'p_row':     row,
        'p_promote': bool(promote),
    })


def reopen_finding(finding_id: str, risk_score, confidence, reason: str) -> dict:
    """Re-open a rejected finding that escalated. The original rejection stays
    in review_notes rather than being erased."""
    return sb_rpc('reopen_finding', {
        'p_id':         finding_id,
        'p_risk_score': risk_score,
        'p_confidence': confidence,
        'p_reason':     reason,
    })


def touch_watchlist_merchant(company_name: str, risk_score, run_id: str = None):
    """Record that an already-accepted merchant is still doing it.

    Best-effort: this is bookkeeping on a suppressed alert, and failing it must
    not fail a run that otherwise succeeded.
    """
    try:
        return sb_rpc('touch_watchlist_merchant', {
            'p_company_name': company_name,
            'p_risk_score':   risk_score,
            'p_run_id':       run_id,
        })
    except SupabaseError as e:
        print(f'  [watchlist] no se pudo actualizar last_flagged: {e}')
        return None


def record_indicator_hits(findings: dict):
    """Bump hit_count / last_hit_at for every indicator that fired.

    Best-effort by the same reasoning as api/analyze.py: the analysis already
    succeeded and the findings are already written, so a bookkeeping failure
    must not turn a good run into a failed one.
    """
    matches = findings.get('indicator_matches') or []
    for match in matches:
        ids = sorted({h.get('indicator_id') for h in match.get('hits', [])
                      if h.get('indicator_id')})
        if not ids:
            continue
        try:
            sb_rpc('record_indicator_hits', {
                'p_indicator_ids': ids,
                'p_company_name':  match.get('company_name'),
            })
        except SupabaseError as e:
            # Log the shape of the failure, never the indicator values - they
            # are confirmed-fraud personal data.
            print(f'  [indicadores] no se registraron los hits: {type(e).__name__}')
            return


# ── Runner cycle bookkeeping ─────────────────────────────────────────────────
# One row per scheduled cycle, whatever the outcome (migration 0012). This is
# what lets the app tell a silently-broken runner apart from a quiet fraud
# week without anyone SSH-ing into the Pi.
#
# Every function here is BEST-EFFORT and returns rather than raises, which is
# the opposite of the rest of this module. The reason is narrow: these writes
# are bookkeeping ABOUT a cycle, so letting one fail the cycle it is
# describing would be perverse - and worse, a health-recording failure would
# then masquerade as the failure it was trying to record. Same reasoning as
# touch_watchlist_merchant and record_indicator_hits above.
#
# The cost is a real blind spot, stated plainly: if Supabase is unreachable we
# cannot record "Supabase is unreachable". The cycle still shows as a gap in
# the timeline, which is the honest representation of "we do not know".

def cycle_start(country_code: str, window_start=None, window_end=None,
                token_expires_at=None, host: str = None):
    """Open a cycle row and return its id, or None if it could not be written.

    Written BEFORE the work starts, so a cycle that dies mid-flight leaves a
    row stuck in 'running'. That is deliberately distinguishable from no row
    at all: one means the process was killed or the Pi lost power, the other
    means cron never fired, and the fixes have nothing in common.
    """
    payload = {
        'country_code':     country_code,
        'outcome':          'running',
        'window_start':     window_start,
        'window_end':       window_end,
        'token_expires_at': token_expires_at,
        'host':             host,
    }
    try:
        res = sb_rest('POST', 'runner_cycles', body=payload,
                      prefer='return=representation')
    except SupabaseError as e:
        print(f'  [ciclo] no se pudo registrar el inicio: {e}')
        return None
    if not res:
        return None
    return res[0].get('id')


def cycle_finish(cycle_id: str, outcome: str, detail: str = None):
    """Close a cycle row with its outcome.

    A failure here is worth a loud warning rather than silence: the row stays
    'running', and the dashboard will report a cycle that died mid-flight when
    in fact it finished cleanly. A wrong alarm is better than a missing one,
    but only if the log says which happened.
    """
    if not cycle_id:
        return False
    try:
        # An RPC rather than a PATCH so `finished_at` comes from the database
        # clock, the same one that stamped started_at. Sending the Pi's own
        # timestamp instead would let clock skew produce a negative duration,
        # which reads as a bug in the dashboard rather than as drift here.
        sb_rpc('finish_runner_cycle', {
            'p_id':      cycle_id,
            'p_outcome': outcome,
            'p_detail':  (detail or None),
        })
        return True
    except SupabaseError as e:
        print(f'  [ciclo] AVISO: el ciclo terminó como {outcome} pero no se '
              f'pudo registrar, así que quedará como "en curso": {e}')
        return False


def pending_summary():
    """(count, oldest_first_seen_at) for the Critical review queue.

    A count alone does not move anyone. "12 pendientes, el más antiguo lleva 4
    días" does, because the second half is the part that sounds wrong.

    Uses PostgREST's exact count rather than fetching rows: the runner has no
    business pulling merchant names it will not use, and the queue can be large.
    """
    try:
        rows = sb_rest(
            'GET',
            'findings_history'
            '?select=first_seen_at'
            '&review_status=eq.pending'
            '&confidence=eq.Critical'
            '&order=first_seen_at.asc'
            '&limit=1',
            prefer='count=exact',
        )
    except SupabaseError as e:
        print(f'  [slack] no se pudo leer la cola de pendientes: {e}')
        return None, None

    oldest = (rows or [{}])[0].get('first_seen_at') if rows else None
    # PostgREST returns the total in Content-Range, which sb_rest does not
    # expose. A second cheap request is simpler than threading headers through
    # the whole transport for one caller.
    try:
        total_rows = sb_rest(
            'GET',
            'findings_history?select=id'
            '&review_status=eq.pending&confidence=eq.Critical&limit=1000',
        ) or []
    except SupabaseError:
        return None, None
    return len(total_rows), oldest


def runner_health():
    """Per-country health, as the dashboard sees it (migration 0012).

    The runner reads its OWN health record to decide whether a failure is
    worth interrupting anyone about. Deriving that here instead - "was the
    last one bad?" - would alert on every single miss, and the overlapping
    windows absorb a single miss by design.

    Returns [] rather than raising: this only ever feeds a notification
    decision, and being unable to check must not turn into a second failure
    on top of the one being checked.
    """
    try:
        return sb_rpc('runner_health', {}) or []
    except SupabaseError as e:
        print(f'  [ciclo] no se pudo leer runner_health: {e}')
        return []


def cycle_attach_run(cycle_id: str, run_id: str):
    """Point a cycle row at the analysis_runs row it produced.

    Called as soon as the run exists rather than at the end of the cycle, so
    that a cycle which analyses successfully and then fails while syncing
    still shows which run it created.
    """
    if not cycle_id or not run_id:
        return False
    try:
        sb_rest('PATCH', f'runner_cycles?id=eq.{cycle_id}',
                body={'run_id': run_id})
        return True
    except SupabaseError as e:
        print(f'  [ciclo] no se pudo enlazar el run {run_id}: {e}')
        return False
