"""Analyze one report CSV and sync its findings.

    python runner/run.py --from-email              # newest unread report
    python runner/run.py --url "<link from the report email>"
    python runner/run.py --csv  path/to/report.csv
    python runner/run.py --from-email --dry-run

The back half of the pipeline: find or fetch -> analyze -> de-duplicate ->
write -> delete. `--from-email` needs a one-time `runner/gmail.py --authorize`;
`--url` needs nothing but the link, because the link is unauthenticated.

What is still missing for a fully unattended cycle is the part that ASKS for a
report (runner/cubo_api.py:trigger_report, which needs the CMS token) and a
scheduler to call it on the hour.

Three guarantees this file is responsible for:

  1. **No CSV survives a run.** Deletion is in a `finally`, so it happens even
     when the analysis throws - which is exactly when a half-written file would
     otherwise be left behind.

  2. **The report URL never reaches a log.** It is unauthenticated: possession
     of the link is authorization to download a full transaction export. It is
     printed only through cubo_api.redact_url(), and never appears in an
     exception message.

  3. **Progress is recorded only after a run genuinely succeeds.** Marking an
     email consumed before the analysis worked would silently discard a
     report; recording a country's success too early would hide an outage.

Exit codes: 0 success, 1 failure. The scheduler reads them.
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import traceback
import uuid
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
for _p in (_HERE, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config          # noqa: E402
import cubo_api        # noqa: E402
import dedup           # noqa: E402
import slack           # noqa: E402
import state as runner_state   # noqa: E402
import supabase_io     # noqa: E402
import token_store     # noqa: E402  (for TokenError in classify_failure)


# Every line this tool prints is Spanish, and merchant names carry accents.
# A Windows console defaults to cp1252, which cannot encode 'á' or '→' and
# raises UnicodeEncodeError from print() - killing a run AFTER the analysis
# succeeded, and reporting it as an unrelated-looking crash. `errors` is set
# as well so no terminal encoding anywhere can ever cost a completed run.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, OSError):
        pass  # already UTF-8, or redirected to something that cannot rewrap


# ── The one genuinely shared piece ───────────────────────────────────────────
# build_findings_rows decides, for every finding, which `section` it belongs
# to, whether it enters the review queue, and what exposure it carries. The
# runner writes to the same table as the web app, so if the two ever disagreed
# the review screens would show rows of two different shapes. Importing the
# real function makes that impossible; re-implementing it would only make it
# unlikely. It is pure (no network, no Supabase) and covered by
# tests/test_persistence.py.
#
# Loaded by path because api/analyze.py shadows the root analyze.py by name.

def _load_api_analyze():
    spec = importlib.util.spec_from_file_location(
        'api_analyze', os.path.join(_ROOT, 'api', 'analyze.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_findings_rows = _load_api_analyze().build_findings_rows

import analyze as fraud_engine  # noqa: E402


# ── Output ───────────────────────────────────────────────────────────────────

def log(msg=''):
    """Timestamped so a scheduled run's output is readable after the fact."""
    if not msg:
        print()
        return
    print(f'[{datetime.now():%H:%M:%S}] {msg}', flush=True)


# ── Step 1: get a CSV ────────────────────────────────────────────────────────

class Source:
    """Where this run's CSV came from.

    `delete_after` is False for --csv: that file belongs to the user, and
    deleting their input because they asked us to read it would be wrong.
    `message_id` is set only when the link came from an email, so the message
    can be marked consumed once the run actually succeeds.
    """

    __slots__ = ('path', 'filename', 'delete_after', 'message_id')

    def __init__(self, path, filename=None, delete_after=False, message_id=None):
        self.path = path
        self.filename = filename
        self.delete_after = delete_after
        self.message_id = message_id


def _download(url: str) -> str:
    os.makedirs(config.work_dir(), exist_ok=True)
    # Named from a fresh uuid, never from the URL: the URL is the credential,
    # and a filename built from it would leak into directory listings, error
    # messages and backups.
    dest = os.path.join(config.work_dir(), f'report-{uuid.uuid4().hex}.csv')
    log(f'Descargando {cubo_api.redact_url(url)}')
    try:
        written = cubo_api.download_csv(url, dest)
    except Exception:
        # A download that dies halfway leaves a partial file, and nothing
        # downstream will ever own it - process() only cleans up files it was
        # handed. Transaction data must not accumulate in a temp directory.
        if os.path.exists(dest):
            try:
                os.remove(dest)
            except OSError:
                pass
        raise
    log(f'  {written:,} bytes')
    return dest


def acquire_csv(args) -> Source:
    if args.csv:
        path = os.path.abspath(args.csv)
        if not os.path.isfile(path):
            raise FileNotFoundError(f'No such CSV: {path}')
        return Source(path, os.path.basename(path), delete_after=False)

    if args.from_email:
        import gmail  # noqa: PLC0415  (only this mode needs the OAuth stack)

        log('Buscando el reporte más reciente en el correo...')
        found = gmail.find_report(skip_processed=True)
        if not found:
            raise cubo_api.CmsError(
                'No hay ningún correo de reporte sin procesar. Pide un '
                'reporte nuevo, o usa --url con un enlace concreto.')
        message_id, url, received = found
        when = f'{received:%Y-%m-%d %H:%M} UTC' if received else 'sin fecha'
        log(f'  mensaje {message_id} ({when})')
        return Source(_download(url), delete_after=True, message_id=message_id)

    return Source(_download(args.url), delete_after=True)


# ── Step 2: analyze ──────────────────────────────────────────────────────────

def run_analysis(csv_path: str, staging: str) -> dict:
    """Run the engine exactly as the CLI does, with live watchlist+indicators.

    The watchlist and indicator files are staged in the same temp directory as
    everything else and wiped with it. The indicator file holds confirmed-fraud
    personal data, so it must not outlive the run any more than the CSV does.
    """
    log('Cargando watchlist e indicadores desde Supabase...')
    wl = supabase_io.load_watchlist()
    indicators = supabase_io.load_indicators()
    log(f'  {len(wl["merchants"])} comercios, {len(wl["cards"])} tarjetas, '
        f'{len(indicators)} indicadores activos')

    wl_path  = os.path.join(staging, 'watchlist.json')
    ind_path = os.path.join(staging, 'indicators.json')
    with open(wl_path, 'w', encoding='utf-8') as fh:
        json.dump(wl, fh, default=str)
    with open(ind_path, 'w', encoding='utf-8') as fh:
        json.dump(indicators, fh, default=str)

    log('Analizando...')
    return fraud_engine.analyze(csv_path,
                                watchlist_path=wl_path,
                                indicators_path=ind_path)


def describe(findings: dict) -> str:
    s = findings.get('summary') or {}
    currency = s.get('currency') or 'UNKNOWN'
    source = s.get('currency_source') or 'desconocido'
    rng = s.get('date_range') or {}
    return (
        f'  {s.get("unique_transactions", 0):,} transacciones únicas'
        f' ({rng.get("start")} → {rng.get("end")})\n'
        f'  país {source}, moneda {currency}\n'
        f'  {s.get("total_critical_findings", 0)} críticos, '
        f'{s.get("total_monitor_findings", 0)} monitor, '
        f'{s.get("total_suspicious_rejected_merchants", 0)} zero-settlement'
    )


def audit_filename(findings: dict) -> str:
    """A readable name for a run that had no file, shown on /historial.

    Built from what the CSV actually contained rather than from what we asked
    for - principle 4 in PLAN.md. A mislabelled request can therefore never
    produce a mislabelled run.
    """
    s = findings.get('summary') or {}
    rng = s.get('date_range') or {}
    country = (s.get('currency_source') or 'desconocido').replace(' ', '-')
    return f'auto-{country}-{rng.get("start")}_{rng.get("end")}.csv'


# ── Step 3: de-duplicate and write ───────────────────────────────────────────

def sync(findings: dict, run_id: str, dry_run: bool = False):
    """Apply the dedup decision to every finding.

    Returns `(counts, events)` - the action counts for the log, and the
    subset of decisions worth telling a human about. The events are collected
    here rather than recomputed later because this is the only place that
    holds all three of (existing row, new finding, decision) at once; working
    them out afterwards from the database would mean re-deriving a judgement
    dedup.py has already made, with a second chance to make it differently.

    One lookup per finding. That is a round-trip per merchant per run - a few
    dozen at most - and keeps the "which row is the open one?" ordering in
    lookup_open_finding rather than duplicating it here.
    """
    ordered, rows = build_findings_rows(run_id, findings)
    if not ordered:
        log('Sin hallazgos que sincronizar.')
        return dedup.summarize([]), []

    now = datetime.now(timezone.utc)
    decisions = []
    events = []
    to_insert = []
    seen_at = {}      # finding_key -> index into `rows`
    insert_at = {}    # finding_key -> index into `to_insert`

    for idx, ((finding, section), row) in enumerate(zip(ordered, rows)):
        key = dedup.finding_key(finding.get('company_name'), section)

        # Two findings with the same key in ONE run should be impossible: the
        # engine emits one finding per merchant per section. If it ever
        # happens, inserting both would create exactly the duplicate pair
        # de-duplication exists to prevent, so say so loudly and keep one.
        if key in seen_at:
            log(f'  ! {finding.get("company_name")} aparece dos veces en '
                f'la sección {section}; se conserva el de mayor puntaje')
            previous = rows[seen_at[key]]
            if (row.get('risk_score') or 0) > (previous.get('risk_score') or 0):
                seen_at[key] = idx
                if key in insert_at:
                    to_insert[insert_at[key]] = row
            continue
        seen_at[key] = idx

        existing = supabase_io.lookup_open_finding(key)
        decision = dedup.decide(existing, finding, now=now)
        decisions.append(decision)

        label = f'{finding.get("company_name")} [{section}]'
        log(f'  {decision.action:8} {label}: {decision.reason}')

        # Collected even on a dry run, so `--dry-run` can show exactly what
        # would have been announced without announcing it.
        event = slack.notable(decision, finding, section)
        if event:
            events.append(event)

        if dry_run:
            continue

        if decision.action == dedup.INSERT:
            insert_at[key] = len(to_insert)
            to_insert.append(row)
        elif decision.action == dedup.UPDATE:
            supabase_io.touch_finding(decision.target_id, row, decision.promote)
        elif decision.action == dedup.REOPEN:
            supabase_io.reopen_finding(
                decision.target_id, finding.get('risk_score'),
                finding.get('confidence'), decision.reason)
        elif decision.action == dedup.SUPPRESS:
            # An accepted merchant still doing it is worth recording even
            # though the alert is suppressed - "still happening" is signal.
            if (existing or {}).get('review_status') == 'accepted':
                supabase_io.touch_watchlist_merchant(
                    finding.get('company_name'), finding.get('risk_score'),
                    run_id)

    if to_insert and not dry_run:
        inserted = supabase_io.insert_findings(to_insert)
        log(f'  {len(inserted)} hallazgos nuevos insertados')

    return dedup.summarize(decisions), events


# ── Step 4: remember what happened ───────────────────────────────────────────

def country_code_of(findings: dict):
    """Which country this CSV was for, as SV / PA / GT, or None.

    Derived from `currency_source`, which analyze.py sets from the
    `country_name` column - the file itself, never the report we asked for.
    A mislabelled request therefore cannot produce a mislabelled run.

    Uses the engine's own normalizer rather than a second copy of it, so the
    two can never disagree about what 'Panamá' folds to.
    """
    source = (findings.get('summary') or {}).get('currency_source')
    if not source:
        return None
    for code, meta in config.COUNTRIES.items():
        if fraud_engine._normalize_country(meta['name']) == source:
            return code
    return None


def _record_progress(source: Source, findings: dict):
    """Mark the email consumed and record that this country succeeded.

    Both happen only after a run genuinely finished. Marking a message
    processed before the analysis worked would silently discard a report; and
    a country's last-success time is the only thing that distinguishes "a
    quiet week" from "the runner has been dead for a week".
    """
    st = runner_state.load()
    changed = False

    if source.message_id:
        st = runner_state.mark_processed(source.message_id, st)
        changed = True

    code = country_code_of(findings)
    if code:
        st = runner_state.record_success(code, state=st)
        changed = True
    else:
        log('AVISO: no se pudo determinar el país del CSV; no se registra '
            'el avance de este país.')

    if changed:
        try:
            runner_state.save(st)
        except OSError as e:
            # Bookkeeping. Losing it costs at most one duplicate report.
            log(f'AVISO: no se pudo guardar el estado ({e}).')


# ── Entry point ──────────────────────────────────────────────────────────────

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog='runner/run.py',
        description='Analyze one Cubo report CSV and sync its findings.')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--url', help='CSV link from the report email')
    src.add_argument('--csv', help='local CSV file (not deleted afterwards)')
    src.add_argument('--from-email', action='store_true',
                     help='find the newest unprocessed report in Gmail')
    p.add_argument('--dry-run', action='store_true',
                   help='analyze and show the de-dup decisions, write nothing')
    p.add_argument('--source', default='auto', choices=['auto', 'manual'],
                   help="how /historial labels this run (default: auto)")
    return p.parse_args(argv)


def process(source: Source, dry_run: bool = False,
            run_source: str = 'auto', cycle_id: str = None) -> dict:
    """Analyze one acquired CSV and sync it. Returns the action counts.

    Split out of main() so the scheduled cycle can reuse the pipeline instead
    of carrying a second copy of it. The cleanup is in here rather than in the
    caller so that EVERY caller gets it - a `finally` that only one entry
    point remembered to write is the kind that stops running the day someone
    adds a second entry point.

    `cycle_id` is passed only by the scheduled cycle (migration 0012). The
    link is written here, as soon as the run row exists, rather than by the
    caller at the end: a cycle that analyses successfully and then fails
    while syncing still shows which run it produced, which is exactly the
    case where knowing the run id is worth something.
    """
    staging = tempfile.mkdtemp(prefix='cubo-runner-')
    try:
        findings = run_analysis(source.path, staging)
        log('Análisis completo:')
        print(describe(findings))

        if dry_run:
            log('DRY RUN - no se escribe nada en Supabase')
            # build_findings_rows needs a run_id shaped like the real thing.
            run_id = str(uuid.UUID(int=0))
        else:
            run_id = supabase_io.insert_run(
                findings['summary'],
                source.filename or audit_filename(findings),
                source=run_source)
            log(f'Run registrado: {run_id}')
            supabase_io.cycle_attach_run(cycle_id, run_id)

        counts, events = sync(findings, run_id, dry_run=dry_run)

        if not dry_run:
            supabase_io.record_indicator_hits(findings)
            _record_progress(source, findings)
            # After the writes, never before: an alert about a finding that
            # then failed to save would send someone to look for something
            # that is not in the queue.
            _announce(findings, events)
        elif events:
            log(f'DRY RUN - se habrían anunciado {len(events)} hallazgo(s) '
                f'en Slack')

        log()
        log(f'nuevos {counts[dedup.INSERT]} · '
            f'actualizados {counts[dedup.UPDATE]} · '
            f'reabiertos {counts[dedup.REOPEN]} · '
            f'silenciados {counts[dedup.SUPPRESS]}')
        return counts

    finally:
        # Runs even when the analysis threw - which is exactly when a
        # half-processed file would otherwise be left on disk.
        if source.delete_after and os.path.exists(source.path):
            try:
                os.remove(source.path)
                log('CSV eliminado.')
            except OSError as e:
                log(f'AVISO: no se pudo borrar el CSV ({e}). Bórralo a mano: '
                    f'{source.path}')
        shutil.rmtree(staging, ignore_errors=True)


def _announce(findings: dict, events: list):
    """Send the cycle's news to Slack. Best-effort and quiet when off.

    The country comes from the CSV's own `country_name` column, never from
    the report we asked for, so a mislabelled request cannot produce a
    mislabelled alert - and ops people who watch one country can trust the
    label they filter on.
    """
    # Every exit here says why. A cycle with nothing new to announce and a
    # cycle that failed to announce used to look identical in the log - an
    # absent line - and telling them apart meant reading the dedup counts and
    # knowing that notable() stays quiet for a re-detection. That ambiguity
    # cost a real "Slack stopped working" investigation on 2026-09-09, when
    # the answer was two consecutive cycles of `nuevos 0`.
    if not events:
        log('Slack: sin novedades — lo detectado ya estaba en la cola')
        return
    country = country_code_of(findings)
    if not config.slack_enabled(country):
        log(f'Slack: desactivado para {(country or "?").upper()}')
        return
    if slack.send_findings(country, events, findings.get('summary')):
        log(f'Slack: {len(events)} hallazgo(s) anunciados')
    else:
        # post() already printed the HTTP reason; this says what was lost.
        log(f'Slack: NO se pudo anunciar {len(events)} hallazgo(s)')


def classify_failure(exc):
    """(outcome, label, detail) for one exception.

    ONE taxonomy, used by three things that must never disagree: the line in
    the cron log, the exit code cron reads, and the `outcome` stored on the
    runner_cycles row the dashboard renders (migration 0012). When these
    drifted apart, a token that had expired and a CMS that was refusing our
    headers both arrived as a bare RuntimeError, and nothing downstream could
    tell them apart - which is the whole reason the outcome column exists.

    `detail` may be STORED and displayed in the app, so it carries the same
    discipline as the log: never a report URL (possession of one is
    authorization to download a full transaction export), never a service
    key, never CSV row data.

    Order matters. CmsError, SupabaseError, TokenError and ConfigError are
    all RuntimeError subclasses, so each has to be tested before the generic
    RuntimeError branch or it would be swallowed by it.
    """
    if isinstance(exc, cubo_api.CmsError):
        return 'cms_error', 'ERROR de descarga', str(exc)

    if isinstance(exc, supabase_io.SupabaseError):
        # PLAN.md: not worth retrying. The next run analyzes an overlapping
        # window and covers whatever this one missed.
        return 'supabase_error', 'ERROR de Supabase', str(exc)

    if isinstance(exc, token_store.TokenError):
        return 'token_error', 'ERROR', str(exc)

    if isinstance(exc, config.ConfigError):
        return 'config_error', 'ERROR', str(exc)

    # gmail.py is imported lazily - only `--from-email` and the scheduled
    # cycle pay for the OAuth stack. Reaching into sys.modules keeps that
    # property: a GmailError cannot exist unless the module is already
    # loaded, so if it is absent there is nothing to classify.
    _gmail = sys.modules.get('gmail')
    if _gmail is not None and isinstance(exc, _gmail.GmailError):
        return 'gmail_error', 'ERROR de Gmail', str(exc)

    if isinstance(exc, (FileNotFoundError, RuntimeError, ValueError)):
        return 'unexpected', 'ERROR', str(exc)

    # Pandas exceptions can embed CSV row values in their messages, so only
    # the type name is safe to log or store.
    return 'unexpected', 'ERROR inesperado', type(exc).__name__


def report_failure(exc) -> int:
    """Turn an exception into an exit code and one readable line.

    Shared with the scheduled cycle so a cron log reads the same either way.
    """
    outcome, label, detail = classify_failure(exc)
    log(f'{label}: {detail}')
    if outcome == 'unexpected' and label == 'ERROR inesperado':
        # The message was withheld above because it could carry CSV values.
        # The traceback goes to stderr, which is the cron log on the Pi and
        # nowhere shared.
        traceback.print_exc(file=sys.stderr)
    return 1


def main(argv=None) -> int:
    args = parse_args(argv)

    # Only what this mode actually uses. Neither URL mode touches the CMS API
    # or needs a CMS token: the report link is unauthenticated.
    needed = ['supabase']
    if args.url or args.from_email:
        needed.append('url')
    if args.from_email:
        needed += ['gmail', 'mail']
    config.validate(*needed)

    try:
        source = acquire_csv(args)
    except Exception as e:                                  # noqa: BLE001
        return report_failure(e)

    try:
        process(source, dry_run=args.dry_run, run_source=args.source)
        return 0
    except Exception as e:                                  # noqa: BLE001
        return report_failure(e)


if __name__ == '__main__':
    sys.exit(main())
