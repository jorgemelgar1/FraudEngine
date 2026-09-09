"""Manual-URL mode: analyze one report CSV and sync its findings.

    python runner/run.py --url "<link from the report email>"
    python runner/run.py --csv  path/to/report.csv
    python runner/run.py --url "<link>" --dry-run

This is step 4 of runner/PLAN.md and the whole back half of the pipeline:
download -> analyze -> de-duplicate -> write -> delete. The only thing it does
not do is read your mailbox, which is step 5. Paste the link yourself and
everything after it is already automatic.

Two guarantees this file is responsible for:

  1. **No CSV survives a run.** Deletion is in a `finally`, so it happens even
     when the analysis throws - which is exactly when a half-written file would
     otherwise be left behind.

  2. **The report URL never reaches a log.** It is unauthenticated: possession
     of the link is authorization to download a full transaction export. It is
     printed only through cubo_api.redact_url(), and never appears in an
     exception message.

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
import supabase_io     # noqa: E402


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

def acquire_csv(args):
    """Return (csv_path, filename_for_the_audit_row, delete_after).

    `delete_after` is False for --csv: that file belongs to the user and
    deleting their input because they asked us to read it would be wrong.
    """
    if args.csv:
        path = os.path.abspath(args.csv)
        if not os.path.isfile(path):
            raise FileNotFoundError(f'No such CSV: {path}')
        return path, os.path.basename(path), False

    os.makedirs(config.work_dir(), exist_ok=True)
    # Named from a fresh uuid, never from the URL: the URL is the credential,
    # and a filename built from it would leak into directory listings, error
    # messages and backups.
    dest = os.path.join(config.work_dir(), f'report-{uuid.uuid4().hex}.csv')

    log(f'Descargando {cubo_api.redact_url(args.url)}')
    written = cubo_api.download_csv(args.url, dest)
    log(f'  {written:,} bytes')
    return dest, None, True


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

def sync(findings: dict, run_id: str, dry_run: bool = False) -> dict:
    """Apply the dedup decision to every finding. Returns action counts.

    One lookup per finding. That is a round-trip per merchant per run - a few
    dozen at most - and keeps the "which row is the open one?" ordering in
    lookup_open_finding rather than duplicating it here.
    """
    ordered, rows = build_findings_rows(run_id, findings)
    if not ordered:
        log('Sin hallazgos que sincronizar.')
        return dedup.summarize([])

    now = datetime.now(timezone.utc)
    decisions = []
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

    return dedup.summarize(decisions)


# ── Entry point ──────────────────────────────────────────────────────────────

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog='runner/run.py',
        description='Analyze one Cubo report CSV and sync its findings.')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--url', help='CSV link from the report email')
    src.add_argument('--csv', help='local CSV file (not deleted afterwards)')
    p.add_argument('--dry-run', action='store_true',
                   help='analyze and show the de-dup decisions, write nothing')
    p.add_argument('--source', default='auto', choices=['auto', 'manual'],
                   help="how /historial labels this run (default: auto)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    # Only what this mode actually uses. Manual-URL mode never touches the CMS
    # API and needs no token: the report link is unauthenticated.
    needed = ['supabase'] if args.csv else ['url', 'supabase']
    config.validate(*needed)

    csv_path = None
    delete_after = False
    staging = tempfile.mkdtemp(prefix='cubo-runner-')

    try:
        csv_path, filename, delete_after = acquire_csv(args)
        findings = run_analysis(csv_path, staging)
        log('Análisis completo:')
        print(describe(findings))

        run_id = 'dry-run'
        if args.dry_run:
            log('DRY RUN - no se escribe nada en Supabase')
            # build_findings_rows needs a run_id shaped like the real thing.
            run_id = str(uuid.UUID(int=0))
        else:
            run_id = supabase_io.insert_run(
                findings['summary'],
                filename or audit_filename(findings),
                source=args.source)
            log(f'Run registrado: {run_id}')

        counts = sync(findings, run_id, dry_run=args.dry_run)

        if not args.dry_run:
            supabase_io.record_indicator_hits(findings)

        log()
        log(f'nuevos {counts[dedup.INSERT]} · '
            f'actualizados {counts[dedup.UPDATE]} · '
            f'reabiertos {counts[dedup.REOPEN]} · '
            f'silenciados {counts[dedup.SUPPRESS]}')
        return 0

    except cubo_api.CmsError as e:
        log(f'ERROR de descarga: {e}')
        return 1
    except supabase_io.SupabaseError as e:
        # PLAN.md: a Supabase failure is not worth retrying here. The next run
        # analyzes an overlapping window and covers whatever this one missed.
        log(f'ERROR de Supabase: {e}')
        return 1
    except Exception as e:                                  # noqa: BLE001
        # Pandas exceptions can embed CSV row values in their messages, so the
        # type is printed but the traceback goes nowhere near a shared log.
        log(f'ERROR inesperado: {type(e).__name__}')
        traceback.print_exc(file=sys.stderr)
        return 1

    finally:
        # Runs even when the analysis threw - which is exactly when a
        # half-processed file would otherwise be left on disk.
        if delete_after and csv_path and os.path.exists(csv_path):
            try:
                os.remove(csv_path)
                log('CSV eliminado.')
            except OSError as e:
                log(f'AVISO: no se pudo borrar el CSV ({e}). Bórralo a mano: '
                    f'{csv_path}')
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
