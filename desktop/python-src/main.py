"""
Cubo Fraud Engine — desktop sidecar entry point.

Invoked by Tauri (the desktop shell) as a subprocess. Takes a CSV path on the
command line, runs the existing root-level analyze.py against it, and emits
the same JSON findings the Vercel function returns. The Tauri side pipes
stdout back to the UI.

This file deliberately does as little as possible — the real analysis logic
lives in `analyze.py` at the repo root and stays shared with the Vercel
production path. The desktop sidecar is just a thin CLI wrapper around it.

Two important behaviors for sidecar callers:
- All informational/debug logging goes to stderr. Stdout is reserved for the
  final JSON payload so Tauri can parse it without filtering noise.
- Exit code 0 = success with JSON on stdout. Non-zero = failure with a
  JSON error object on stdout (still parseable; Tauri reads it the same way).
"""

# Dev mode needs the repo root on sys.path so `import analyze` works when
# running `python main.py` directly. This block must execute BEFORE the
# `import analyze` line below.
#
# In PyInstaller frozen builds the repo root is added at build time via
# `--paths`, so analyze becomes a regular bundled module and this no-op'd
# branch is skipped.
import os
import sys

if not getattr(sys, 'frozen', False):
    _here = os.path.dirname(os.path.abspath(__file__))
    _repo_root = os.path.abspath(os.path.join(_here, '..', '..'))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

import argparse  # noqa: E402
import json      # noqa: E402
import traceback # noqa: E402

# Top-level import so PyInstaller's static analyzer follows it and bundles
# pandas/numpy + analyze.py. If this moves back inside a function/try, the
# bundle will be missing the engine at runtime (we hit that bug once).
import analyze as fraud_engine  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description='Cubo Fraud Engine — desktop sidecar')
    parser.add_argument('csv_path', help='Path to the CSV file to analyze')
    parser.add_argument('--watchlist', default=None,
                        help='Optional path to a watchlist JSON file. Phase 2 '
                             'leaves this empty; Phase 3 wires Supabase.')
    args = parser.parse_args()

    print(f'[sidecar] analyzing: {args.csv_path}', file=sys.stderr)

    if not os.path.exists(args.csv_path):
        json.dump({'error': f'CSV not found: {args.csv_path}'}, sys.stdout)
        return 3

    try:
        findings = fraud_engine.analyze(args.csv_path, watchlist_path=args.watchlist)
    except Exception as e:
        # Keep the trace in stderr (so the dev terminal shows it) but send a
        # sanitized one-line error to stdout for the UI.
        traceback.print_exc(file=sys.stderr)
        json.dump({'error': f'{type(e).__name__}: {e}'}, sys.stdout)
        return 4

    json.dump(findings, sys.stdout, default=str)
    return 0


if __name__ == '__main__':
    sys.exit(main())
