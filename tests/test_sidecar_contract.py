"""Contract test between the Tauri Rust command and the Python sidecar.

`analyze_csv` in desktop/src-tauri/src/lib.rs builds an argv and spawns the
sidecar. desktop/python-src/main.py parses that argv with argparse. Nothing
connected the two, so adding a flag on one side and forgetting the other was
silent at build time — and at runtime argparse exits 2 with usage text on
stdout, which the Rust side reports to the user as "could not parse sidecar
JSON". The real cause (an unknown flag) never appears.

That is exactly what happened when `--indicators` was added: the engine and
the Rust command both had it, the sidecar did not, and the desktop app would
have shipped unable to analyze anything at all.

Run with plain python (no pytest needed):

    python tests/test_sidecar_contract.py
"""

import ast
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

_LIB_RS   = os.path.join(_ROOT, 'desktop', 'src-tauri', 'src', 'lib.rs')
_SIDECAR  = os.path.join(_ROOT, 'desktop', 'python-src', 'main.py')
_ENGINE   = os.path.join(_ROOT, 'analyze.py')


def _flags_pushed_by_rust():
    """Long flags the Rust command pushes onto the sidecar's argv."""
    src = open(_LIB_RS, encoding='utf-8').read()
    # args.push("--watchlist".to_string()); / args.push("--indicators"...)
    return set(re.findall(r'args\.push\(\s*"(--[a-z][a-z0-9-]*)"', src))


def _flags_accepted_by(path):
    """Long flags declared on an argparse parser in `path`."""
    tree = ast.parse(open(path, encoding='utf-8').read())
    flags = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == 'add_argument'):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                    and arg.value.startswith('--'):
                flags.add(arg.value)
    return flags


def test_sidecar_accepts_every_flag_rust_sends():
    pushed = _flags_pushed_by_rust()
    accepted = _flags_accepted_by(_SIDECAR)
    missing = pushed - accepted
    assert not missing, (
        f'lib.rs passes {sorted(missing)} to the sidecar, but '
        f'desktop/python-src/main.py does not declare them. argparse would '
        f'exit 2 and the UI would show an unparseable-JSON error.'
    )


def test_rust_actually_passes_the_flags_we_expect():
    """Guard against the reverse drift: the sidecar growing a flag that
    nothing ever sends is dead weight worth noticing."""
    pushed = _flags_pushed_by_rust()
    assert '--watchlist' in pushed
    assert '--indicators' in pushed


def test_sidecar_forwards_indicators_to_the_engine():
    """Declaring the flag is not enough — it has to reach analyze()."""
    src = open(_SIDECAR, encoding='utf-8').read()
    assert 'indicators_path=' in src, (
        'main.py parses --indicators but never passes it to '
        'fraud_engine.analyze(), so the sidecar would silently ignore it.'
    )


def test_engine_cli_and_sidecar_agree():
    """The root CLI and the sidecar should expose the same analysis inputs,
    so a monthly run from the terminal behaves like the desktop app."""
    engine_flags = _flags_accepted_by(_ENGINE)
    sidecar_flags = _flags_accepted_by(_SIDECAR)
    for flag in ('--watchlist', '--indicators'):
        assert flag in engine_flags, f'{flag} missing from analyze.py CLI'
        assert flag in sidecar_flags, f'{flag} missing from the sidecar CLI'


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failures = 0
    for t in tests:
        try:
            t()
            print(f'  PASS  {t.__name__}')
        except AssertionError as e:
            failures += 1
            print(f'  FAIL  {t.__name__}: {e}')
        except Exception as e:
            failures += 1
            print(f'  ERROR {t.__name__}: {type(e).__name__}: {e}')
    print(f'\n{len(tests) - failures}/{len(tests)} passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
