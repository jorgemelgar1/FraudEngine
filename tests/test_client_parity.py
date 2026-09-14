#!/usr/bin/env python3
"""Contract test: the two clients ask the database for the same things.

Self-contained: run with plain `python tests/test_client_parity.py`
(no pytest required), or via `pytest tests/test_client_parity.py`.

There are two front ends over one database — the Vercel web app (through
api/findings.py) and the Tauri desktop app (through desktop/src/lib/findings.ts).
The desktop file already carried the instruction:

    "Mirrors api/findings.py:_LIST_SELECT so the desktop pages render the same
     fields as the Vercel ones. Keep this in sync if the Vercel select ever
     grows; otherwise the two clients silently disagree on what data is
     available."

A comment cannot enforce that, and it did not. The desktop select grew
`times_seen`, `first_seen_at`, `source` and `currency_source`; the web one did
not. So the browser queue could not tell an analyst that a finding had been
seen three times, which country it belonged to, or whether it came from the
runner — while the desktop showed all of it from the same rows. Nothing looked
broken. The web app simply never asked.

This file turns that comment into a check. It compares the column sets, not the
formatting, so either side may reorder or re-wrap freely.
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

_WEB = os.path.join(_ROOT, 'api', 'findings.py')
_DESKTOP = os.path.join(_ROOT, 'desktop', 'src', 'lib', 'findings.ts')
_SHARED = os.path.join(_ROOT, 'shared')


def _read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


# Matches a real import STATEMENT at the start of a line, not the word "import"
# wherever it appears. The first version of this scanned the whole file, so the
# sentence "neither can import the other's" in a comment matched, swallowed the
# newlines up to the next `from '...'`, and reported the wrong thing about the
# wrong line.
_IMPORT_RE = re.compile(
    r"^\s*import\s+(?P<type>type\s+)?[^;]*?from\s+'(?P<target>[^']+)'",
    re.M)


def _imports_of(path):
    """(is_type_only, module) for every import statement in a file."""
    return [(bool(m.group('type')), m.group('target'))
            for m in _IMPORT_RE.finditer(_read(path))]


def _split_top_level(flat):
    """Split a PostgREST select on commas that are not inside parentheses, so
    an embedded join like analysis_runs(a,b,c) stays one item."""
    out, depth, buf = [], 0, ''
    for ch in flat:
        if ch == ',' and depth == 0:
            out.append(buf)
            buf = ''
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        buf += ch
    if buf:
        out.append(buf)
    return [c for c in out if c]


def _web_columns():
    src = _read(_WEB)
    m = re.search(r'_LIST_SELECT = \((.*?)\n\)', src, re.S)
    assert m, '_LIST_SELECT moved or was renamed in api/findings.py'
    return set(_split_top_level(re.sub(r"[\n'\s]", '', m.group(1))))


def _desktop_columns():
    src = _read(_DESKTOP)
    m = re.search(r'const LIST_SELECT = \[(.*?)\n\]', src, re.S)
    assert m, 'LIST_SELECT moved or was renamed in desktop findings.ts'
    body = re.sub(r'//.*', '', m.group(1))          # strip comments first
    return set(re.findall(r"'([^']+)'", body))


def _columns_of(item):
    """Flatten an embedded join into `table(col)` pairs so a missing column
    inside analysis_runs(...) is reported precisely rather than as one blob."""
    m = re.match(r'^([a-z_]+)\((.*)\)$', item)
    if not m:
        return {item}
    table, inner = m.groups()
    return {f'{table}({c})' for c in inner.split(',') if c}


def _flat(columns):
    out = set()
    for c in columns:
        out |= _columns_of(c)
    return out


def test_the_web_asks_for_everything_the_desktop_does():
    """The failing direction that actually bit. A column the desktop selects
    and the web does not is a feature the browser cannot render, and nothing
    surfaces it — the field is simply absent from the JSON."""
    missing = _flat(_desktop_columns()) - _flat(_web_columns())
    assert not missing, (
        'desktop/src/lib/findings.ts selects %s, which api/findings.py does '
        'not. The web app cannot show what it never fetched.' % sorted(missing))


def test_the_desktop_asks_for_everything_the_web_does():
    """The other direction is just as bad, only quieter: the desktop would be
    the one missing a field the web already renders."""
    missing = _flat(_web_columns()) - _flat(_desktop_columns())
    assert not missing, (
        'api/findings.py selects %s, which the desktop does not.' % sorted(missing))


def test_the_dedup_columns_are_actually_selected():
    """Named explicitly because these are the ones that drifted, and because
    losing them degrades silently: `times_seen` absent reads as 1, which is
    indistinguishable from a genuinely new finding."""
    cols = _flat(_web_columns())
    for needed in ('times_seen', 'first_seen_at'):
        assert needed in cols, f'{needed} is not selected by api/findings.py'
    for needed in ('analysis_runs(currency_source)',):
        assert needed in cols, f'{needed} is not selected — no country tag possible'


def test_shared_modules_import_from_neither_app():
    """The condition that lets shared/ exist at all.

    The web app cannot import from desktop/ — .vercelignore excludes it, so
    such a build fails on Vercel and passes on every laptop. Anything under
    shared/ reaching back into an app breaks that asymmetrically and late.
    """
    offenders = []
    for name in sorted(os.listdir(_SHARED)):
        if not name.endswith('.ts'):
            continue
        for _is_type, target in _imports_of(os.path.join(_SHARED, name)):
            if 'desktop' in target or target.startswith('@/'):
                offenders.append(f'{name} -> {target}')
    assert not offenders, (
        'shared/ must not depend on either app: %s' % offenders)


def test_shared_modules_are_framework_free():
    """No React, no Tauri, no Supabase client. Shared code that reaches for a
    client can only be used by whichever app already constructed one."""
    banned = ('@tauri-apps', 'react', 'next/', '@supabase/supabase-js')
    offenders = []
    for name in sorted(os.listdir(_SHARED)):
        if not name.endswith('.ts'):
            continue
        for is_type, target in _imports_of(os.path.join(_SHARED, name)):
            if not any(target.startswith(b) for b in banned):
                continue
            # A type-only import is erased at compile time: no runtime
            # dependency, no bundle weight. shared/history.ts may therefore
            # name SupabaseClient as a type while still taking the client as
            # an argument rather than constructing one — which is the point.
            if is_type:
                continue
            offenders.append(f'{name} -> {target}')
    assert not offenders, 'shared/ must stay framework-free: %s' % offenders


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failures = 0
    for t in tests:
        try:
            t()
            print('  PASS  %s' % t.__name__)
        except AssertionError as e:
            failures += 1
            print('  FAIL  %s: %s' % (t.__name__, e))
        except Exception as e:                           # noqa: BLE001
            failures += 1
            print('  ERROR %s: %s: %s' % (t.__name__, type(e).__name__, e))
    print('\n%d/%d passed' % (len(tests) - failures, len(tests)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
