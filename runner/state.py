"""Small durable state for the runner: what it has already processed.

Two things live here, and neither is in the database on purpose - both are
facts about *this machine's* progress, not about fraud:

  processed message ids   so a delayed report cannot be consumed twice
  last success per country  so "no findings for two days" can be told apart
                            from "the runner has been dead for two days"

That second one matters more than it looks. A silently broken runner and a
clean fraud week produce exactly the same thing: nothing. Recording when each
country last completed is what makes the difference observable.

Written atomically - to a temporary file, then renamed - so a crash or a power
cut mid-write leaves the previous state intact rather than a truncated file
that fails to parse on every subsequent run.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import config


# Enough that a delayed report cannot slip past, small enough that the file
# stays trivial to read by hand when something looks wrong. At 24 reports a
# day this is about three weeks of history.
MAX_PROCESSED_IDS = 500

# A country that has not completed in this long is a problem worth surfacing,
# even though overlapping windows mean no single miss loses data.
STALE_AFTER = timedelta(hours=12)

_EMPTY = {'processed_ids': [], 'last_success': {}, 'version': 1}


def load() -> dict:
    """Read the state file. A missing or corrupt file yields empty state.

    Deliberately forgiving: state is a convenience, and refusing to run
    because a bookkeeping file is damaged would turn a trivial problem into
    an outage. The cost of losing it is one possible duplicate report.
    """
    path = config.state_path()
    if not os.path.exists(path):
        return dict(_EMPTY, processed_ids=[], last_success={})
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return dict(_EMPTY, processed_ids=[], last_success={})
    if not isinstance(data, dict):
        return dict(_EMPTY, processed_ids=[], last_success={})
    data.setdefault('processed_ids', [])
    data.setdefault('last_success', {})
    data.setdefault('version', 1)
    return data


def save(state: dict) -> str:
    """Write the state file atomically. Returns the path."""
    path = config.state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Trim oldest first; the list is append-ordered.
    ids = state.get('processed_ids') or []
    if len(ids) > MAX_PROCESSED_IDS:
        state['processed_ids'] = ids[-MAX_PROCESSED_IDS:]

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(state, fh, indent=2, default=str)
        os.replace(tmp, path)     # atomic on both Windows and POSIX
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return path


# ── Processed messages ───────────────────────────────────────────────────────

def is_processed(message_id: str, state: dict = None) -> bool:
    state = load() if state is None else state
    return message_id in (state.get('processed_ids') or [])


def mark_processed(message_id: str, state: dict = None) -> dict:
    """Record a message as consumed. Returns the state (not yet saved).

    Callers pass `state` through so a run can mark several things and save
    once, rather than racing itself with repeated read-modify-writes.
    """
    state = load() if state is None else state
    ids = state.setdefault('processed_ids', [])
    if message_id not in ids:
        ids.append(message_id)
    return state


# ── Per-country progress ─────────────────────────────────────────────────────

def record_success(country_code: str, when: datetime = None,
                   state: dict = None) -> dict:
    state = load() if state is None else state
    when = when or datetime.now(timezone.utc)
    state.setdefault('last_success', {})[country_code.upper()] = when.isoformat()
    return state


def last_success(country_code: str, state: dict = None):
    state = load() if state is None else state
    raw = (state.get('last_success') or {}).get(country_code.upper())
    return _as_dt(raw)


def stale_countries(now: datetime = None, state: dict = None,
                    stale_after: timedelta = None) -> list:
    """Countries with no successful run recently, worst first.

    A country that has never run counts as stale: the first thing to notice
    about a runner installed a week ago is that one of the three never
    actually worked.
    """
    state = load() if state is None else state
    now = now or datetime.now(timezone.utc)
    stale_after = stale_after or STALE_AFTER

    out = []
    for code in config.ROTATION:
        when = last_success(code, state=state)
        if when is None:
            out.append((code, None))
        elif now - when > stale_after:
            out.append((code, when))
    # Never-run first, then oldest first.
    out.sort(key=lambda item: item[1] or datetime.min.replace(tzinfo=timezone.utc))
    return out


def describe(state: dict = None) -> str:
    """Human-readable summary, for `python3 runner/state.py`."""
    state = load() if state is None else state
    now = datetime.now(timezone.utc)
    lines = [f'Archivo: {config.state_path()}',
             f'Mensajes procesados: {len(state.get("processed_ids") or [])}',
             'Último éxito por país:']
    for code in config.ROTATION:
        when = last_success(code, state=state)
        if when is None:
            lines.append(f'  {code}: nunca')
            continue
        hours = (now - when).total_seconds() / 3600
        flag = '  <-- atrasado' if hours > STALE_AFTER.total_seconds() / 3600 else ''
        lines.append(f'  {code}: {when:%Y-%m-%d %H:%M} UTC ({hours:.1f} h){flag}')
    return '\n'.join(lines)


def _as_dt(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


if __name__ == '__main__':
    print(describe())
