"""Decide what to do when a run re-detects a finding.

This is the piece that decides whether the automated runner is usable. The
today+yesterday window means a merchant flagged at 10:00 stays in scope until
end of tomorrow, so it is re-detected roughly 16 times (48 h / 3-hour cycle)
before ageing out. Sixteen copies of every finding in the review queue is not
a degraded tool, it is a dead one.

The decision is a PURE function of (existing row, new finding, now). No I/O,
no database, no clock lookup - all three are arguments. That is deliberate:
every branch below is reachable in a unit test, including the ones that only
occur 48 hours apart.

Schema and the SQL side live in migration 0010.
"""

from datetime import datetime, timedelta, timezone


# ── Policy ───────────────────────────────────────────────────────────────────

# How long a rejected finding stays quiet before it may alert again. Decided
# with the user: long enough that a dismissed false positive does not nag
# every three hours, short enough that a merchant that genuinely turns bad
# does not stay invisible.
REJECTION_COOLOFF = timedelta(hours=48)

# A rejected finding re-opens early if the score climbs by at least this much.
# Escalation beats the cooloff: the reviewer dismissed what they saw, not what
# it has since become.
ESCALATION_SCORE_DELTA = 15

# Tier ordering, for detecting a crossing into Critical.
_TIER_RANK = {'Monitor': 1, 'Critical': 2}


# ── Actions ──────────────────────────────────────────────────────────────────

INSERT = 'insert'        # never seen - create as pending
UPDATE = 'update'        # already open - refresh in place
SUPPRESS = 'suppress'    # already actioned or inside a cooloff - do nothing
REOPEN = 'reopen'        # a rejected finding that escalated or aged out


class Decision:
    """What to do, and why - the reason is logged and shown to reviewers."""

    __slots__ = ('action', 'reason', 'promote', 'target_id', 'escalated')

    def __init__(self, action, reason, promote=False, target_id=None,
                 escalated=None):
        self.action = action
        self.reason = reason
        # Only meaningful for UPDATE: a Monitor-tier row that has reached
        # Critical must move into the review queue.
        self.promote = promote
        self.target_id = target_id
        # Why this re-detection is worth someone's attention, or None.
        #
        # Separate from `reason`, which explains what happened to the ROW.
        # Almost every re-detection is an UPDATE - a merchant is seen ~16
        # times before ageing out of the window - and telling anyone about
        # those would be sixteen notifications per merchant. This field marks
        # the few that are genuinely news: the score climbed materially, or
        # the finding crossed into Critical.
        #
        # It exists on the Decision rather than in the notifier so it stays a
        # pure function of the same three inputs, testable without a network.
        self.escalated = escalated

    def __repr__(self):
        return f'<Decision {self.action}: {self.reason}>'

    def __eq__(self, other):
        return (isinstance(other, Decision)
                and self.action == other.action
                and self.promote == other.promote)


# ── Identity ─────────────────────────────────────────────────────────────────

def finding_key(company_name: str, section: str) -> str:
    """Stable identity across runs.

    (merchant, section) rather than (merchant, fingerprints): ops reasons
    about whether a MERCHANT is a problem. A new pattern at a known merchant
    should refresh the open finding, not raise a second one beside it.

    Must match the backfill expression in migration 0010 exactly, or existing
    rows become invisible to the runner and every one of them is re-raised.
    """
    name = (company_name or '').strip().lower()
    sec = (section or 'exposure').strip().lower()
    return f'{name}|{sec}'


# ── Escalation ───────────────────────────────────────────────────────────────

def _tier(confidence) -> int:
    return _TIER_RANK.get(confidence, 0)


def escalation_reason(old_score, old_confidence, new_score, new_confidence):
    """Why this re-detection outranks the earlier rejection, or None.

    Two independent triggers. Tier-crossing is the more meaningful of the
    two - a merchant dismissed as Monitor that now scores Critical has
    genuinely changed behaviour.

    Note the score-delta trigger is weak for the zero-settlement section,
    whose score saturates at 100 (tests/CALIBRATION.md): a finding pinned at
    the ceiling on first detection can never climb. Tier-crossing still works
    there, which is why both rules exist rather than just the numeric one.
    """
    if _tier(new_confidence) > _tier(old_confidence) and new_confidence == 'Critical':
        return f'subió de {old_confidence} a Critical'

    old_score = old_score or 0
    new_score = new_score or 0
    if new_score >= old_score + ESCALATION_SCORE_DELTA:
        return f'el puntaje subió de {old_score} a {new_score}'

    return None


# ── The decision ─────────────────────────────────────────────────────────────

def decide(existing, finding, now=None):
    """Return a Decision for one re-detected finding.

    `existing` is the row from lookup_open_finding (a dict) or None.
    `finding`  is the finding dict produced by analyze.py.
    `now`      is injected so cooloff expiry is testable without waiting.
    """
    now = now or datetime.now(timezone.utc)

    new_score = finding.get('risk_score') or 0
    new_conf = finding.get('confidence')

    # ── Never seen ───────────────────────────────────────────────────────
    if not existing:
        return Decision(INSERT, 'primera detección')

    status = existing.get('review_status')
    target = existing.get('id')
    old_score = existing.get('risk_score') or 0
    old_conf = existing.get('confidence')

    # ── Already in the queue ─────────────────────────────────────────────
    # Refresh rather than duplicate. The reviewer must see the CURRENT score:
    # a merchant first caught at 45 that is now at 90 is a different decision.
    if status == 'pending':
        # A merchant already in the queue at 45 that is now at 90 is news; the
        # same merchant seen again at 46 is not. Same rule and same threshold
        # as the rejected branch below - one definition of "materially worse",
        # not two that drift apart.
        return Decision(
            UPDATE,
            f'ya pendiente, visto de nuevo (puntaje {old_score} → {new_score})',
            target_id=target,
            escalated=escalation_reason(old_score, old_conf,
                                        new_score, new_conf),
        )

    # ── Monitor tier ─────────────────────────────────────────────────────
    # Informational, not queued. But if it reaches Critical it has to enter
    # the queue - otherwise a merchant that quietly escalates is never
    # reviewed, which is exactly the failure this whole tool exists to avoid.
    if status == 'not_applicable':
        promote = new_conf == 'Critical'
        reason = ('escaló a Critical, entra a revisión' if promote
                  else 'sigue en Monitor, se actualiza sin encolar')
        # A promotion is the most meaningful escalation there is: something
        # filed as informational now needs a human. A Monitor row that merely
        # gets a higher Monitor score is not worth interrupting anyone for.
        return Decision(
            UPDATE, reason, promote=promote, target_id=target,
            escalated=(f'pasó de {old_conf or "Monitor"} a Critical'
                       if promote else None),
        )

    # ── Accepted ─────────────────────────────────────────────────────────
    # Already actioned and on the watchlist. Re-alerting adds nothing a
    # reviewer can act on. The sighting is still worth recording, which the
    # caller does by touching the watchlist's last_flagged.
    if status == 'accepted':
        return Decision(
            SUPPRESS, 'ya aceptado y en la watchlist', target_id=target
        )

    # ── Rejected ─────────────────────────────────────────────────────────
    if status == 'rejected':
        escalated = escalation_reason(old_score, old_conf, new_score, new_conf)
        if escalated:
            return Decision(REOPEN, escalated, target_id=target,
                            escalated=escalated)

        until = existing.get('suppressed_until')
        if until is None:
            # Row rejected before this migration, or the cooloff was cleared.
            # Derive it from the review timestamp so old rejections still get
            # their quiet period rather than re-alerting immediately.
            reviewed = existing.get('reviewed_at')
            until = (_as_dt(reviewed) + REJECTION_COOLOFF) if reviewed else None

        until = _as_dt(until)
        if until and now < until:
            remaining = until - now
            hours = int(remaining.total_seconds() // 3600)
            return Decision(
                SUPPRESS,
                f'descartado, en silencio {hours}h más',
                target_id=target,
            )

        return Decision(
            REOPEN, 'terminó el periodo de silencio de 48h', target_id=target
        )

    # ── Anything else ────────────────────────────────────────────────────
    # An unrecognised status must not silently drop a finding. Insert so it
    # surfaces, and let a human notice the odd state.
    return Decision(INSERT, f'estado desconocido ({status!r}), se encola')


def suppressed_until_for(now=None):
    """When a rejection made now should stop suppressing."""
    now = now or datetime.now(timezone.utc)
    return now + REJECTION_COOLOFF


# ── Helpers ──────────────────────────────────────────────────────────────────

def _as_dt(value):
    """Tolerant timestamp parse. Supabase returns ISO strings; tests pass
    datetimes. Naive values are assumed UTC so comparisons never raise."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        s = str(value).replace('Z', '+00:00')
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def summarize(decisions):
    """Counts per action, for the run log."""
    out = {INSERT: 0, UPDATE: 0, SUPPRESS: 0, REOPEN: 0}
    for d in decisions:
        out[d.action] = out.get(d.action, 0) + 1
    return out
