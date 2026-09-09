"""Tests for finding de-duplication (runner/dedup.py, migration 0010).

This is the logic that decides whether the automated runner is usable at all.
A merchant flagged at 10:00 sits inside the today+yesterday window until end
of tomorrow, so the runner re-detects it ~16 times before it ages out.

The decision function is pure, so every branch is reachable here - including
the ones that only happen 48 hours apart, which is why `now` is injected
rather than read from the clock.

Run with plain python (no pytest needed):

    python tests/test_dedup.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
for p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if p not in sys.path:
        sys.path.insert(0, p)

import dedup  # noqa: E402


NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)


def _finding(score=75, confidence='Critical', company='Mandados sv',
             section='exposure'):
    return {
        'company_name': company,
        'risk_score': score,
        'confidence': confidence,
        'section': section,
        'fingerprints': ['amount_ladder'],
    }


def _existing(status, score=75, confidence='Critical', **kw):
    row = {
        'id': 'aaaaaaaa-0000-0000-0000-000000000001',
        'review_status': status,
        'risk_score': score,
        'confidence': confidence,
        'times_seen': 1,
        'first_seen_at': NOW - timedelta(hours=6),
        'last_seen_at': NOW - timedelta(hours=3),
        'suppressed_until': None,
        'reviewed_at': None,
    }
    row.update(kw)
    return row


# ── Identity ─────────────────────────────────────────────────────────────────

def test_key_is_merchant_plus_section():
    assert dedup.finding_key('Mandados sv', 'exposure') == 'mandados sv|exposure'


def test_key_is_case_and_whitespace_stable():
    """The same merchant must not split into two findings because the export
    changed its capitalisation."""
    a = dedup.finding_key('Mandados sv', 'exposure')
    b = dedup.finding_key('  MANDADOS SV  ', 'exposure')
    assert a == b


def test_key_separates_sections():
    """One merchant can legitimately have both an exposure and a
    zero-settlement finding open at once - they are different problems."""
    a = dedup.finding_key('Kabu', 'exposure')
    b = dedup.finding_key('Kabu', 'zero_settlement')
    assert a != b


def test_key_defaults_section():
    assert dedup.finding_key('Kabu', None) == 'kabu|exposure'


def test_key_matches_the_sql_backfill():
    """Migration 0010 backfills with lower(trim(company_name))||'|'||section.
    If these ever diverge, every pre-existing finding becomes invisible to the
    runner and gets raised again as new."""
    company, section = '  Inversiones Kabu ', 'zero_settlement'
    sql_equivalent = f'{company.strip().lower()}|{section}'
    assert dedup.finding_key(company, section) == sql_equivalent


# ── First sighting ───────────────────────────────────────────────────────────

def test_unseen_finding_is_inserted():
    d = dedup.decide(None, _finding(), now=NOW)
    assert d.action == dedup.INSERT


# ── Already pending: update, never duplicate ────────────────────────────────

def test_pending_is_updated_not_duplicated():
    """The whole point. 16 re-detections must produce 1 row, not 16."""
    d = dedup.decide(_existing('pending'), _finding(), now=NOW)
    assert d.action == dedup.UPDATE
    assert d.target_id is not None


def test_pending_update_carries_the_new_score():
    """The reviewer must see the CURRENT score. A merchant first caught at 45
    and now at 90 is a materially different decision."""
    d = dedup.decide(_existing('pending', score=45), _finding(score=90), now=NOW)
    assert d.action == dedup.UPDATE
    assert '45' in d.reason and '90' in d.reason


def test_sixteen_redetections_stay_one_finding():
    existing = _existing('pending')
    actions = [dedup.decide(existing, _finding(), now=NOW).action for _ in range(16)]
    assert set(actions) == {dedup.UPDATE}


# ── Accepted: suppress ───────────────────────────────────────────────────────

def test_accepted_is_suppressed():
    """Already on the watchlist. Re-alerting gives a reviewer nothing to do."""
    d = dedup.decide(_existing('accepted'), _finding(), now=NOW)
    assert d.action == dedup.SUPPRESS


def test_accepted_stays_suppressed_even_if_score_rises():
    d = dedup.decide(_existing('accepted', score=40), _finding(score=100), now=NOW)
    assert d.action == dedup.SUPPRESS


# ── Rejected: 48h cooloff ────────────────────────────────────────────────────

def test_rejected_is_silent_inside_the_cooloff():
    row = _existing('rejected', suppressed_until=NOW + timedelta(hours=20))
    d = dedup.decide(row, _finding(), now=NOW)
    assert d.action == dedup.SUPPRESS
    assert '20h' in d.reason


def test_rejected_reopens_after_the_cooloff():
    row = _existing('rejected', suppressed_until=NOW - timedelta(minutes=1))
    d = dedup.decide(row, _finding(), now=NOW)
    assert d.action == dedup.REOPEN


def test_cooloff_derived_from_reviewed_at_when_missing():
    """Rows rejected before migration 0010 have no suppressed_until. They must
    still get their quiet period rather than re-alerting immediately."""
    row = _existing('rejected', suppressed_until=None,
                    reviewed_at=NOW - timedelta(hours=2))
    d = dedup.decide(row, _finding(), now=NOW)
    assert d.action == dedup.SUPPRESS


def test_old_rejection_without_cooloff_reopens():
    row = _existing('rejected', suppressed_until=None,
                    reviewed_at=NOW - timedelta(days=30))
    d = dedup.decide(row, _finding(), now=NOW)
    assert d.action == dedup.REOPEN


def test_cooloff_boundary_is_48_hours():
    reviewed = NOW - timedelta(hours=47, minutes=59)
    assert dedup.decide(_existing('rejected', suppressed_until=None,
                                  reviewed_at=reviewed),
                        _finding(), now=NOW).action == dedup.SUPPRESS
    reviewed = NOW - timedelta(hours=48, minutes=1)
    assert dedup.decide(_existing('rejected', suppressed_until=None,
                                  reviewed_at=reviewed),
                        _finding(), now=NOW).action == dedup.REOPEN


# ── Rejected: escalation overrides the cooloff ──────────────────────────────

def test_score_escalation_reopens_early():
    """Escalation beats the cooloff: the reviewer dismissed what they saw,
    not what it has since become."""
    row = _existing('rejected', score=50,
                    suppressed_until=NOW + timedelta(hours=40))
    d = dedup.decide(row, _finding(score=70), now=NOW)
    assert d.action == dedup.REOPEN
    assert 'puntaje' in d.reason


def test_score_escalation_needs_the_full_delta():
    row = _existing('rejected', score=50,
                    suppressed_until=NOW + timedelta(hours=40))
    # +14 is below the +15 threshold: still silent.
    assert dedup.decide(row, _finding(score=64), now=NOW).action == dedup.SUPPRESS
    # +15 exactly: re-opens.
    assert dedup.decide(row, _finding(score=65), now=NOW).action == dedup.REOPEN


def test_tier_crossing_reopens_even_without_a_score_jump():
    """The important half of the rule. A finding rejected at Monitor that now
    scores Critical has genuinely changed behaviour - and for the
    zero-settlement section, whose score saturates at 100, tier-crossing is
    the ONLY escalation signal that can ever fire."""
    row = _existing('rejected', score=100, confidence='Monitor',
                    suppressed_until=NOW + timedelta(hours=40))
    d = dedup.decide(row, _finding(score=100, confidence='Critical'), now=NOW)
    assert d.action == dedup.REOPEN
    assert 'Critical' in d.reason


def test_saturated_score_still_escalates_by_tier():
    """Regression guard for the CALIBRATION.md ceiling problem: a finding
    pinned at 100 on first detection can never climb, so a purely numeric
    escalation rule would leave it silent forever."""
    row = _existing('rejected', score=100, confidence='Monitor',
                    suppressed_until=NOW + timedelta(hours=47))
    assert dedup.decide(row, _finding(score=100, confidence='Critical'),
                        now=NOW).action == dedup.REOPEN


def test_dropping_a_tier_does_not_reopen():
    row = _existing('rejected', score=90, confidence='Critical',
                    suppressed_until=NOW + timedelta(hours=40))
    d = dedup.decide(row, _finding(score=50, confidence='Monitor'), now=NOW)
    assert d.action == dedup.SUPPRESS


# ── Monitor tier ─────────────────────────────────────────────────────────────

def test_monitor_finding_updates_without_queueing():
    row = _existing('not_applicable', confidence='Monitor', score=45)
    d = dedup.decide(row, _finding(score=50, confidence='Monitor'), now=NOW)
    assert d.action == dedup.UPDATE
    assert d.promote is False


def test_monitor_promoted_when_it_reaches_critical():
    """A merchant that quietly escalates must enter the queue - otherwise it
    is never reviewed, which is the exact failure this tool exists to avoid."""
    row = _existing('not_applicable', confidence='Monitor', score=45)
    d = dedup.decide(row, _finding(score=80, confidence='Critical'), now=NOW)
    assert d.action == dedup.UPDATE
    assert d.promote is True


# ── Robustness ───────────────────────────────────────────────────────────────

def test_unknown_status_is_queued_not_dropped():
    """A status we do not recognise must surface, not vanish silently."""
    d = dedup.decide(_existing('some_future_status'), _finding(), now=NOW)
    assert d.action == dedup.INSERT


def test_iso_string_timestamps_are_accepted():
    """Supabase returns ISO strings, not datetimes."""
    row = _existing('rejected', suppressed_until='2026-09-10T12:00:00Z')
    d = dedup.decide(row, _finding(), now=NOW)
    assert d.action == dedup.SUPPRESS


def test_naive_timestamps_do_not_raise():
    row = _existing('rejected',
                    suppressed_until=datetime(2026, 9, 10, 12, 0, 0))
    d = dedup.decide(row, _finding(), now=NOW)
    assert d.action == dedup.SUPPRESS


def test_missing_scores_do_not_raise():
    row = _existing('rejected', score=None,
                    suppressed_until=NOW + timedelta(hours=40))
    d = dedup.decide(row, {'company_name': 'X'}, now=NOW)
    assert d.action in (dedup.SUPPRESS, dedup.REOPEN)


def test_summarize_counts_actions():
    ds = [dedup.Decision(dedup.INSERT, ''), dedup.Decision(dedup.INSERT, ''),
          dedup.Decision(dedup.SUPPRESS, '')]
    counts = dedup.summarize(ds)
    assert counts[dedup.INSERT] == 2 and counts[dedup.SUPPRESS] == 1


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
