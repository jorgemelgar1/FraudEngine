"""Tests for runner/slack.py — the notification layer.

The behaviour that matters here is mostly NEGATIVE: what does not get sent.
A merchant is re-detected roughly sixteen times before it ages out of the
today+yesterday window, so the difference between a useful channel and one
everybody mutes is entirely in the cases that produce silence.

Every message shape is built by a pure function, so all of this runs without
a network and without a webhook.

Run with plain python (no pytest needed):

    python tests/test_slack.py
"""

import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))

# Before importing config, which snapshots the environment at import time.
os.environ.setdefault('RUNNER_STATE_DIR', tempfile.mkdtemp(prefix='slack-test-'))

for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config          # noqa: E402
import dedup           # noqa: E402
import slack           # noqa: E402


def _finding(name='ACME STORE', score=80, confidence='Critical',
             exposure=1234.5, currency='USD', fingerprints=None):
    return {
        'company_name': name,
        'risk_score': score,
        'confidence': confidence,
        'estimated_chargeback_exposure': exposure,
        'currency': currency,
        'fingerprints': fingerprints if fingerprints is not None
        else ['tarjetas_multiples'],
    }


def _text(payload):
    """Everything renderable in one string, for substring assertions."""
    return json.dumps(payload, ensure_ascii=False)


# ── What is news, and what is not ────────────────────────────────────────────

def test_a_first_detection_is_news():
    event = slack.notable(dedup.Decision(dedup.INSERT, 'primera detección'),
                          _finding(), 'exposure')
    assert event and event['kind'] == slack.NEW


def test_a_plain_re_detection_is_not_news():
    """THE central test. A merchant is seen ~16 times before ageing out; if
    each one notified, the channel would be muted within a week and the whole
    feature would be worth less than nothing."""
    decision = dedup.Decision(dedup.UPDATE, 'ya pendiente, visto de nuevo',
                              escalated=None)
    assert slack.notable(decision, _finding(), 'exposure') is None


def test_a_suppressed_finding_is_not_news():
    decision = dedup.Decision(dedup.SUPPRESS, 'ya aceptado y en la watchlist')
    assert slack.notable(decision, _finding(), 'exposure') is None


def test_a_score_jump_on_a_pending_finding_is_news():
    """The gap this feature was built to close: a merchant already in the
    queue at 45 that is now at 90 is exactly what ops asked to hear about,
    and before this it produced an ordinary UPDATE like any other."""
    existing = {'id': 'x', 'review_status': 'pending',
                'risk_score': 45, 'confidence': 'Critical'}
    decision = dedup.decide(existing, _finding(score=90))
    assert decision.action == dedup.UPDATE
    assert decision.escalated, 'a +45 jump has to be marked as escalated'

    event = slack.notable(decision, _finding(score=90), 'exposure')
    assert event and event['kind'] == slack.ESCALATED
    assert '45' in event['detail'] and '90' in event['detail']


def test_a_small_score_change_on_a_pending_finding_is_not_news():
    existing = {'id': 'x', 'review_status': 'pending',
                'risk_score': 80, 'confidence': 'Critical'}
    decision = dedup.decide(existing, _finding(score=84))
    assert decision.action == dedup.UPDATE
    assert decision.escalated is None, '+4 is not a considerable increase'
    assert slack.notable(decision, _finding(score=84), 'exposure') is None


def test_promotion_from_monitor_to_critical_is_news():
    """Something filed as informational now needs a human. This is the most
    meaningful escalation there is."""
    existing = {'id': 'x', 'review_status': 'not_applicable',
                'risk_score': 40, 'confidence': 'Monitor'}
    decision = dedup.decide(existing, _finding(score=85, confidence='Critical'))
    assert decision.promote is True
    event = slack.notable(decision, _finding(score=85), 'exposure')
    assert event and event['kind'] == slack.ESCALATED
    assert 'Critical' in event['detail']


def test_a_monitor_row_that_stays_monitor_is_not_news():
    existing = {'id': 'x', 'review_status': 'not_applicable',
                'risk_score': 30, 'confidence': 'Monitor'}
    decision = dedup.decide(existing, _finding(score=35, confidence='Monitor'))
    assert slack.notable(decision, _finding(confidence='Monitor'),
                         'exposure') is None


def test_a_cooloff_expiry_is_announced_but_not_as_an_escalation():
    """It is back in the queue, which is worth saying — but the merchant did
    not get worse, and calling it an escalation would be a lie."""
    decision = dedup.Decision(dedup.REOPEN,
                              'terminó el periodo de silencio de 48h')
    event = slack.notable(decision, _finding(), 'exposure')
    assert event and event['kind'] == slack.REOPENED


def test_an_escalated_reopen_is_an_escalation():
    decision = dedup.Decision(dedup.REOPEN, 'el puntaje subió de 40 a 90',
                              escalated='el puntaje subió de 40 a 90')
    event = slack.notable(decision, _finding(), 'exposure')
    assert event and event['kind'] == slack.ESCALATED


# ── Silence ──────────────────────────────────────────────────────────────────

def test_no_events_produces_no_message():
    """A quiet cycle must be silent. A "nothing to report" every three hours
    teaches everyone to skim past the channel."""
    assert slack.build_findings_message('PA', []) is None


def test_only_monitor_events_with_monitor_off_produces_no_message():
    events = [slack.notable(dedup.Decision(dedup.INSERT, 'x'),
                            _finding(confidence='Monitor'), 'exposure')]
    assert slack.build_findings_message('PA', events, monitor_mode='off') is None


# ── The message ──────────────────────────────────────────────────────────────

def _one_new(**kw):
    return [slack.notable(dedup.Decision(dedup.INSERT, 'primera detección'),
                          _finding(**kw), 'exposure')]


def test_the_country_is_on_the_header_and_on_every_line():
    """Different ops people watch different countries, so "is this mine?" has
    to be answerable without opening anything."""
    payload = slack.build_findings_message('PA', _one_new())
    body = _text(payload)
    assert 'Panam' in body and 'PA' in body
    header = payload['blocks'][0]['text']['text']
    assert 'Panam' in header


def test_the_country_comes_out_readable_even_if_unknown():
    payload = slack.build_findings_message('ZZ', _one_new())
    assert payload is not None, 'an unknown country must not lose the message'
    assert 'ZZ' in _text(payload)


def test_merchant_score_and_exposure_are_present():
    payload = slack.build_findings_message('GT', _one_new(
        name='TIENDA X', score=91, exposure=4812.0, currency='GTQ'))
    body = _text(payload)
    assert 'TIENDA X' in body
    assert '91' in body
    assert '4,812.00' in body and 'GTQ' in body


def test_an_unknown_currency_is_not_dressed_up_as_dollars():
    """Same rule as both apps: a guess about money is worse than an
    admission, and 'UNKNOWN' is what pre-fix rows carry."""
    payload = slack.build_findings_message('GT', _one_new(currency='UNKNOWN'))
    body = _text(payload)
    assert 'sin moneda' in body
    assert 'USD' not in body


def test_zero_settlement_findings_do_not_claim_an_exposure():
    event = slack.notable(dedup.Decision(dedup.INSERT, 'x'),
                          _finding(exposure=None), 'zero_settlement')
    payload = slack.build_findings_message('SV', [event])
    assert 'sin liquidación' in _text(payload)


def test_a_fallback_text_is_always_present():
    """blocks render in the channel; text is what a mobile push notification
    and a screen reader get. Sending only blocks produces a silent, empty
    notification."""
    payload = slack.build_findings_message('PA', _one_new())
    assert payload['text'] and len(payload['text']) > 0


def test_critical_comes_before_monitor_and_new_before_the_rest():
    events = [
        slack.notable(dedup.Decision(dedup.REOPEN, 'x', escalated='subió'),
                      _finding(name='SEGUNDO', score=99), 'exposure'),
        slack.notable(dedup.Decision(dedup.INSERT, 'x'),
                      _finding(name='PRIMERO', score=50), 'exposure'),
    ]
    body = _text(slack.build_findings_message('PA', events))
    assert body.index('PRIMERO') < body.index('SEGUNDO')


def test_monitor_merchants_are_collapsed_into_one_line():
    """Volume-safe by construction: however many Monitor findings a cycle
    produces, they cost one line, not one message each."""
    events = [slack.notable(dedup.Decision(dedup.INSERT, 'x'),
                            _finding(name=f'M{i}', confidence='Monitor'),
                            'exposure')
              for i in range(12)]
    payload = slack.build_findings_message('PA', events)
    body = _text(payload)
    assert '12' in body
    assert 'M0' in body and 'M11' not in body, 'the tail becomes a count'


def test_a_flood_of_criticals_is_truncated_rather_than_unreadable():
    events = [slack.notable(dedup.Decision(dedup.INSERT, 'x'),
                            _finding(name=f'C{i}'), 'exposure')
              for i in range(40)]
    payload = slack.build_findings_message('PA', events)
    assert len(payload['blocks']) <= slack.MAX_BLOCKS, 'Slack rejects >50'
    assert 'más' in _text(payload), 'the reader must know it was truncated'


def test_ampersands_in_merchant_names_are_escaped():
    """Slack requires & < > escaped. Real merchant names contain
    ampersands, and an unescaped one breaks the rest of the line."""
    payload = slack.build_findings_message('PA', _one_new(name='B&B CAFE'))
    assert '&amp;' in _text(payload)
    assert 'B&B' not in _text(payload).replace('&amp;', '&#')


def test_the_window_and_transaction_count_appear_when_known():
    summary = {'date_range': {'start': '2026-09-08', 'end': '2026-09-09'},
               'unique_transactions': 4812}
    body = _text(slack.build_findings_message('PA', _one_new(), summary))
    assert '2026-09-08' in body and '4,812' in body


def test_a_missing_summary_does_not_break_the_message():
    assert slack.build_findings_message('PA', _one_new(), None) is not None


# ── Card data must never reach the channel ───────────────────────────────────

def test_card_data_in_the_payload_never_reaches_slack():
    """The channel is a wider audience than the app. The finding dict carries
    evidence rows with BINs, last-4 and cardholder names; only the merchant,
    score, exposure and fingerprints are allowed out."""
    finding = _finding()
    finding['evidence'] = [{
        'transaction_id': 'tx-1',
        'card_bin': '411111',
        'card_last_digits': '1234',
        'card_holder': 'JON/GUERRERO',
    }]
    event = slack.notable(dedup.Decision(dedup.INSERT, 'x'), finding,
                          'exposure')
    body = _text(slack.build_findings_message('PA', [event]))
    for secret in ('411111', '1234', 'GUERRERO', 'tx-1'):
        assert secret not in body, f'{secret} leaked into a Slack message'


# ── The daily queue nudge ────────────────────────────────────────────────────

def test_an_empty_queue_says_nothing():
    """A cheerful "0 pendientes" every morning is how a channel becomes
    background noise, and then the message that matters lands somewhere
    nobody looks."""
    assert slack.build_queue_message(0) is None
    assert slack.build_queue_message(None) is None


def test_the_nudge_leads_with_the_count():
    body = _text(slack.build_queue_message(12))
    assert '12' in body and 'pendiente' in body
    assert 'Pendientes' in body, 'it should say where to go'


def test_the_age_of_the_oldest_is_what_makes_it_land():
    """A count alone does not move anyone. "el más antiguo lleva 4 días" is
    the half that sounds wrong."""
    body = _text(slack.build_queue_message(12, oldest_days=4.2))
    assert '4' in body and 'día' in body


def test_a_fresh_queue_does_not_claim_an_age():
    body = _text(slack.build_queue_message(3, oldest_days=0.2))
    assert 'más antiguo' not in body


def test_one_pending_reads_correctly():
    body = _text(slack.build_queue_message(1, oldest_days=1))
    assert 'comercio pendiente de revisión' in body
    assert 'comercios' not in body


# ── Health messages ──────────────────────────────────────────────────────────

def test_a_health_message_carries_the_fix_not_just_the_problem():
    payload = slack.build_health_message(
        'Guatemala lleva 3 ciclos sin completarse',
        detail='HTTP 403', fix='compara --show-request con --show-headers',
        level='bad')
    body = _text(payload)
    assert 'Guatemala' in body and '403' in body
    assert 'show-request' in body


def test_a_long_error_detail_is_capped():
    payload = slack.build_health_message('x', detail='y' * 5000)
    for block in payload['blocks']:
        rendered = json.dumps(block)
        assert len(rendered) < 3200, 'Slack rejects text objects over 3000'


# ── Sending is off unless configured ─────────────────────────────────────────

def test_posting_without_a_webhook_is_a_no_op_not_a_crash():
    """No webhook configured must mean silence. A runner that refuses to
    analyse fraud because a notification setting is missing has its
    priorities exactly backwards."""
    assert slack.post({'text': 'x'}, '') is False
    assert slack.post({'text': 'x'}, None) is False


def test_send_findings_is_off_when_slack_is_not_configured():
    saved = config.SLACK_WEBHOOK_URL
    config.SLACK_WEBHOOK_URL = ''
    try:
        assert slack.send_findings('PA', _one_new()) is False
    finally:
        config.SLACK_WEBHOOK_URL = saved


def test_a_per_country_webhook_overrides_the_default():
    """Different ops teams watch different countries, so one channel per
    country is the likely end state. It should be config, not a rewrite."""
    saved_default = config.SLACK_WEBHOOK_URL
    saved_map = dict(config.SLACK_WEBHOOK_BY_COUNTRY)
    config.SLACK_WEBHOOK_URL = 'https://hooks.slack.example/default'
    config.SLACK_WEBHOOK_BY_COUNTRY['GT'] = 'https://hooks.slack.example/gt'
    try:
        assert config.slack_webhook_for('GT').endswith('/gt')
        assert config.slack_webhook_for('PA').endswith('/default')
        assert config.slack_webhook_for(None).endswith('/default')
    finally:
        config.SLACK_WEBHOOK_URL = saved_default
        config.SLACK_WEBHOOK_BY_COUNTRY.clear()
        config.SLACK_WEBHOOK_BY_COUNTRY.update(saved_map)


def test_the_webhook_url_is_never_in_an_error_message():
    """urllib embeds the URL it was called with in its own exceptions, which
    is exactly how a credential ends up in a log file."""
    import io
    from contextlib import redirect_stdout

    secret = 'https://hooks.slack.example/services/T0/B0/SUPERSECRETTOKEN'
    buf = io.StringIO()
    with redirect_stdout(buf):
        slack.post({'text': 'x'}, secret)
    output = buf.getvalue()
    assert 'SUPERSECRETTOKEN' not in output, 'the webhook leaked into stdout'
    assert 'hooks.slack.example' not in output


def test_slack_failures_never_raise():
    """A Slack outage must not fail a run that analysed correctly."""
    assert slack.post({'text': 'x'},
                      'https://127.0.0.1:1/definitely-not-listening') is False


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
        except Exception as e:                              # noqa: BLE001
            failures += 1
            print(f'  ERROR {t.__name__}: {type(e).__name__}: {e}')
    print(f'\n{len(tests) - failures}/{len(tests)} passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
