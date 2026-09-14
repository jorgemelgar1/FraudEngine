"""Slack notifications for the automated runner.

Two kinds of message, one channel:

  findings   a CRITICAL merchant is new, worse, or back
  health     the runner itself is in trouble

**The hard part is not sending, it is NOT sending.** The runner analyses a
today+yesterday window every three hours per country, so a flagged merchant is
re-detected roughly sixteen times before it ages out. Notifying on every
detection would put sixteen messages per merchant into the channel, everyone
would mute it inside a week, and the feature would be worse than nothing -
because now there is an alerting system that nobody reads.

So the trigger is not "a finding exists", it is "the de-duplication engine
decided this is news": a first detection, a score that climbed materially, or
a crossing into Critical. That decision already exists in dedup.py, is a pure
function, and has its own tests. `notable()` below is the single place that
projects it into "worth telling someone".

**Critical only, and only three states, since 2026-09-14.** Two doors were
open and both produced volume nobody could keep up with:

  * Monitor findings reached the channel, collapsed to one line but still
    enough to SEND a message. A cycle with zero Critical findings and one new
    Monitor merchant posted anyway, and since merchants roll through the
    two-day window constantly, that alone was roughly an alert an hour.

  * Nothing distinguished "this merchant is new" from "this merchant is
    still here". Anything already awaiting review is the app's job to show,
    not the channel's - a notification about something a person has already
    been told about is how a channel gets muted.

So the channel now hears exactly two things about fraud: a merchant that is
newly Critical, and one that has just become Critical (or materially worse)
having not been. Everything else - Monitor, re-detections, a dismissed
finding whose cooloff expired, the depth of the queue - belongs to Pendientes
and Historial, and to the one daily queue nudge.

Design rules, all of them learned elsewhere in this codebase:

  * **Best-effort.** A Slack outage must never fail a run that analysed
    correctly. Every entry point returns a bool and swallows its errors.
  * **Off is a valid state.** No SLACK_WEBHOOK_URL configured means silence,
    not a crash. Notifications are an enhancement; fraud detection is not.
  * **The webhook URL is a credential.** Possession of it is permission to
    post into the channel, exactly like the report CDN link. It is never
    logged, never printed, and never included in an error message.
  * **No card data, ever.** A finding's payload carries BINs, last-4 digits
    and cardholder names. The channel is a wider audience than the app, so
    messages carry merchant name, score, exposure and fingerprints only.
  * **stdlib only** - urllib, like the rest of the runner.
"""

import json
import urllib.error
import urllib.request

import config
import dedup


# Slack's own limits, which the formatting has to respect rather than
# discover in production: 50 blocks per message, 3000 characters per text
# object, 150 for a header.
MAX_BLOCKS = 45
MAX_TEXT = 2900
MAX_HEADER = 148

# How many findings get a line of their own before the rest become a count.
# A message longer than this stops being read, which defeats the purpose.
MAX_LISTED = 10

# Error details can be long and are attacker-influenced in principle; they go
# into a public-ish channel, so they are capped.
MAX_DETAIL = 280

POST_TIMEOUT = 10


# ── What counts as news ──────────────────────────────────────────────────────

# The kinds, in the order they appear in a message. Order is by how much
# someone needs to act, not alphabetically.
NEW = 'new'
ESCALATED = 'escalated'
REOPENED = 'reopened'

# The kinds that reach Slack. REOPENED is deliberately absent: a dismissed
# finding whose 48-hour cooloff has expired is neither new nor worse - it is
# simply eligible again. It lands in Pendientes, where the person who
# dismissed it will see it. Interrupting someone about a merchant they have
# already judged once is precisely how a channel earns a mute.
#
# notable() still PRODUCES it, because the runner logs it and a future
# consumer may want it. Only the message filters on this.
ANNOUNCED_KINDS = (NEW, ESCALATED)


def notable(decision, finding, section):
    """Project a dedup Decision into a notification event, or None.

    The single place that decides what the channel hears about. Returning
    None for the overwhelmingly common UPDATE is the whole point - see the
    module docstring.
    """
    kind = None
    detail = None

    if decision.action == dedup.INSERT:
        kind, detail = NEW, 'primera detección'
    elif decision.action == dedup.REOPEN:
        # Either an escalation past the cooloff, or the cooloff simply
        # ending. Both put the finding back in the queue, but only the first
        # means the merchant got worse.
        kind = ESCALATED if decision.escalated else REOPENED
        detail = decision.escalated or 'terminó el periodo de silencio'
    elif decision.action == dedup.UPDATE and decision.escalated:
        kind, detail = ESCALATED, decision.escalated
    else:
        # UPDATE with no material change, or SUPPRESS. This is most of them.
        return None

    # The zero-settlement detector puts its counts under `metrics`; the
    # exposure model has none. Read defensively either way - a finding from an
    # engine older than a field is a normal thing to receive here.
    metrics = finding.get('metrics') or {}

    return {
        'kind':         kind,
        'company_name': finding.get('company_name') or '(sin nombre)',
        'confidence':   finding.get('confidence'),
        'section':      section,
        'risk_score':   finding.get('risk_score'),
        'exposure':     finding.get('estimated_chargeback_exposure'),
        'currency':     finding.get('currency'),
        # How much of the merchant's book the exposure figure is drawn from.
        # Without it the channel prints a bare amount, which reads as the
        # merchant's whole trade - the misreading the 2026-09-13 scoping work
        # exists to prevent, still live in Slack until now.
        'settled_count': finding.get('suspicious_settled_count'),
        'attempts':      metrics.get('attempts'),
        'cards':         metrics.get('distinct_cards'),
        'ips':           metrics.get('distinct_ips'),
        'fingerprints': list(finding.get('fingerprints') or []),
        'detail':       detail,
    }


# ── Formatting ───────────────────────────────────────────────────────────────

def _esc(text) -> str:
    """Slack requires these three escaped in message text.

    Merchant names really do contain ampersands, and an unescaped one either
    swallows the rest of the line or renders as a broken entity.
    """
    return (str(text if text is not None else '')
            .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))


def _clip(text, limit) -> str:
    text = str(text if text is not None else '')
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _money(amount, currency) -> str:
    """Amount with its currency, or honestly without one.

    Mirrors the apps: rows from before the 2026-09 currency fix carry
    'UNKNOWN', where the engine could not tell GTQ from USD. Claiming either
    would be a guess, and a guess about money in an alerting channel is worse
    than an admission.
    """
    if amount is None:
        return '—'
    try:
        formatted = f'{float(amount):,.2f}'
    except (TypeError, ValueError):
        return '—'
    if not currency or currency == 'UNKNOWN':
        return f'{formatted} (sin moneda)'
    return f'{currency} {formatted}'


def country_label(country_code) -> str:
    """'Panamá (PA)', or just the code if it is not one of ours.

    Every line carries this because different ops people watch different
    countries, and the first question anyone scanning the channel asks is
    "is this mine?".
    """
    if not country_code:
        return 'país desconocido'
    try:
        return f'{config.country_by_code(country_code)["name"]} ({country_code.upper()})'
    except ValueError:
        return str(country_code)


_KIND_LABEL = {
    NEW:       'NUEVO',
    ESCALATED: 'ESCALÓ',
    REOPENED:  'VOLVIÓ',
}

# An emoji per kind, so the two states are separable at a glance on a phone
# without reading the word. Slack renders these from their shortcodes.
_KIND_ICON = {
    NEW:       ':new:',
    ESCALATED: ':chart_with_upwards_trend:',
    REOPENED:  ':leftwards_arrow_with_hook:',
}


# Fingerprints and tiers arrive from the engine as English snake_case keys.
# They are identifiers, not prose, and a channel read by ops in Spanish should
# never show them raw. These are the SAME strings the app shows in Pendientes
# (desktop/src/lib/patterns.ts) - deliberately duplicated across the language
# boundary rather than fetched, because the runner must be able to describe a
# finding with Supabase unreachable. tests/test_slack_spanish.py fails if the
# two ever drift.
_PATTERN_LABEL = {
    'amount_ladder':                       'Escalera de montos',
    'velocity_burst':                      'Ráfaga de intentos',
    'round_number_repetition':             'Montos redondos',
    'bin_diversity_burst':                 'Muchos bancos distintos',
    'high_reject_rate':                    'Rechazos muy altos',
    'critical_codes':                      'Rechazos por fraude',
    'minfraud_blocked':                    'Bloqueado por MinFraud',
    'watchlist_merchant':                  'Reincidente',
    'watchlist_card':                      'Tarjeta ya marcada',
    'cross_merchant_reuse':                'Tarjeta compartida',
    'channel_switch_retry':                'Reintento por otro canal',
    'real_name_rotation':                  'Identidades rotativas',
    'multi_test_transactions':             'Cobros de prueba',
    'foreign_card_velocity':               'Tarjetas extranjeras',
    'confirmed_indicator_exact':           'Fraude confirmado',
    'confirmed_indicator_cross_merchant':  'Confirmado en otro comercio',
    'confirmed_indicator_fuzzy':           'Parecido a fraude confirmado',
    # Detector de sesiones sin liquidación. Sin traducir hasta 2026-09: el
    # test de contrato sólo miraba `fingerprints.append(...)` y este detector
    # usa `fps.append(...)`, así que el código crudo llegaba hasta Slack.
    'zero_settlement_session':             'Sesión sin liquidación',
    'card_fanout_burst':                   'Ráfaga de tarjetas',
    'card_fanout_session':                 'Varias tarjetas en una hora',
    'card_fanout_slow':                    'Varias tarjetas en el día',
    'card_fanout_pair':                    'Dos tarjetas seguidas',
    'card_diversity':                      'Muchas tarjetas y BINs',
    'single_ip_multi_card':                'Una IP, muchas tarjetas',
    'payer_identity_rotation':             'Identidades del pagador rotativas',
    'near_duplicate_identity':             'Identidades casi idénticas',
    'repeated_decline_code':               'Mismo código de rechazo',
    'unresolved_attempts_only':            'Intentos sin resolver',
}

# The confidence tier used to be printed on every line ("Crítico, puntaje
# 92"), and had its own label map because `Critical` is an English identifier
# and ops reads this channel in Spanish.
#
# Both are gone as of 2026-09-14. Every finding that reaches a message is
# Critical — announceable() admits nothing else — so the word carried no
# information and cost a line's worth of width on a phone. The header says
# "críticos" once, which is where it belongs.
#
# If Monitor ever returns to the channel, this needs to come back with it.


# The runner_cycles.outcome vocabulary (migration 0012). Same reasoning as
# the fingerprints: these are column values, not sentences, and "cms_error"
# in a Spanish channel tells an analyst nothing they can act on.
_OUTCOME_LABEL = {
    'running':        'en curso',
    'ok':             'correcto',
    'no_email':       'no llegó el correo con el reporte',
    'cms_error':      'falló la descarga desde el CMS',
    'token_error':    'el token del CMS está vencido o ilegible',
    'gmail_error':    'falló la conexión con Gmail',
    'supabase_error': 'falló la escritura en Supabase',
    'config_error':   'falta configuración en el runner',
    'unexpected':     'error inesperado',
}


def outcome_label(outcome) -> str:
    """The Spanish description of a cycle outcome."""
    key = (outcome or '').strip()
    return _OUTCOME_LABEL.get(key, key or '?')


def pattern_label(fingerprint) -> str:
    """The Spanish name for a fingerprint.

    An unknown key is humanised rather than passed through: the engine gains
    detectors faster than this file gets updated, and 'Card fanout fast' reads
    as an oversight while `card_fanout_fast` reads as a bug.
    """
    fp = (fingerprint or '').strip()
    if fp in _PATTERN_LABEL:
        return _PATTERN_LABEL[fp]
    return fp.replace('_', ' ').capitalize() if fp else '?'


def _scope_line(event) -> str:
    """What this merchant actually did, in money or in attempts.

    Two shapes, because the two detectors measure different things and a
    bare number from either one is misread. An exposure figure without its
    scope reads as the merchant's whole trade - which is what it used to
    mean, before the 2026-09-13 fix narrowed it to the charges a finding
    actually implicates. And "sin liquidación" on its own says nothing about
    whether the session was six attempts or six hundred.
    """
    exposure = event.get('exposure')
    settled = event.get('settled_count')

    if exposure:
        money = _money(exposure, event.get('currency'))
        if settled:
            s = '' if settled == 1 else 's'
            return f'exposición {money} sobre {settled} cargo{s} liquidado{s}'
        # An older payload with no scope recorded. Say the amount and stop
        # rather than implying a scope nobody computed.
        return f'exposición {money}'

    # Nothing settled: the session is the story. Counts come from the
    # zero-settlement detector's own metrics and are simply absent on an
    # exposure-model finding, which is fine - it then reads "sin liquidación".
    bits = []
    if event.get('attempts'):
        bits.append(f'{event["attempts"]} intentos')
    if event.get('cards'):
        bits.append(f'{event["cards"]} tarjetas')
    if event.get('ips'):
        bits.append(f'{event["ips"]} IP')
    return 'sin liquidación' + (' · ' + ' · '.join(bits) if bits else '')


def _finding_line(event, country_code) -> str:
    """One merchant, as a block. Four lines at most, in priority order:

        what happened · who · how bad
        why it is being announced   (only when it says something new)
        what is at stake
        which patterns fired

    The country is on the line as well as in the header, because ops is split
    by country and "is this mine?" should be answerable from any single line -
    a forwarded screenshot, a quoted reply, or a header that has scrolled
    away. The short code rather than the full name: four repetitions of
    "Panamá (PA)" in one message is noise.

    It is the country of the FILE (from its own country_name column), so
    within one message it is necessarily the same on every line - one report
    is one country.
    """
    score = event.get('risk_score')
    code = (country_code or '??').upper()
    kind = event['kind']

    parts = [
        f'{_KIND_ICON.get(kind, "")} *{_KIND_LABEL.get(kind, kind)}* · '
        f'*{_esc(event["company_name"])}* · `{_esc(code)}` — '
        f'puntaje *{score if score is not None else "?"}*'.lstrip(),
    ]
    # 'primera detección' beside a line already labelled NUEVO is a word doing
    # no work. An escalation's detail carries the old score and the new one,
    # which is the whole reason anyone is being told.
    detail = event.get('detail')
    if detail and kind != NEW:
        parts.append(f'_{_esc(detail)}_')
    parts.append(_scope_line(event))
    fingerprints = event.get('fingerprints') or []
    if fingerprints:
        parts.append(' · '.join(_esc(pattern_label(f))
                                 for f in fingerprints[:6]))
    return _clip('\n'.join(parts), MAX_TEXT)


def _section(text) -> dict:
    return {'type': 'section', 'text': {'type': 'mrkdwn', 'text': text}}


def _context(text) -> dict:
    return {'type': 'context',
            'elements': [{'type': 'mrkdwn', 'text': _clip(text, MAX_TEXT)}]}


def announceable(events):
    """The subset of a cycle's events the channel is allowed to hear about.

    One place, so the trigger and the contents can never disagree - a message
    that fires on one rule and renders by another is how an empty alert gets
    sent. Two filters, and both are load-bearing:

      confidence  Critical only. Monitor is recorded, reviewable in the apps,
                  and silent here.
      kind        NEW or ESCALATED. Not REOPENED - see ANNOUNCED_KINDS.

    Tolerates a None in the list. notable() returns None for the common
    re-detection and run.py already drops those before they get here, but
    this is the notification path: it runs AFTER the findings are safely
    written, and nothing wraps it in a try/except. An AttributeError here
    would fail a cycle that had already done its job perfectly - which is
    the one outcome this module promises never to cause.
    """
    return [e for e in (events or []) if e
            and e.get('confidence') == 'Critical'
            and e.get('kind') in ANNOUNCED_KINDS]


def build_findings_message(country_code, events, summary=None):
    """The Slack payload for one cycle's news, or None if there is none.

    Returning None rather than an empty message is deliberate: a quiet cycle
    should produce silence, not a "nothing to report" that trains people to
    skim past the channel.

    What reaches here is only ever a merchant that is newly Critical or has
    just become Critical. Everything else a cycle produces - Monitor findings,
    the fifteen re-detections of a merchant already in the queue, a dismissed
    finding whose cooloff expired - is the apps' job to show. A notification
    about something a person has already been told about is how a channel
    gets muted, and then the message that matters arrives somewhere nobody
    looks.
    """
    critical = announceable(events)
    if not critical:
        return None

    summary = summary or {}

    n_new = sum(1 for e in critical if e['kind'] == NEW)
    n_esc = sum(1 for e in critical if e['kind'] == ESCALATED)

    headline = []
    if n_new:
        headline.append(f'{n_new} crítico{"s" if n_new != 1 else ""} '
                        f'nuevo{"s" if n_new != 1 else ""}')
    if n_esc:
        headline.append(f'{n_esc} escaló a crítico' if n_esc == 1
                        else f'{n_esc} escalaron a crítico')

    header = _clip(
        f':rotating_light: {country_label(country_code)} — '
        f'{", ".join(headline)}',
        MAX_HEADER)

    blocks = [{'type': 'header',
               'text': {'type': 'plain_text', 'text': header, 'emoji': True}}]

    window = summary.get('date_range') or {}
    meta = []
    if window.get('start'):
        meta.append(f'ventana {window.get("start")} → {window.get("end")}')
    if summary.get('unique_transactions') is not None:
        meta.append(f'{summary["unique_transactions"]:,} transacciones')
    if meta:
        blocks.append(_context(' · '.join(meta)))

    # New before escalated, worst-first inside each: the channel is scanned
    # top down, and a merchant nobody has ever looked at outranks one that is
    # already known and has got worse.
    ordered = sorted(
        critical,
        key=lambda e: (e['kind'] != NEW, -(e.get('risk_score') or 0)))

    for event in ordered[:MAX_LISTED]:
        blocks.append(_section(_finding_line(event, country_code)))

    if len(ordered) > MAX_LISTED:
        blocks.append(_context(
            f'…y {len(ordered) - MAX_LISTED} comercio(s) crítico(s) más.'))

    blocks.append(_context(
        'Revisar en *Pendientes* de la app · '
        f'runner {_esc((country_code or "?").upper())}'))

    # Text is what a notification preview and a screen reader get; blocks are
    # what the channel renders. Sending only blocks produces a silent, empty
    # push notification on mobile.
    fallback = _clip(f'{country_label(country_code)}: {", ".join(headline)}',
                     MAX_TEXT)
    return {'text': fallback, 'blocks': blocks[:MAX_BLOCKS]}


def build_queue_message(pending, oldest_days=None):
    """The daily nudge, or None when there is nothing to nudge about.

    An empty queue produces silence. A cheerful "0 pendientes" every morning is
    how a channel becomes background noise, and then the message that matters
    arrives somewhere nobody looks.
    """
    if not pending:
        return None

    plural = pending != 1
    headline = (f'{pending} comercio{"s" if plural else ""} '
                f'pendiente{"s" if plural else ""} de revisión')

    line = f'*{pending}* ' + headline.split(' ', 1)[1]
    if oldest_days is not None and oldest_days >= 1:
        line += (f' · el más antiguo lleva *{int(oldest_days)} '
                 f'día{"s" if int(oldest_days) != 1 else ""}* esperando')

    return {
        # The fallback is what a mobile push and a screen reader get, so it has
        # to agree with the rendered line — including the plural.
        'text': _clip(headline, MAX_TEXT),
        'blocks': [
            _section(f':clipboard: {line}'),
            _context('Revisar en *Pendientes* de la app · '
                     'confirmar fraude o descartar con motivo'),
        ],
    }


def build_health_message(title, detail=None, fix=None, level='warn'):
    """A message about the runner itself rather than about fraud."""
    icon = {'warn': ':warning:', 'bad': ':x:', 'info': ':information_source:'}
    header = _clip(f'{icon.get(level, ":warning:")} Runner — {title}',
                   MAX_HEADER)
    blocks = [{'type': 'header',
               'text': {'type': 'plain_text', 'text': header, 'emoji': True}}]
    if detail:
        blocks.append(_section(f'```{_clip(_esc(detail), MAX_DETAIL)}```'))
    if fix:
        blocks.append(_context(f'*Qué hacer:* {_esc(fix)}'))
    return {'text': _clip(f'Runner — {title}', MAX_TEXT), 'blocks': blocks}


# ── Sending ──────────────────────────────────────────────────────────────────

def post(payload, webhook_url) -> bool:
    """POST one payload. Returns whether Slack accepted it.

    Never raises, and never puts the webhook URL into a message: urllib's own
    exceptions embed the URL they were called with, which is exactly how a
    credential ends up in a log file.
    """
    if not webhook_url or not payload:
        return False

    data = json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(
        webhook_url, data=data,
        headers={'Content-Type': 'application/json'}, method='POST')

    try:
        with urllib.request.urlopen(request, timeout=POST_TIMEOUT) as response:
            body = response.read().decode('utf-8', errors='replace').strip()
            if response.status == 200 and body == 'ok':
                return True
            print(f'  [slack] respuesta inesperada ({response.status}): '
                  f'{body[:120]}')
            return False
    except urllib.error.HTTPError as e:
        print(f'  [slack] no se pudo enviar: {_http_hint(e.code)}')
        return False
    except urllib.error.URLError as e:
        print(f'  [slack] no se pudo enviar: sin conexión ({e.reason})')
        return False
    except Exception as e:                                  # noqa: BLE001
        print(f'  [slack] no se pudo enviar: {type(e).__name__}')
        return False


def _http_hint(code) -> str:
    """Slack's failure codes, named. Each has a different cause and cure, and
    a bare number sends someone to search for it."""
    if code == 404:
        return ('404 - el webhook ya no existe. El canal fue archivado o '
                'eliminado, o alguien quitó la app de Slack.')
    if code == 403:
        return ('403 - el webhook fue revocado, o la app perdió acceso al '
                'canal (pasa al convertir un canal público en privado).')
    if code == 410:
        return '410 - el webhook está desactivado permanentemente.'
    if code == 400:
        return ('400 - Slack rechazó el formato del mensaje. Es un error '
                'nuestro, no de configuración.')
    if code == 429:
        return '429 - demasiados mensajes; Slack está limitando el ritmo.'
    return f'HTTP {code}'


# ── Entry points ─────────────────────────────────────────────────────────────

def send_findings(country_code, events, summary=None) -> bool:
    """Tell the channel about one cycle's news. Silent when there is none."""
    if not config.slack_enabled(country_code):
        return False
    payload = build_findings_message(country_code, events, summary)
    if payload is None:
        return False
    return post(payload, config.slack_webhook_for(country_code))


def send_health(title, detail=None, fix=None, level='warn',
                country_code=None) -> bool:
    if not config.slack_enabled(country_code):
        return False
    return post(build_health_message(title, detail, fix, level),
                config.slack_webhook_for(country_code))


def send_queue_reminder(pending, oldest_days=None) -> bool:
    """One nudge a day about the review queue. Silent when it is empty."""
    if not config.slack_enabled():
        return False
    payload = build_queue_message(pending, oldest_days)
    if payload is None:
        return False
    return post(payload, config.slack_webhook_for())


def send_test(country_code=None) -> bool:
    """Prove the webhook works, without waiting for real fraud."""
    return post(
        build_health_message(
            'prueba de conexión',
            detail='Si ves este mensaje, el webhook está bien configurado.',
            fix='Nada. Esta es una prueba enviada a mano.',
            level='info'),
        config.slack_webhook_for(country_code))
