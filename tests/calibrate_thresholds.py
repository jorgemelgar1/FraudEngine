#!/usr/bin/env python3
"""Threshold calibration harness for the zero-settlement (card-testing) detector.

The detector's constants — ZERO_SETTLEMENT_*, FANOUT_*, IP_MULTI_*, the W_*
weights, and the SECTION_* tier cutoffs — were chosen as starting guesses when
the detector was written. This script is how you replace those guesses with
evidence, using a real CSV, without pasting cardholder data anywhere.

    python tests/calibrate_thresholds.py <csv_path> \
        --fraud "Mandados sv,Inversiones Kabu" \
        --benign "Comercio Exitoso"

What you get:

  A. Gate funnel        — how many merchants each entry gate removes, in order.
  B. Labeled verdicts   — for every merchant you named with --fraud/--benign:
                          did the detector catch it, at what score/tier, and if
                          it was gated out, WHICH gate rejected it and by how
                          much. This is the number you tune against.
  C. Signal firing rates— how often each fingerprint fires among the merchants
                          that entered. A signal that fires on 0% or 100% of
                          them carries no information and its weight is doing
                          nothing.
  D. Threshold sweeps   — how the Critical / Monitor / gated-out counts move as
                          each threshold is varied one at a time.
  E. Near misses        — merchants that failed exactly ONE gate, and by how
                          little. These are where a threshold change would
                          bite first, in either direction.

PRIVACY: this script prints merchant names, counts, rates, and score
components only. It never prints cardholder names, payer emails, IPs, BINs,
card last-four, or transaction ids, so its output is safe to paste into a
ticket or chat. It reads the CSV locally and writes nothing but the optional
--json report.

SCOPE: this calls the detector directly, so the counts here are BEFORE the
section-priority de-dup that analyze() applies afterwards (a merchant already
surfaced in the Critical/Monitor tiers is shown there and dropped from this
section). Expect the final report to list the same merchants or fewer. That
is intentional — you are calibrating the detector, not the report layout.
"""

import argparse
import json
import os
import sys
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import analyze  # noqa: E402


# ── Fingerprint → weight attribution ─────────────────────────────────────────
# The detector returns the fingerprints that fired but not their individual
# contributions, so we reconstruct them from the same constants it used. Keep
# this table in sync with detect_suspicious_rejected_merchants.

def _weight_for(fingerprint, metrics):
    """Points this fingerprint contributed to the merchant's score."""
    if fingerprint == 'single_ip_multi_card':
        # One fingerprint name, two tiers — disambiguate via the metric the
        # detector used to pick between them.
        strong = metrics.get('max_cards_per_ip', 0) >= analyze.IP_MULTI_CARD_STRONG
        return analyze.W_IP_MULTI_STRONG if strong else analyze.W_IP_MULTI_WEAK
    return {
        'zero_settlement_session': analyze.W_ZERO_SETTLEMENT,
        'card_fanout_burst':       analyze.W_FANOUT_BURST,
        'card_fanout_session':     analyze.W_FANOUT_SESSION,
        'card_fanout_slow':        analyze.W_FANOUT_SLOW,
        'card_fanout_pair':        analyze.W_FANOUT_PAIR,
        'payer_identity_rotation': analyze.W_IDENTITY_ROTATION,
        'near_duplicate_identity': analyze.W_NEAR_DUPLICATE,
        'repeated_decline_code':   analyze.W_REPEAT_CODE,
        'card_diversity':          analyze.W_CARD_DIVERSITY,
        'watchlist_merchant':      analyze.W_WATCHLIST_MERCHANT,
        'watchlist_card':          analyze.W_WATCHLIST_CARD,
    }.get(fingerprint, 0)


# ── Gate analysis ────────────────────────────────────────────────────────────

def merchant_gate_stats(df_raw):
    """Per-merchant view of the three entry-gate inputs, for EVERY merchant.

    Mirrors the opening of detect_suspicious_rejected_merchants so the numbers
    line up exactly with what the gate sees.
    """
    attempts_all = analyze._build_attempts(df_raw)
    attempts_all = attempts_all[attempts_all['status'] != 'DRAFT']
    stats = {}
    if len(attempts_all) == 0:
        return stats
    for mname, m in attempts_all.groupby('company_name', sort=False):
        n_attempts = len(m)
        n_succ = int((m['status'] == 'SUCCEEDED').sum())
        stats[mname] = {
            'attempts': n_attempts,
            'succeeded': n_succ,
            'success_rate': (n_succ / n_attempts) if n_attempts else 0.0,
            'distinct_cards': int(m['_card_key'].nunique()),
        }
    return stats


def gate_failures(st):
    """Which entry gates this merchant fails, with the shortfall on each."""
    fails = []
    if st['attempts'] < analyze.ZERO_SETTLEMENT_MIN_ATTEMPTS:
        fails.append((
            'min_attempts',
            f"{st['attempts']} < {analyze.ZERO_SETTLEMENT_MIN_ATTEMPTS} "
            f"(short by {analyze.ZERO_SETTLEMENT_MIN_ATTEMPTS - st['attempts']})",
        ))
    if st['success_rate'] > analyze.ZERO_SETTLEMENT_MAX_SUCCESS_RATE:
        fails.append((
            'max_success_rate',
            f"{st['success_rate']:.1%} > {analyze.ZERO_SETTLEMENT_MAX_SUCCESS_RATE:.1%} "
            f"({st['succeeded']}/{st['attempts']} settled)",
        ))
    if st['distinct_cards'] < analyze.ZERO_SETTLEMENT_MIN_DISTINCT_CARDS:
        fails.append((
            'min_distinct_cards',
            f"{st['distinct_cards']} < {analyze.ZERO_SETTLEMENT_MIN_DISTINCT_CARDS}",
        ))
    return fails


# ── Sweeps ───────────────────────────────────────────────────────────────────

def sweep(df_raw, wl_merchants, wl_cards, currency, const_name, values):
    """Re-run the detector once per candidate value of one module constant.

    The detector reads its constants as module globals at call time, so
    temporarily rebinding one and re-running gives a true end-to-end count
    rather than an approximation.
    """
    original = getattr(analyze, const_name)
    out = []
    try:
        for v in values:
            setattr(analyze, const_name, v)
            found = analyze.detect_suspicious_rejected_merchants(
                df_raw, wl_merchants, wl_cards, currency,
            )
            out.append({
                'value': v,
                'critical': sum(1 for f in found if f['confidence'] == 'Critical'),
                'monitor': sum(1 for f in found if f['confidence'] == 'Monitor'),
                'total': len(found),
            })
    finally:
        setattr(analyze, const_name, original)
    return out


def _fmt_sweep(rows, current, label):
    lines = [f'  {label}']
    for r in rows:
        marker = '  <- current' if r['value'] == current else ''
        lines.append(
            f"    {str(r['value']):>8}  ->  {r['critical']:>3} Critical  "
            f"{r['monitor']:>3} Monitor  {r['total']:>3} total{marker}"
        )
    return '\n'.join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Calibrate the zero-settlement detector against a real CSV.',
    )
    ap.add_argument('csv_path', help='Transaction CSV to calibrate against')
    ap.add_argument('--fraud', default='',
                    help='Comma-separated merchants ops has CONFIRMED as fraud. '
                         'These are the true positives the detector must catch.')
    ap.add_argument('--benign', default='',
                    help='Comma-separated merchants ops has confirmed as LEGITIMATE. '
                         'These must NOT be flagged.')
    ap.add_argument('--watchlist', default=None,
                    help='Optional watchlist JSON, so watchlist signals score '
                         'the same way they would in a real run.')
    ap.add_argument('--json', default=None,
                    help='Also write the full report as JSON to this path.')
    ap.add_argument('--top', type=int, default=25,
                    help='How many near-miss merchants to list (default 25)')
    args = ap.parse_args()

    fraud = [s.strip() for s in args.fraud.split(',') if s.strip()]
    benign = [s.strip() for s in args.benign.split(',') if s.strip()]

    # Load exactly the way analyze() does, so every number here matches what a
    # real run would produce. load_and_dedupe validates the schema, parses the
    # timestamps, and hands back (raw rows, deduped rows) — the detector wants
    # the raw ones because it rebuilds its own attempt-level view.
    df_raw, df_u = analyze.load_and_dedupe(args.csv_path)

    wl = analyze.load_watchlist(args.watchlist) if args.watchlist else {'merchants': {}, 'cards': {}}
    wl_merchants = set(wl.get('merchants', {}))
    wl_cards = set(wl.get('cards', {}))
    currency = analyze.detect_currency(df_u)

    stats = merchant_gate_stats(df_raw)
    found = analyze.detect_suspicious_rejected_merchants(
        df_raw, wl_merchants, wl_cards, currency,
    )
    by_name = {f['company_name']: f for f in found}

    report = {'csv': os.path.basename(args.csv_path), 'currency': currency}

    print('=' * 74)
    print(f'Zero-settlement detector calibration — {os.path.basename(args.csv_path)}')
    print(f'{len(df_raw)} rows · {len(stats)} merchants · currency {currency}')
    print('=' * 74)

    # ── A. Gate funnel ───────────────────────────────────────────────────────
    n_total = len(stats)
    n_attempts_ok = sum(1 for s in stats.values()
                        if s['attempts'] >= analyze.ZERO_SETTLEMENT_MIN_ATTEMPTS)
    n_rate_ok = sum(1 for s in stats.values()
                    if s['attempts'] >= analyze.ZERO_SETTLEMENT_MIN_ATTEMPTS
                    and s['success_rate'] <= analyze.ZERO_SETTLEMENT_MAX_SUCCESS_RATE)
    n_gate_ok = sum(1 for s in stats.values() if not gate_failures(s))
    n_crit = sum(1 for f in found if f['confidence'] == 'Critical')
    n_mon = sum(1 for f in found if f['confidence'] == 'Monitor')

    funnel = {
        'merchants': n_total,
        'pass_min_attempts': n_attempts_ok,
        'pass_max_success_rate': n_rate_ok,
        'pass_min_distinct_cards': n_gate_ok,
        'scored_monitor_or_above': len(found),
        'critical': n_crit,
        'monitor': n_mon,
        'entered_gate_but_scored_below_monitor': n_gate_ok - len(found),
    }
    report['funnel'] = funnel

    def _funnel_line(label, value, note=''):
        print(f'   {label:<44}{value:>6}{note}')

    print('\nA. ENTRY GATE FUNNEL')
    _funnel_line('all merchants', n_total)
    _funnel_line(f'...with >= {analyze.ZERO_SETTLEMENT_MIN_ATTEMPTS} attempts',
                 n_attempts_ok)
    _funnel_line(f'...and <= {analyze.ZERO_SETTLEMENT_MAX_SUCCESS_RATE:.0%} success rate',
                 n_rate_ok)
    _funnel_line(f'...and >= {analyze.ZERO_SETTLEMENT_MIN_DISTINCT_CARDS} distinct cards',
                 n_gate_ok, '   <- entered scoring')
    _funnel_line(f'...scored >= {analyze.SECTION_MONITOR_THRESHOLD} (Monitor)',
                 len(found))
    _funnel_line(f'...scored >= {analyze.SECTION_CRITICAL_THRESHOLD} (Critical)',
                 n_crit)
    if n_gate_ok - len(found) > 0:
        print(f'   (dropped: {n_gate_ok - len(found)} passed the gate but scored '
              f'below Monitor — zero-settlement with no escalation signal)')

    # ── B. Labeled verdicts ──────────────────────────────────────────────────
    if fraud or benign:
        print('\nB. LABELED MERCHANT VERDICTS')
        verdicts = []
        for label, names, want_flagged in (('FRAUD', fraud, True),
                                           ('BENIGN', benign, False)):
            for name in names:
                st = stats.get(name)
                f = by_name.get(name)
                if st is None:
                    print(f'   [{label}] {name}: NOT FOUND in this CSV '
                          f'(check spelling — match is exact)')
                    verdicts.append({'merchant': name, 'label': label,
                                     'result': 'not_in_csv'})
                    continue
                if f is not None:
                    ok = '✓' if want_flagged else '✗ FALSE POSITIVE'
                    print(f'   [{label}] {name}: flagged {f["confidence"]} '
                          f'(score {f["risk_score"]})  {ok}')
                    contribs = [(fp, _weight_for(fp, f.get('metrics', {})))
                                for fp in f['fingerprints']]
                    for fp, w in contribs:
                        print(f'              +{w:<3} {fp}')
                    raw = sum(w for _fp, w in contribs)
                    if raw > f['risk_score']:
                        print(f'              (raw {raw} capped to '
                              f'{f["risk_score"]})')
                    verdicts.append({
                        'merchant': name, 'label': label,
                        'result': 'flagged', 'confidence': f['confidence'],
                        'score': f['risk_score'],
                        'contributions': dict(contribs),
                        'metrics': f.get('metrics', {}),
                    })
                else:
                    fails = gate_failures(st)
                    ok = '✗ MISSED' if want_flagged else '✓'
                    if fails:
                        reason = '; '.join(f'{g}: {d}' for g, d in fails)
                        print(f'   [{label}] {name}: gated out — {reason}  {ok}')
                        result = 'gated_out'
                    else:
                        print(f'   [{label}] {name}: entered scoring but landed '
                              f'below Monitor ({analyze.SECTION_MONITOR_THRESHOLD})  {ok}')
                        reason = 'score below Monitor threshold'
                        result = 'scored_below_monitor'
                    verdicts.append({
                        'merchant': name, 'label': label, 'result': result,
                        'reason': reason,
                        'gate_stats': {k: v for k, v in st.items()},
                    })
        report['verdicts'] = verdicts

        missed = [v for v in verdicts
                  if v['label'] == 'FRAUD' and v['result'] != 'flagged']
        fps = [v for v in verdicts
               if v['label'] == 'BENIGN' and v['result'] == 'flagged']
        print(f'\n   SUMMARY: {len(fraud) - len(missed)}/{len(fraud)} confirmed-fraud '
              f'merchants caught, {len(fps)} false positive(s) on the benign list.')
        if missed:
            print('   The "gated out" reasons above tell you exactly which '
                  'threshold to relax, and by how much.')

    # ── C. Signal firing rates ───────────────────────────────────────────────
    print('\nC. SIGNAL FIRING RATES (among the '
          f'{len(found)} merchants that scored >= Monitor)')
    if found:
        counts = Counter(fp for f in found for fp in f['fingerprints'])
        rates = {}
        for fp, c in counts.most_common():
            pct = c / len(found)
            rates[fp] = {'count': c, 'rate': round(pct, 4)}
            note = ''
            if pct == 1.0 and fp != 'zero_settlement_session':
                note = '   <- fires on ALL; carries no discriminating signal'
            elif pct < 0.02:
                note = '   <- almost never fires; weight is inert'
            print(f'   {fp:<28} {c:>4}  ({pct:>6.1%}){note}')
        for fp in ('card_fanout_burst', 'card_fanout_session', 'card_fanout_slow',
                   'card_fanout_pair', 'single_ip_multi_card',
                   'payer_identity_rotation', 'near_duplicate_identity',
                   'repeated_decline_code', 'card_diversity'):
            if fp not in counts:
                print(f'   {fp:<28} {0:>4}  ({0:>6.1%})   <- NEVER fires on this CSV')
        report['signal_rates'] = rates
    else:
        print('   (no merchants entered — nothing to measure)')

    # ── C2. Score distribution / saturation ──────────────────────────────────
    # A score that saturates at the 100 cap has thrown away the information
    # that would separate "bad" from "much worse", and it makes the Critical
    # cutoff inert: if every finding is pinned at 100, moving the threshold
    # between 40 and 70 changes nothing.
    if found:
        scores = sorted((f['risk_score'] for f in found), reverse=True)
        raw_scores = [
            sum(_weight_for(fp, f.get('metrics', {})) for fp in f['fingerprints'])
            for f in found
        ]
        n_capped = sum(1 for r in raw_scores if r > 100)
        print('\nC2. SCORE DISTRIBUTION')
        print(f'   scores (desc): {", ".join(str(s) for s in scores[:20])}'
              f'{" ..." if len(scores) > 20 else ""}')
        print(f'   at the 100 cap: {n_capped}/{len(found)} '
              f'({n_capped / len(found):.0%})')
        report['score_distribution'] = {
            'scores': scores,
            'raw_scores': raw_scores,
            'capped': n_capped,
        }
        if n_capped and n_capped / len(found) >= 0.25:
            print('   ⚠ A quarter or more of findings hit the cap. The weights sum')
            print('     past 100 on ordinary card-testing patterns, so the Critical')
            print('     cutoff cannot discriminate among them — check section D: if')
            print('     SECTION_CRITICAL_THRESHOLD shows identical counts across its')
            print('     whole range, it is currently inert. Consider lowering the')
            print('     individual W_* weights so a typical finding lands mid-range.')

    # ── D. Threshold sweeps ──────────────────────────────────────────────────
    print('\nD. THRESHOLD SWEEPS (one constant varied at a time)')
    sweeps = {}
    for const_name, values, label in (
        ('ZERO_SETTLEMENT_MIN_ATTEMPTS', [3, 4, 5, 6, 8, 10, 15],
         'ZERO_SETTLEMENT_MIN_ATTEMPTS (entry: minimum attempts)'),
        ('ZERO_SETTLEMENT_MAX_SUCCESS_RATE', [0.0, 0.02, 0.05, 0.10, 0.20],
         'ZERO_SETTLEMENT_MAX_SUCCESS_RATE (entry: settle-rate ceiling)'),
        ('ZERO_SETTLEMENT_MIN_DISTINCT_CARDS', [1, 2, 3, 4],
         'ZERO_SETTLEMENT_MIN_DISTINCT_CARDS (entry: distinct-card floor)'),
        ('SECTION_CRITICAL_THRESHOLD', [40, 45, 50, 55, 60, 70],
         'SECTION_CRITICAL_THRESHOLD (tier cutoff)'),
        ('SECTION_MONITOR_THRESHOLD', [15, 20, 25, 30, 35],
         'SECTION_MONITOR_THRESHOLD (tier cutoff)'),
    ):
        rows = sweep(df_raw, wl_merchants, wl_cards, currency, const_name, values)
        sweeps[const_name] = rows
        print(_fmt_sweep(rows, getattr(analyze, const_name), label))
        # A threshold whose entire sweep produces one identical result is not
        # separating anything on this data — say so rather than leaving the
        # reader to compare rows by eye.
        distinct = {(r['critical'], r['monitor']) for r in rows}
        if len(distinct) == 1 and len(rows) > 1:
            print(f'      ⚠ inert on this CSV: every value in the swept range '
                  f'gives the same result')
    report['sweeps'] = sweeps

    # ── E. Near misses ───────────────────────────────────────────────────────
    print(f'\nE. NEAR MISSES (failed exactly one gate; top {args.top} by attempts)')
    near = []
    for name, st in stats.items():
        fails = gate_failures(st)
        if len(fails) == 1:
            near.append((name, st, fails[0]))
    near.sort(key=lambda x: -x[1]['attempts'])
    if near:
        for name, st, (gate, detail) in near[:args.top]:
            print(f'   {name[:38]:<38} {gate:<19} {detail}')
        print(f'   ({len(near)} merchants fail exactly one gate in total)')
    else:
        print('   (none)')
    report['near_misses'] = [
        {'merchant': n, 'gate': g, 'detail': d, **s} for n, s, (g, d) in near
    ]

    print('\n' + '=' * 74)
    print('Next step: if a confirmed-fraud merchant shows as "gated out" in B,')
    print('use its shortfall plus the sweep in D to pick a new threshold, edit')
    print('the constant at the top of analyze.py, and re-run this script.')
    print('=' * 74)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f'\nJSON report written to {args.json}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
