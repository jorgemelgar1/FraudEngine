# Calibrating the zero-settlement detector

The card-testing detector (`detect_suspicious_rejected_merchants` in
[analyze.py](../analyze.py)) has ~15 tunable constants. They were chosen as
starting guesses when the detector was written and have never been checked
against a real CSV. This document is how you check them, and what is already
known to be wrong.

## Running the harness

```bash
python tests/calibrate_thresholds.py <csv_path> \
    --fraud  "Mandados sv,Inversiones Kabu" \
    --benign "Comercio Exitoso"
```

`--fraud` is the list of merchants **ops has confirmed as fraud**; `--benign`
is the list confirmed legitimate. Merchant names must match the CSV exactly.
Both are optional but the harness is far more useful with them — they turn
"here are some numbers" into "the detector caught 2/2 and produced 0 false
positives".

Add `--watchlist path/to/wl.json` to include watchlist signals, and
`--json out.json` to save the full report.

**The output is safe to share.** The harness prints merchant names, counts,
rates, and score components only — never cardholder names, payer emails, IPs,
BINs, card last-four, or transaction ids. You can paste it into a ticket.

**Counts are pre-dedup.** The harness calls the detector directly, so it
reports what the detector found before `analyze()` decides which listing a
merchant appears under. The final report will therefore show the same
merchants or fewer. On the synthetic fixture the harness finds 3 while the
report lists 2.

Deduplication goes by **severity**, then by section. A merchant the exposure
model already rated Critical keeps that listing (it also carries the
chargeback-exposure figure); a merchant the exposure model only rated Monitor
loses to a Critical finding from this detector. Either way the loser's
fingerprints are merged into the survivor, so no reason is lost with the row.

Until 2026-09 the rule was section-first — this section always lost — and the
two models use different Critical lines (70 there, `SECTION_CRITICAL_THRESHOLD`
= 50 here. A Monitor exposure finding therefore suppressed a Critical
card-testing one, which then never reached the review queue at all, because
`build_findings_rows` queues Critical only. On this very fixture, Mandados sv
was a Critical/100 card-testing finding reported to nobody. Worth remembering
while reading old harness output against old reports: the discrepancy was not
only deduplication, it was loss.

## What each section tells you

| Section | Use it to answer |
|---|---|
| **A. Gate funnel** | Which of the three entry gates is doing the filtering, and whether one of them is removing almost everything. |
| **B. Labeled verdicts** | Did we catch the known fraud? If not, *which gate* rejected it and *by how much* — this is the number you tune against. |
| **C. Signal firing rates** | Which fingerprints never fire (their weight is inert) or always fire (they carry no discriminating information). |
| **C2. Score distribution** | Whether scores saturate at the 100 cap. |
| **D. Threshold sweeps** | How Critical/Monitor counts move as each constant varies. A sweep flagged `inert` changes nothing across its whole range. |
| **E. Near misses** | Merchants that failed exactly one gate. These flip first when you move a threshold — check them for false positives before committing a change. |

## The tuning loop

1. Run the harness against a real CSV with `--fraud` / `--benign` populated.
2. Any confirmed-fraud merchant showing **gated out** in section B is a miss.
   Its shortfall says exactly which constant to relax.
3. Cross-check the candidate value in section D — does relaxing it pull in a
   flood of new merchants, or just the one you wanted?
4. Check section E for what else would flip at that value.
5. Edit the constant at the top of `analyze.py`, re-run, repeat.
6. Re-run `python tests/test_rejected_merchants.py` — the synthetic
   regression tests must still pass.

## Known problem: the score saturates

Running the harness against the synthetic fixture already shows a structural
defect that does **not** need real data to confirm:

```
C2. SCORE DISTRIBUTION
   scores (desc): 100, 100, 35
   at the 100 cap: 2/3 (67%)

  SECTION_CRITICAL_THRESHOLD (tier cutoff)
          40  ->    2 Critical    1 Monitor    3 total
          ...
          70  ->    2 Critical    1 Monitor    3 total
      ⚠ inert on this CSV: every value in the swept range gives the same result
```

The weights sum past 100 on an ordinary card-testing session. Four signals
that co-occur in essentially every such session already exceed the cap:

```
W_ZERO_SETTLEMENT     25   (base — everything that enters gets this)
W_FANOUT_BURST        40
W_IP_MULTI_STRONG     25
W_IDENTITY_ROTATION   20
                     ---
                     110   -> capped to 100
```

Add `card_diversity` (15) and `repeated_decline_code` (20) — both common —
and the raw score reaches 145. Consequences:

- **The Critical cutoff is inert.** Anything past a couple of signals pins at
  100, so `SECTION_CRITICAL_THRESHOLD` can be set anywhere from 40 to 70 with
  no effect. The tier boundary is not actually being decided by the number.
- **Severity is unrankable.** A merchant with 4 signals and one with 7 both
  score 100, so sorting the section by `risk_score` does not put the worst
  offender first.

### Possible fix — DEFERRED BY DECISION (2026-08-24)

**The weights are frozen. Do not change them without a new decision.** The
rescale below is recorded as an option for whoever eventually runs the
real-CSV calibration; it is not a pending task and should not be applied on
the strength of the synthetic fixture alone.

The reasoning behind freezing: the saturation is real but it does not produce
*wrong* answers today — every merchant that pins at 100 is a merchant the
detector genuinely wants to flag as Critical. What is lost is the ability to
*rank* them and to move the Critical cutoff meaningfully. Both only start to
matter once there is real volume to rank, and re-tuning before then would
mean fitting the weights to fabricated data.

Rescale the weights so a *typical* card-testing merchant lands mid-range and
only an exceptional one approaches 100. Roughly halving the escalation
weights while keeping their relative ordering:

| Constant | Now | Proposed |
|---|---|---|
| `W_ZERO_SETTLEMENT` | 25 | 20 |
| `W_FANOUT_BURST` | 40 | 25 |
| `W_FANOUT_SESSION` | 30 | 18 |
| `W_FANOUT_SLOW` | 20 | 12 |
| `W_FANOUT_PAIR` | 10 | 6 |
| `W_IP_MULTI_STRONG` | 25 | 15 |
| `W_IP_MULTI_WEAK` | 10 | 6 |
| `W_IDENTITY_ROTATION` | 20 | 12 |
| `W_NEAR_DUPLICATE` | 15 | 10 |
| `W_REPEAT_CODE` | 20 | 12 |
| `W_CARD_DIVERSITY` | 15 | 9 |
| `W_WATCHLIST_MERCHANT` | 20 | 12 |
| `W_WATCHLIST_CARD` | 10 | 6 |

Under that scale the four-signal session above scores 72 instead of capping,
and the tier thresholds would need re-picking against real data — which is
the point: they would then actually decide something. If this is ever
revisited, run it against the real Mandados / Kabu CSVs first to confirm the
rescale does not drop them below the Critical line.

## Still open

- No run against a real CSV has happened yet. Every threshold in
  `analyze.py` remains a starting guess — and they stay that way until
  someone runs the harness above. Frozen by decision, not by oversight.
- `card_fanout_slow` and `near_duplicate_identity` never fire on the
  synthetic fixture, so their weights are untested. A real CSV will show
  whether they fire in practice at all.
- The `ZERO_SETTLEMENT_MAX_SUCCESS_RATE` sweep is inert on the fixture
  (merchants are either 0% or 100% settled). Real data has merchants in
  between; that is where this constant earns its keep.

### Changed in the 2026-09 integrity fixes

None of these were weight changes — the `W_*` constants are still frozen —
but three of them move scores, so harness output from before that date is not
comparable to output after it:

- **Card fan-out is timed on `last_intent_at`**, not `transaction_created_at`.
  Several attempts on one `transaction_id` share a single creation time, so
  the windows used to collapse a slow grind into `card_fanout_burst`, the top
  tier at 40 points. Expect fan-out tiers to come down on real data, and
  `card_fanout_slow` — listed above as never firing — to start firing.
- **A session with no declines caps at Monitor** and gains the
  `unresolved_attempts_only` fingerprint. Six PENDING attempts used to score
  Critical/100 with nothing declined and no aging rule.
- **Velocity bands are per-currency** (`VELOCITY_BANDS`). The old bands were
  USD-shaped and applied to GTQ amounts unconverted, so Guatemalan merchants
  were held to roughly a fifth of the allowance a comparable USD merchant got.
  The GTQ bands are round local numbers chosen by hand, not a converted rate —
  they are a guess like everything else here, and the sweep should check them.
