# Automated report runner — build plan

A scheduled job on **one machine** that requests transaction reports from the
Cubo CMS, collects them from Gmail, runs them through `analyze.py`, and writes
findings to Supabase. The desktop app that teammates install is **not**
touched: manual CSV upload keeps working exactly as it does today.

The point is a proactive monitor. Today someone has to remember to export and
upload. This watches continuously and puts findings in the same review queue.

---

## Scope

**In:** one Windows machine, scheduled task, one country per hour on rotation,
today+yesterday window, findings written to the existing tables.

**Out:** the desktop app, the Vercel function, anything teammates install.
The runner shares only the *database* with them.

### Principles

1. **The engine does not change.** `analyze.py` already takes a CSV path.
   The runner calls it exactly as the CLI does. The only edit is the currency
   fix, which is a prerequisite (see below), not a feature.
2. **No CSV survives a run.** Downloaded, analyzed, deleted in a `finally`.
3. **The report URL is a credential.** It is unauthenticated — possession is
   authorization. Never logged, never in an exception message.
4. **Attribute from data, never from intent.** The country a run is labelled
   with comes from `country_name` inside the CSV, not from the id we asked for.
5. **Overlapping windows mean failures self-heal.** A run that dies at 14:00 is
   covered by the next run for that country. No replay queue needed.

---

## Prerequisite: fix the currency bug first

`analyze.py` defines `_normalize_country` twice; the second definition wins and
returns uppercase, so every lookup into `COUNTRY_TO_CURRENCY` (lowercase keys)
misses and falls through to `USD`.

```
Guatemala      -> USD   (should be GTQ)
El Salvador    -> USD   (right answer, wrong reason)
Panama         -> USD   (right answer, wrong reason)
```

This was survivable when uploads were manual and the analyst knew which file
was which. It is **not** survivable when GT runs automatically every three
hours: the system would produce mislabelled money figures continuously, which
is the exact problem that started this work.

Fix = rename the foreign-card helper to `_normalize_country_code`, make an
unmapped country return `UNKNOWN` instead of silently defaulting, add the
AST guard test. Roughly an hour. **Do this before the first scheduled run.**

---

## The cycle

One country per hour, rotating. Each country is refreshed every three hours,
but only one request goes out per hour and **only one report is ever in
flight** — which is what makes email matching unambiguous.

```
hour 0   SV        hour 3   SV        hour 6   SV
hour 1   PA        hour 4   PA        hour 7   PA
hour 2   GT        hour 5   GT        hour 8   GT
```

Rotation is derived from the clock (`COUNTRIES[hour % 3]`), so it is stateless
and self-correcting — a missed run does not shift the schedule, that country
simply picks up at its next slot.

**Volume:** 24 report requests and 24 emails per day, total. Worth mentioning
to the CTO before switching it on, so nobody discovers it in an access log.

### Window: today + yesterday

```
createdAt=<yesterday>&createdAt=<today>
```

At 01:00 that is ~25 hours of data; at 23:00 it is ~47. Always at least 24,
which is what the engine's longest hard window (card fan-out, slow tier)
requires. It also gives the zero-settlement gate — which needs 6+ attempts
from a merchant before it will look — a realistic chance to accumulate them.

**Known limitation:** a merchant spreading 6 attempts across five days is still
invisible to a two-day window. If that pattern matters, add a separate weekly
sweep with a 7-day window; it is the same runner with different arguments.

**To verify:** which timezone the API interprets those dates in. If it is UTC
and we are UTC-6, "today" cuts differently than expected. Does not break
anything, but the window boundaries should be understood rather than assumed.

---

## Per-run state machine

```
IDLE
  -> TRIGGERED      GET /report, 200 empty body. Record requested_at.
  -> AWAITING_MAIL  poll the Gmail label for a message from the reports sender
                    with internalDate > requested_at.
                    timeout 15 min, poll every 30 s.
  -> DOWNLOADED     extract the CDN URL from the plain-text part,
                    GET it into a temp file.
  -> ANALYZED       read country_name from the CSV (authoritative),
                    run analyze.py with watchlist + indicators from Supabase.
  -> SYNCED         de-duplicate, then write.
  -> CLEANED        delete the CSV. Runs even if any step above threw.
```

**Never re-trigger blindly.** If the mail never arrives, the job ends as
`AWAITING_MAIL_TIMEOUT` and that country waits for its next slot. Re-firing
inside the same cycle would queue duplicate reports and duplicate emails.

**Processed message IDs are recorded** so a delayed report cannot be consumed
twice. Combined with the one-in-flight schedule and content attribution, a late
email is handled correctly rather than mis-assigned.

---

## De-duplication

The reason this is the central piece: a merchant flagged at 10:00 stays inside
the today+yesterday window until end of tomorrow, so it will be **re-detected
roughly 16 times** (48 hours ÷ 3-hour cycle) before it ages out. Without
de-duplication the review queue receives 16 copies of every finding and becomes
unusable — and the review queue is the product.

### Identity

`finding_key = (company_name, section)`

One open finding per merchant per detector. Ops reasons about *"is this
merchant a problem?"*, not *"is this merchant's Tuesday-afternoon pattern a
problem?"*. A new pattern at a known merchant updates the existing finding's
fingerprints rather than raising a second one.

### Rules

| Existing state | On re-detection | Rationale |
|---|---|---|
| none | insert as `pending` | first sighting |
| `pending` | **update in place** — refresh score, fingerprints, evidence; bump `times_seen`, set `last_seen_at` | one row, and the reviewer sees the *current* score rather than the first one |
| `accepted` | suppress the alert; bump the watchlist's `last_flagged` | already actioned and watchlisted; re-alerting is noise, but "still happening" is worth recording |
| `rejected` | suppress **for 48 h**, *unless* the score escalates (below) | a dismissed false positive should not nag, but must not be invisible forever |

### Rejected: the escalation override

Re-open immediately, before the 48 h expires, if **either** holds:

- `new_score >= rejected_score + 15`, or
- the finding crosses into `Critical` having been rejected at `Monitor`

Tier-crossing is the more meaningful of the two: a merchant dismissed as
Monitor that now scores Critical has genuinely changed behaviour.

> **Caveat worth knowing:** score escalation is a weak signal for the
> zero-settlement section, because that score already saturates at 100
> (`tests/CALIBRATION.md`) — many findings pin at the ceiling on first
> detection and can never "escalate". The tier-crossing rule still works there.
> This is one more reason the weight rescale eventually matters.

### Surfacing it

Pending findings show **"detectado N veces desde <fecha>"**. That is real
signal for a reviewer: a merchant seen once may be noise; one seen on 16
consecutive runs is not.

---

## Changes required

### `analyze.py`
- Currency fix (prerequisite above). **Nothing else.**

### Database — migrations 0010 and 0011
```
findings_history
  + finding_key       text          stable identity for re-detection
  + first_seen_at     timestamptz
  + last_seen_at      timestamptz
  + times_seen        integer default 1
  + suppressed_until  timestamptz   rejection cooloff

analysis_runs
  + source            text          'manual' | 'auto'

RPC lookup_open_finding(key)          the current row for a key, or nothing
RPC touch_finding(id, row, promote)   refresh an open finding in place
RPC reopen_finding(id, ...)           a rejected finding that escalated
RPC touch_watchlist_merchant(...)     "still happening" on a suppressed alert
```

**0011 exists because 0010 was not enough.** It added `finding_key` but nothing
*populated* it: three clients write findings (the web app, the desktop app, the
runner) and none of them sent the column, so every finding created after 0010
had `finding_key = NULL` — invisible to `lookup_open_finding`, and therefore
re-raised as new on every single run. Fixing that in three clients means three
chances to drift, so 0011 makes the column **`GENERATED`**: Postgres computes it
on every write and no client can supply, forget, or disagree about it.

0011 also widens `touch_finding` to refresh the *whole* finding rather than four
columns of it. The 0010 version left `chargeback_exposure_usd`, `description_es`
and `run_id` at their first-detection values, so a reviewer would have seen a
current risk score beside a two-day-old amount with no way to tell which was
which.

`source` matters for trust: when a number looks odd, being able to tell your
own upload from the robot's run is the first debugging question.

### Review UI (web + desktop)
- Show `times_seen` / `first_seen_at` on pending findings
- Show `source` on `/historial`

Small, additive. No change to how review works.

### The desktop app
- **Nothing.** Teammates keep uploading manually. The runner writes to the same
  tables, so its findings appear in everyone's Pendientes.

---

## Retention

The CSV is deleted after every run, in a `finally` block, so a crash mid-analysis
still cleans up.

**What is deliberately kept:** each finding keeps up to five evidence rows, and
those carry `card_holder`, `card_bin`, `card_last_digits`, `transaction_id`,
`client_email` and `ip`. That is by design — a reviewer cannot act on a finding
they cannot see — but it means the accurate description is *"we keep a small
evidence sample, not the file"*, not *"we keep nothing"*. The README's privacy
section already covers this since the indicator release; worth re-reading once
the runner is live and the volume of retained findings grows.

---

## Failure modes

| Failure | Behaviour | Why that is right |
|---|---|---|
| Token expired (90-day life) | Fail loudly, alert, stop | Silent failure would look like "no fraud found" |
| Email never arrives | End the job, wait for next slot | Re-triggering queues duplicate reports |
| CSV download fails | Retry twice, then give up | Transient CDN blips |
| Analysis throws | CSV still deleted; error logged | Cleanup must not depend on success |
| Supabase unreachable | Skip the write, log it | Next run covers the same window — self-healing |
| Machine asleep / off | Slots missed | Overlapping windows absorb it; alert if a country has not succeeded in 12 h |

---

## Build order

1. ~~**Currency fix** + guard test.~~ **Done**, shipped in v0.5.0.
2. ~~**Migrations 0010 + 0011** — dedup columns, generated key, RPCs.~~ **Done.**
3. ~~**De-duplication logic** + tests against synthetic repeated runs.~~ **Done**
   — `runner/dedup.py`, 28 tests.
4. ~~**Manual-URL mode**~~ **Done** — `runner/run.py`, 16 tests plus an
   end-to-end pass over the real engine.
5. **Gmail reader** — OAuth, stored refresh token, label-scoped polling.
6. **Scheduler** — cron on the Pi, hourly, rotation by `hour % 3`.
7. **UI additions** — `times_seen`, `source`.

Steps 1–4 are useful on their own, and now exist: you can analyze any report
link you paste, which is already better than exporting and uploading by hand.

---

## Running it today (steps 1–4)

**Once:** apply `supabase/migrations/0011_finding_key_generated.sql` in the
Supabase SQL Editor, and create `runner/.env` from `runner/.env.example`.
Manual-URL mode reads only the Supabase block and `CUBO_CSV_URL_PATTERN` — no
CMS token is involved, because the report link is unauthenticated.

```bash
# Analyze a report link from the email
python runner/run.py --url "<link from the report email>"

# See what it WOULD do, writing nothing
python runner/run.py --url "<link>" --dry-run

# Analyze a CSV you already have (this file is never deleted)
python runner/run.py --csv ~/reports/guatemala.csv
```

Output is one line per finding with the de-dup decision that was made and why:

```
insert   Inversiones Kabu [exposure]: primera detección
update   Mandados SV [exposure]: ya pendiente, visto de nuevo (puntaje 45 → 90)
suppress Comercio Tres [exposure]: descartado, en silencio 31h más
```

Findings land in Pendientes for the whole team, tagged `source = auto`.

**Two things this deliberately refuses to do:** download anything whose URL does
not match `CUBO_CSV_URL_PATTERN` (a malformed or spoofed email must not turn the
runner into a fetch-anything tool), and leave a downloaded CSV on disk — that
happens in a `finally`, so it survives a crash mid-analysis.

---

## Settled

- Rejection cooloff: **48 h, with score-escalation override**
- Cadence: **one country per hour, SV → PA → GT, rotating**
- Window: **today + yesterday**
- Mailbox: the token owner's account, filtered to a label that skips the inbox
- CSVs deleted every run
- Runner lives on one machine, never in the distributed app

## Still open

- Timezone the API applies to `createdAt`
- Gmail OAuth client — needs a Google Cloud project
- Alerting channel when the runner fails (email to self? the Slack work that
  was deferred?)
- Whether to add a weekly 7-day sweep for slow-burn merchants
