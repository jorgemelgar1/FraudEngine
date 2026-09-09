#!/usr/bin/env bash
#
# What cron calls, once an hour. Install with:
#
#   crontab -e
#   0 * * * * /home/<you>/fraud-engine/runner/cron-run.sh
#
# Cron runs with almost no environment - no venv, no PATH to speak of, and a
# working directory that is not the repository. Every one of those has to be
# established here rather than assumed, which is why this wrapper exists
# instead of cron calling python directly.
#
# Override the paths if your layout differs:
#   CUBO_RUNNER_REPO, CUBO_RUNNER_VENV, CUBO_RUNNER_LOG_DIR
set -uo pipefail

REPO="${CUBO_RUNNER_REPO:-$HOME/fraud-engine}"
VENV="${CUBO_RUNNER_VENV:-$HOME/fraud-engine-venv}"
LOG_DIR="${CUBO_RUNNER_LOG_DIR:-$HOME/fraud-engine-logs}"
LOG="$LOG_DIR/cycle-$(date +%Y-%m-%d).log"

mkdir -p "$LOG_DIR"

{
  echo "=============================================================="
  echo "$(date '+%Y-%m-%d %H:%M:%S %Z')  starting"

  if [ ! -x "$VENV/bin/python3" ]; then
    echo "ERROR: no virtualenv at $VENV"
    exit 1
  fi
  if [ ! -f "$REPO/runner/cycle.py" ]; then
    echo "ERROR: no runner at $REPO/runner/cycle.py"
    exit 1
  fi

  # One report in flight at a time. If the previous hour's cycle is somehow
  # still waiting for its email, SKIP this one rather than queueing a second
  # request - two identical report mails in the mailbox is exactly the
  # ambiguity the whole schedule is designed to avoid. The next slot covers
  # whatever this one skipped.
  #
  # `-E 99` gives "could not get the lock" its own exit code. Without it that
  # is a plain 1, indistinguishable from the runner failing, and a healthy
  # skip would read as an error every hour.
  if command -v flock >/dev/null 2>&1; then
    flock -n -E 99 "$LOG_DIR/.cycle.lock" \
      "$VENV/bin/python3" "$REPO/runner/cycle.py" "$@"
    status=$?
    if [ $status -eq 99 ]; then
      echo "SKIPPED: the previous cycle is still running."
      status=0
    fi
  else
    "$VENV/bin/python3" "$REPO/runner/cycle.py" "$@"
    status=$?
  fi

  echo "$(date '+%Y-%m-%d %H:%M:%S %Z')  finished, exit $status"
} >> "$LOG" 2>&1

# Two weeks of logs. Long enough to investigate "it stopped working last
# Tuesday", short enough that an SD card never fills because of us.
find "$LOG_DIR" -name 'cycle-*.log' -mtime +14 -delete 2>/dev/null

exit ${status:-0}
