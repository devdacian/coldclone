#!/usr/bin/env bash
# external-review-codex.sh — deterministic wrapper for the FORWARD external cross-model
# review (Claude Code orchestrator -> `codex exec` / GPT reviewer).
#
# This is half of Touchstone's external-review arm. Its sibling
# external-review-claude.sh runs the REVERSE path (Codex orchestrator ->
# headless `claude -p` / Claude reviewer). Pick the wrapper whose REVIEWER is a
# DIFFERENT model family from your orchestrator — that cross-family difference
# is the whole point.
#
# Naming convention: external-review-<reviewer>.sh, where <reviewer> is the CLI
# this wrapper invokes (codex, claude, …). The basename without `.sh` is also the
# stderr marker prefix (this wrapper emits `external-review-codex:`; the sibling
# emits `external-review-claude:`). A new reviewer CLI gets its own
# external-review-<cli>.sh. The selection rule reduces to: never use the wrapper
# named after your OWN orchestrator family.
#
# This wrapper owns ONLY the deterministic invocation: flag assembly, the
# sandbox/model pins, the OPENAI_API_KEY scrub, capture wiring, the per-round
# watchdog, and the structural health check. It does NOT assemble prompts,
# verify findings, dispose them, classify errors retry-vs-skip, or run the loop
# — all of that judgment lives in the orchestrator (see TOUCHSTONE.md, and the
# Claude-Code mechanism section in TOUCHSTONE-claude.md).
#
# Inputs:  a single assembled prompt-file (the orchestrator builds brief +
#          inlined lens checklist + PRIOR ROUNDS DISPOSITION each round, and for
#          an implementation review concatenates the git diff into that same
#          file, because `codex exec` has only ONE stdin channel and no
#          prompt-file flag), a JSON-schema file, and the review --cd repo.
# Outputs: the findings-file (codex `-o`, the clean final structured message)
#          and the json-log (the boolean `--json` event stream, which codex
#          prints to stdout and this wrapper redirects to the log).
#
# Exit codes:
#   0 — HEALTHY round: a turn.completed event is present AND no turn.failed /
#       error event is present. The findings-file is ready to parse.
#   1 — UNHEALTHY round: no turn.completed, or a failure event is present
#       (includes the codex-binary-missing / launch-failure case, which lands
#       in the log). The orchestrator reads the json-log to classify
#       retry-vs-skip (see TOUCHSTONE.md graceful-degradation posture).
#   2 — usage / config error (missing arg, unreadable prompt/schema, bad --cd).
#
# The shell/pipe exit code of `codex exec` is NEVER trusted — an in-band error
# event can ride with a 0 exit. The structural health check below is the
# authoritative round verdict.

set -uo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: external-review-codex.sh --prompt <file> --schema <file> --findings <file> --log <file>
                          --cd <repo>
                          [--model <model>] [--effort <effort>]
                          [--web-search <on|off>]
                          [--watchdog-seconds <N>]

  --prompt        Assembled reviewer prompt-file (piped on bare stdin).
  --schema        JSON-schema file passed to codex --output-schema.
  --findings      Output path for the structured final message (codex -o).
  --log           Output path for the JSONL event stream (redirected stdout).
  --cd            REQUIRED. Repo the reviewer reads (no default — a forgotten
                  --cd is a loud exit-2 config error).
  --model         Reviewer model pin (default: gpt-5.5).
  --effort        Reasoning effort (default: high — the field-validated level).
  --web-search    Enable the Codex hosted web_search tool for this round:
                  on|off (default: off). The off/default path passes
                  -c web_search=disabled so the wrapper is fail-closed. Web-enabled
                  rounds may run longer; avoid pairing with an overly tight
                  focused-round watchdog.
  --watchdog-seconds  Per-round wall-clock cap (default: 600). The wrapper
                  SELF-ENFORCES it: on expiry the reviewer's whole process tree
                  is reaped (TERM, 10s grace, then KILL). On a round that
                  health-checks UNHEALTHY (typically the trip preceded
                  turn.completed) the wrapper exits 1 and emits a WATCHDOG-TIMEOUT
                  marker on stderr for the orchestrator's retry-vs-skip
                  classification; on a round that health-checks HEALTHY despite
                  the trip the kill was only cleanup (exit 0, WATCHDOG-CLEANUP
                  marker). Pass 300 for a small/focused diff and 600 for a large
                  one. Must be a positive integer.
EOF
}

# --cd is REQUIRED (no default). Defaulting empty + adding `cd` to the
# required-arg check below fails LOUD on a forgotten --cd (exit 2) instead of
# silently reviewing the wrong dir.
CD_DIR=""
MODEL="gpt-5.5"
EFFORT="high"
PROMPT=""
SCHEMA=""
FINDINGS=""
LOG=""
WATCHDOG_SECONDS="600"
WEB_SEARCH="off"

# Guard a value-taking flag: $1 = flag name, $2 = remaining-arg count ($#).
# Without this, a value-taking flag passed as the LAST token with no value
# makes `shift 2` fail (count > $#, shifts nothing) under `set -uo pipefail`
# (no `set -e`), so $# stays 1 and the while-loop spins forever. Fail fast to
# the documented exit-2 config-error path instead.
require_val() {
  if [ "$2" -lt 2 ]; then
    echo "error: $1 requires a value" >&2
    exit 2
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prompt)   require_val "$1" "$#"; PROMPT="$2";   shift 2 ;;
    --schema)   require_val "$1" "$#"; SCHEMA="$2";   shift 2 ;;
    --findings) require_val "$1" "$#"; FINDINGS="$2"; shift 2 ;;
    --log)      require_val "$1" "$#"; LOG="$2";      shift 2 ;;
    --cd)       require_val "$1" "$#"; CD_DIR="$2";   shift 2 ;;
    --model)    require_val "$1" "$#"; MODEL="$2";    shift 2 ;;
    --effort)   require_val "$1" "$#"; EFFORT="$2";   shift 2 ;;
    --web-search) require_val "$1" "$#"; WEB_SEARCH="$2"; shift 2 ;;
    --watchdog-seconds) require_val "$1" "$#"; WATCHDOG_SECONDS="$2"; shift 2 ;;
    -h|--help)  usage; exit 2 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# Positive-integer validation. A typo'd bound must be a loud config error (exit
# 2), never a silently-disabled watchdog.
case "$WATCHDOG_SECONDS" in
  ''|*[!0-9]*|0|0*)
    echo "error: --watchdog-seconds must be a positive integer: $WATCHDOG_SECONDS" >&2
    exit 2
    ;;
esac

case "$WEB_SEARCH" in
  on|off) ;;
  *) echo "error: --web-search must be 'on' or 'off': $WEB_SEARCH" >&2; exit 2 ;;
esac

for req in "prompt:$PROMPT" "schema:$SCHEMA" "findings:$FINDINGS" "log:$LOG" "cd:$CD_DIR"; do
  name="${req%%:*}"
  val="${req#*:}"
  if [ -z "$val" ]; then
    echo "error: missing required --$name" >&2
    usage
    exit 2
  fi
done

{ [ -f "$PROMPT" ] && [ -r "$PROMPT" ]; } || { echo "error: prompt file not found or not readable: $PROMPT" >&2; exit 2; }
{ [ -f "$SCHEMA" ] && [ -r "$SCHEMA" ]; } || { echo "error: schema file not found or not readable: $SCHEMA" >&2; exit 2; }
[ -d "$CD_DIR" ] || { echo "error: --cd directory not found: $CD_DIR" >&2; exit 2; }

# Validate the OUTPUT parent dirs up front. Without this, an unwritable/missing
# --log or --findings parent makes the codex stdout redirection fail, no log is
# created, and the health check then reports UNHEALTHY (exit 1) — misrouting a
# local config mistake into the orchestrator's retry-vs-skip degradation path.
# A bad output path is a config error (exit 2), not a failed review round.
LOG_DIR="$(dirname "$LOG")"
{ [ -d "$LOG_DIR" ] && [ -w "$LOG_DIR" ]; } || { echo "error: --log parent directory missing or not writable: $LOG_DIR" >&2; exit 2; }
[ ! -d "$LOG" ] || { echo "error: --log points to a directory, not a file: $LOG" >&2; exit 2; }
FINDINGS_DIR="$(dirname "$FINDINGS")"
{ [ -d "$FINDINGS_DIR" ] && [ -w "$FINDINGS_DIR" ]; } || { echo "error: --findings parent directory missing or not writable: $FINDINGS_DIR" >&2; exit 2; }
[ ! -d "$FINDINGS" ] || { echo "error: --findings points to a directory, not a file: $FINDINGS" >&2; exit 2; }

# Reject path collisions BEFORE truncating any output. `-ef` compares by inode,
# so it catches same-path, symlink, and hard-link aliasing. The inputs always
# exist here (validated with -f above), so an input==output alias is caught even
# when the output did not pre-exist (the shared path exists as the input). An
# aliased output would otherwise let the fresh-output truncation below wipe a
# validated input out from under codex.
for in_path in "$PROMPT" "$SCHEMA"; do
  for out_path in "$LOG" "$FINDINGS"; do
    if [ "$in_path" -ef "$out_path" ]; then
      echo "error: input and output paths must be distinct (collision: $in_path == $out_path)" >&2
      exit 2
    fi
  done
done

# Establish FRESH, empty, writable output files BEFORE invoking codex. This
# (a) truncates any stale log/findings from a PRIOR run so they can never be
# parsed as this round's result (a stale healthy log must never produce a
# false HEALTHY verdict); (b) surfaces an unwritable existing output FILE as a
# config error here (exit 2) rather than as a silent failed redirection later;
# and (c) guarantees that if codex does not run for any reason, the log is
# EMPTY, so the health check reports UNHEALTHY — never a stale HEALTHY.
: > "$LOG"      || { echo "error: cannot create/write --log file: $LOG" >&2; exit 2; }
: > "$FINDINGS" || { echo "error: cannot create/write --findings file: $FINDINGS" >&2; exit 2; }

# With both outputs now established, reject a LOG==FINDINGS collision: the two
# capture channels (the JSONL event log via redirected stdout, and the final
# structured message via -o) must be distinct files, or codex would conflate
# them into one and the health check / findings parser would read merged content.
if [ "$LOG" -ef "$FINDINGS" ]; then
  echo "error: --log and --findings must be distinct files (collision: $LOG == $FINDINGS)" >&2
  exit 2
fi

# Print all transitive descendant PIDs of $1 (NOT including $1), BFS over the
# ps ppid table. macOS bash 3.2 has no native tree walk. Snapshotting the tree
# BEFORE killing beats reparent-to-init: an orphan keeps its pid even after its
# parent dies, so a pre-kill snapshot still names it.
_descendant_pids() {
  _dp_ps=$(ps -eo pid=,ppid= 2>/dev/null)
  _dp_frontier="$1"
  while [ -n "$_dp_frontier" ]; do
    _dp_next=""
    for _dp_p in $_dp_frontier; do
      _dp_kids=$(printf '%s\n' "$_dp_ps" | awk -v P="$_dp_p" '$2==P{print $1}')
      if [ -n "$_dp_kids" ]; then
        printf '%s\n' $_dp_kids
        _dp_next="$_dp_next $_dp_kids"
      fi
    done
    _dp_frontier="$_dp_next"
  done
}

# Reap the reviewer robustly. The reviewer can re-setpgid/setsid its work out of
# the shell-assigned process group (sandbox helpers do this), so a group-only
# kill misses escaped workers and a group-aliveness early-out can hang the
# wrapper on `wait`. Guard on the PID's OWN liveness (never the group alone),
# and kill the DIRECT PID (guaranteed to reach our own child) + its snapshotted
# descendant tree + the process group. TERM -> 10s grace -> KILL.
kill_review_group() {
  [ -n "${REVIEW_PID:-}" ] || return 0
  if ! kill -0 "$REVIEW_PID" 2>/dev/null && ! kill -0 -- "-$REVIEW_PID" 2>/dev/null; then
    return 0
  fi
  _targets="$REVIEW_PID $(_descendant_pids "$REVIEW_PID")"
  kill -TERM $_targets 2>/dev/null          # direct PIDs (reaches the leader)
  kill -TERM -- "-$REVIEW_PID" 2>/dev/null  # + the process group
  _waited=0
  while [ "$_waited" -lt 10 ]; do
    kill -0 "$REVIEW_PID" 2>/dev/null || break  # leader gone -> wait will return
    sleep 1
    _waited=$((_waited + 1))
  done
  kill -KILL $_targets 2>/dev/null
  kill -KILL -- "-$REVIEW_PID" 2>/dev/null
  return 0
}

# Fresh --ephemeral reviewer each round (no resume): preserves the load-bearing
# fresh-reviewer independence. --sandbox read-only: the reviewer reads the whole
# repo to verify but cannot mutate it (no approval prompts -> autonomous-safe).
# --json is BOOLEAN: it prints the JSONL event stream to stdout, which we
# redirect to the log; -o captures the clean final structured message. The
# prompt is delivered on bare stdin. OPENAI_API_KEY is scrubbed so a stray key
# cannot silently divert the run to per-token API billing instead of the
# included subscription quota.
WEB_SEARCH_ARG=""
WEB_SEARCH_MODE_CFG="-c web_search=disabled"
if [ "$WEB_SEARCH" = "on" ]; then
  WEB_SEARCH_ARG="--search"
  WEB_SEARCH_MODE_CFG=""
fi
#
# WEB_SEARCH_ARG is intentionally expanded unquoted below: empty vanishes, and
# the on-value is a single top-level Codex argv word. Its closed-enum source
# prevents spaces/globs from user input. WEB_SEARCH_MODE_CFG is also expanded
# unquoted: the off-value splits into `-c` plus its config assignment, and the
# on-value vanishes. It is constant data, not user input.
#
# The launch runs as a background job under set -m so it gets its OWN process
# group (pgid == $!), which is what lets the watchdog kill codex AND any
# descendants it leaves behind. set +m immediately after scopes job control to
# the launch. The trap is EXIT-only DELIBERATELY: on bash, a TRAPPED INT/TERM
# runs the handler and then RESUMES the script (which would run the health check
# on a killed round and exit 0), while an UNTRAPPED fatal signal runs the EXIT
# trap and dies with the signal status — the wanted semantics with no re-raise
# machinery (verified empirically on bash 3.2.57).
set -m
env -u OPENAI_API_KEY codex $WEB_SEARCH_ARG exec \
  --ephemeral \
  --cd "$CD_DIR" \
  --sandbox read-only \
  --skip-git-repo-check \
  -m "$MODEL" \
  -c model_reasoning_effort="$EFFORT" \
  $WEB_SEARCH_MODE_CFG \
  --output-schema "$SCHEMA" \
  --json \
  -o "$FINDINGS" \
  < "$PROMPT" > "$LOG" 2>&1 &
REVIEW_PID=$!
trap kill_review_group EXIT
set +m

# Wall-clock watchdog: `codex exec` exposes no time/turn/tool-call bound, and a
# reviewer can get stuck in a runaway tool-use loop for hours. A trip that lands
# BEFORE turn.completed flushes (the common case) leaves no turn.completed
# event, so the structural health check below lands the round on the normal
# UNHEALTHY exit-1 path; the post-health marker logic handles the
# trip-after-flush race.
TIMED_OUT=0
ELAPSED=0
while kill -0 "$REVIEW_PID" 2>/dev/null; do
  if [ "$ELAPSED" -ge "$WATCHDOG_SECONDS" ]; then
    TIMED_OUT=1
    kill_review_group
    break
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done
wait "$REVIEW_PID" 2>/dev/null

# Structural health check + token-usage surfacing. The health verdict is success
# iff some event has type == "turn.completed" AND no event has type in
# {turn.failed, error}. Each line is parsed as JSON and the `type` field matched
# exactly — NEVER a substring scan, because a review whose content discusses
# "turn.failed" / "error" (or quotes the event names) would trip a naive grep.
# When a turn.completed event carries a `usage` block, the token figures are
# surfaced to stderr (informational; never changes the verdict).
python3 - "$LOG" <<'PY'
import json
import sys

log_path = sys.argv[1]

completed = False
failed = False
usage = None
try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(evt, dict):
                continue
            etype = evt.get("type")
            if etype == "turn.completed":
                completed = True
                u = evt.get("usage")
                if isinstance(u, dict):
                    usage = u  # last turn.completed wins
            elif etype in ("turn.failed", "error"):
                failed = True
except OSError:
    sys.exit(1)

healthy = completed and not failed

# Graceful usage surfacing — never raises, never affects the health verdict.
if usage is not None:
    def _g(k):
        v = usage.get(k)
        return v if isinstance(v, int) else 0
    inp = _g("input_tokens")
    cached = _g("cached_input_tokens")
    out = _g("output_tokens")
    reasoning = _g("reasoning_output_tokens")
    sys.stderr.write(
        f"external-review-codex: USAGE input={inp} cached_input={cached} "
        f"output={out} reasoning={reasoning}\n"
    )

sys.exit(0 if healthy else 1)
PY
health=$?

# Watchdog marker — chosen AFTER the health check, because a kill can land
# after turn.completed flushed (the review finished; the kill was cleanup of a
# lingering process tree). Only the unhealthy-trip marker carries a
# timeout-shaped token: the orchestrator's retryable classifier matches
# `timed out`, and a healthy round must never be classifiable as a transient
# failure.
if [ "$TIMED_OUT" -eq 1 ]; then
  if [ "$health" -eq 0 ]; then
    FINDINGS_NOTE=""
    [ -s "$FINDINGS" ] || FINDINGS_NOTE=" (findings file is empty)"
    echo "external-review-codex: WATCHDOG-CLEANUP -- lingering reviewer process group killed after turn.completed$FINDINGS_NOTE" >&2
  else
    echo "external-review-codex: WATCHDOG-TIMEOUT seconds=$WATCHDOG_SECONDS -- reviewer process group killed; review timed out after ${WATCHDOG_SECONDS}s" >&2
  fi
fi

if [ "$health" -eq 0 ]; then
  echo "external-review-codex: HEALTHY (turn.completed present, no failure event) -- findings=$FINDINGS log=$LOG" >&2
  exit 0
fi

echo "external-review-codex: UNHEALTHY (no turn.completed, or a turn.failed/error event present) -- inspect $LOG to classify retry-vs-skip" >&2
exit 1
