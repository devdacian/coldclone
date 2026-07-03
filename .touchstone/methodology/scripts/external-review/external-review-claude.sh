#!/usr/bin/env bash
# external-review-claude.sh — deterministic wrapper for the REVERSE external
# cross-model review (Codex / GPT orchestrator -> headless `claude -p` / Claude
# reviewer). This is the counterpart to external-review-codex.sh, which runs the
# FORWARD path (Claude orchestrator -> `codex exec` / GPT reviewer).
#
# Use this wrapper when your ORCHESTRATOR is Codex/GPT and you want a Claude
# reviewer of a different model family. Like its sibling, it owns ONLY the
# deterministic invocation: env scrub, the auth/billing fail-closed preflight,
# the sterility flag assembly, the model/effort/budget pins, capture wiring, the
# per-round watchdog, and the structural health check. It does NOT assemble
# prompts, verify findings, dispose them, classify errors retry-vs-skip, or run
# the loop — all of that judgment lives in the orchestrator.
#
# BILLING SAFETY (the entire reason this wrapper exists):
#   The reviewer MUST bill the interactive Claude subscription (OAuth token in
#   the OS keychain), never Anthropic API per-token billing, an apiKeyHelper,
#   or a 3P provider (Bedrock/Vertex/Foundry). Two mechanisms enforce this:
#     1. ENV SCRUB — every billing-route env var that could divert the run is
#        unset for BOTH the preflight AND the review (a single shared scrub), so
#        the preflight observes the exact auth surface the review will use.
#        USER/HOME are deliberately PRESERVED: the subscription OAuth token lives
#        in the OS login keychain, and reading it requires USER to be set.
#     2. FAIL-CLOSED PREFLIGHT — `claude auth status --json` is a LOCAL keychain
#        read (no inference, no spend). The review is invoked ONLY if it reports
#        loggedIn==true, authMethod=="claude.ai", apiProvider=="firstParty",
#        and subscriptionType in {pro,max}. (auth status is BLIND to a bare
#        ANTHROPIC_API_KEY, which is why the env scrub is the authoritative
#        defense against that one route.)
#
# STERILITY (sterile enough for an arms-length external reviewer):
#   --setting-sources ''  drops user/project/local settings -> no hooks, no
#                         plugins, no permissions, no apiKeyHelper from files.
#   CLAUDE_CODE_DISABLE_CLAUDE_MDS=1  disables CLAUDE.md memory loading.
#   --strict-mcp-config   with NO --mcp-config -> zero MCP servers.
#   --disable-slash-commands  -> skills off.
#   --no-session-persistence  -> no transcript/history written.
#   --no-chrome / --prompt-suggestions false  -> no side channels.
#   --tools ""            prompt-only reviewer (default). The orchestrator
#                         inlines the diff/code into the prompt-file. Pass --repo
#                         to instead grant a READ-ONLY tool set + access.
#   cwd = fresh scratch   the review runs in a throwaway dir so a CLAUDE.md in
#                         the invocation cwd cannot auto-discover into the prompt.
#   `--bare` is deliberately NOT used: under --bare, OAuth/keychain is never read
#   (auth is strictly ANTHROPIC_API_KEY / apiKeyHelper), which would DEFEAT
#   subscription billing. Sterility is assembled by flag instead.
#
# Inputs:  an assembled prompt-file (the orchestrator builds it; for a diff
#          review it inlines the git diff into that same file) and a JSON-schema
#          file.
# Outputs: the log-file (the full `--output-format json` result envelope) and
#          the findings-file (the envelope's `.structured_output`, extracted on
#          a HEALTHY round). Claude subprocess stderr is captured at
#          "<log>.stderr". Wrapper-owned status markers such as AUTH OK,
#          USAGE, HEALTHY, and UNHEALTHY are emitted to this wrapper process's
#          stderr and, when --wrapper-stderr-log is passed, copied there too.
#
# Exit codes:
#   0 — HEALTHY round: the envelope parsed, type=="result", is_error==false,
#       subtype=="success", structured_output present + schema-valid, and
#       modelUsage includes --model. The findings-file is ready to consume.
#   1 — UNHEALTHY round: missing/garbled envelope, is_error==true, a non-success
#       subtype, or structured_output absent/schema-invalid/model-mismatched.
#   2 — usage / config error (missing arg, unreadable prompt/schema, bad dir,
#       path collision, unwritable output, invalid watchdog).
#   3 — AUTH/BILLING preflight FAILED (fail-closed): not logged in, the auth
#       method/provider is anything other than the first-party subscription, or
#       managed Claude Code settings are present. The review is NOT invoked (no
#       spend). The orchestrator treats this as a non-retryable skip.
#
# The shell exit code of `claude -p` is never trusted; the structural health
# check on the JSON envelope is authoritative.

set -uo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: external-review-claude.sh --prompt <file> --schema <file> \
                                 --findings <file> --log <file> \
                                 [--wrapper-stderr-log <file>] \
                                 [--repo <dir>] [--model <model>] \
                                 [--effort <level>] [--max-budget-usd <amount>] \
                                 [--web-search <on|off>] \
                                 [--watchdog-seconds <N>]

  --prompt          Assembled reviewer prompt-file (piped on stdin).
  --schema          JSON-schema file passed to claude --json-schema.
  --findings        Output path for the extracted .structured_output (HEALTHY).
  --log             Output path for the full JSON result envelope (stdout).
                    Claude subprocess stderr is captured at "<log>.stderr";
                    wrapper status markers are written to wrapper stderr.
  --wrapper-stderr-log
                    OPTIONAL path for a durable copy of wrapper-owned stderr
                    markers (AUTH OK, USAGE, HEALTHY/UNHEALTHY). This is
                    distinct from Claude child stderr at "<log>.stderr".
  --repo            OPTIONAL repo dir to let the reviewer READ (grants a
                    read-only tool set: Read,Grep,Glob + --add-dir <dir>). When
                    omitted the reviewer is prompt-only (--tools "") and the
                    orchestrator must inline all code into the prompt-file.
  --model           Reviewer model pin (default: claude-opus-4-8).
  --effort          Effort level: low|medium|high|xhigh|max (default: high).
  --max-budget-usd  Hard subscription-spend cap for the call (default: 5).
  --web-search      Enable Claude WebSearch/WebFetch for this round: on|off
                    (default: off). When enabled, the wrapper also passes
                    --permission-mode auto. No write-capable tools or Bash are
                    enabled.
  --watchdog-seconds  Per-round wall-clock cap (default: 600). Must be a
                    positive integer.
EOF
}

# ---- billing-route env scrub (shared by preflight AND review) ---------------
SCRUB_VARS=(
  ANTHROPIC_API_KEY
  ANTHROPIC_AUTH_TOKEN
  ANTHROPIC_AWS_API_KEY
  ANTHROPIC_AWS_BASE_URL
  ANTHROPIC_AWS_WORKSPACE_ID
  ANTHROPIC_BASE_URL
  ANTHROPIC_BEDROCK_BASE_URL
  ANTHROPIC_BEDROCK_MANTLE_BASE_URL
  ANTHROPIC_BEDROCK_SERVICE_TIER
  ANTHROPIC_FOUNDRY_API_KEY
  ANTHROPIC_FOUNDRY_BASE_URL
  ANTHROPIC_FOUNDRY_RESOURCE
  ANTHROPIC_VERTEX_BASE_URL
  ANTHROPIC_WORKSPACE_ID
  ANTHROPIC_CUSTOM_HEADERS
  AWS_BEARER_TOKEN_BEDROCK
  CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD
  CLAUDE_CODE_OAUTH_REFRESH_TOKEN
  CLAUDE_CODE_OAUTH_SCOPES
  CLAUDE_CODE_OAUTH_TOKEN
  CLAUDE_CODE_USE_ANTHROPIC_AWS
  CLAUDE_CODE_USE_BEDROCK
  CLAUDE_CODE_USE_MANTLE
  CLAUDE_CODE_USE_VERTEX
  CLAUDE_CODE_USE_FOUNDRY
  CLAUDE_CODE_SKIP_BEDROCK_AUTH
  CLAUDE_CODE_SKIP_FOUNDRY_AUTH
  CLAUDE_CODE_SKIP_MANTLE_AUTH
  CLAUDE_CODE_SKIP_VERTEX_AUTH
  ANTHROPIC_VERTEX_PROJECT_ID
  CLOUD_ML_REGION
)
SCRUB=(env)
for _v in "${SCRUB_VARS[@]}"; do SCRUB+=(-u "$_v"); done
SCRUB+=(CLAUDE_CODE_DISABLE_CLAUDE_MDS=1)

# Keychain repair: an env-stripped context may have dropped USER, which silently
# breaks the OAuth keychain read (-> loggedIn:false). Re-derive it.
: "${USER:=$(id -un 2>/dev/null)}"
export USER
if [ -z "${HOME:-}" ]; then
  echo "error: HOME is unset; cannot locate the subscription keychain/credentials" >&2
  exit 2
fi

MODEL="claude-opus-4-8"
EFFORT="high"
MAX_BUDGET_USD="5"
PROMPT=""
SCHEMA=""
FINDINGS=""
LOG=""
WRAPPER_STDERR_LOG=""
REPO=""
WATCHDOG_SECONDS="600"
WEB_SEARCH="off"

# Guard a value-taking flag passed as the LAST token (see forward wrapper).
require_val() {
  if [ "$2" -lt 2 ]; then
    echo "error: $1 requires a value" >&2
    exit 2
  fi
}

WRAPPER_LOG_READY=0
wrapper_log() {
  printf '%s\n' "$*" >&2
  if [ "${WRAPPER_LOG_READY:-0}" = "1" ] && [ -n "${WRAPPER_STDERR_LOG:-}" ]; then
    printf '%s\n' "$*" >> "$WRAPPER_STDERR_LOG"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prompt)          require_val "$1" "$#"; PROMPT="$2";         shift 2 ;;
    --schema)          require_val "$1" "$#"; SCHEMA="$2";         shift 2 ;;
    --findings)        require_val "$1" "$#"; FINDINGS="$2";       shift 2 ;;
    --log)             require_val "$1" "$#"; LOG="$2";            shift 2 ;;
    --wrapper-stderr-log) require_val "$1" "$#"; WRAPPER_STDERR_LOG="$2"; shift 2 ;;
    --repo)            require_val "$1" "$#"; REPO="$2";           shift 2 ;;
    --model)           require_val "$1" "$#"; MODEL="$2";          shift 2 ;;
    --effort)          require_val "$1" "$#"; EFFORT="$2";         shift 2 ;;
    --max-budget-usd)  require_val "$1" "$#"; MAX_BUDGET_USD="$2"; shift 2 ;;
    --web-search)      require_val "$1" "$#"; WEB_SEARCH="$2";     shift 2 ;;
    --watchdog-seconds) require_val "$1" "$#"; WATCHDOG_SECONDS="$2"; shift 2 ;;
    -h|--help)  usage; exit 2 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

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

for req in "prompt:$PROMPT" "schema:$SCHEMA" "findings:$FINDINGS" "log:$LOG"; do
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
python3 - "$SCHEMA" <<'PY' || { echo "error: schema file is not valid JSON: $SCHEMA" >&2; exit 2; }
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        json.load(fh)
except (OSError, json.JSONDecodeError, ValueError):
    sys.exit(1)
PY
if [ -n "$REPO" ]; then
  [ -d "$REPO" ] || { echo "error: --repo directory not found: $REPO" >&2; exit 2; }
fi

# Absolutize EVERY path before we cd into the scratch dir for the review (a
# CLAUDE.md in the invocation cwd must not auto-discover into the prompt). After
# the cd, relative paths would resolve against the scratch dir and break.
abspath() {
  local d b
  d="$(dirname "$1")"
  b="$(basename "$1")"
  d="$(cd "$d" 2>/dev/null && pwd)" || return 1
  printf '%s/%s\n' "$d" "$b"
}
PROMPT="$(abspath "$PROMPT")"     || { echo "error: cannot resolve --prompt path" >&2; exit 2; }
SCHEMA="$(abspath "$SCHEMA")"     || { echo "error: cannot resolve --schema path" >&2; exit 2; }
FINDINGS="$(abspath "$FINDINGS")" || { echo "error: cannot resolve --findings parent dir" >&2; exit 2; }
LOG="$(abspath "$LOG")"           || { echo "error: cannot resolve --log parent dir" >&2; exit 2; }
if [ -n "$WRAPPER_STDERR_LOG" ]; then
  WRAPPER_STDERR_LOG="$(abspath "$WRAPPER_STDERR_LOG")" || { echo "error: cannot resolve --wrapper-stderr-log parent dir" >&2; exit 2; }
fi
if [ -n "$REPO" ]; then REPO="$(cd "$REPO" && pwd)"; fi
STDERR_LOG="${LOG}.stderr"

# Validate OUTPUT parent dirs up front so an unwritable/missing output surfaces
# as a config error (exit 2) here, not as a silent failed redirection later.
LOG_DIR="$(dirname "$LOG")"
{ [ -d "$LOG_DIR" ] && [ -w "$LOG_DIR" ]; } || { echo "error: --log parent directory missing or not writable: $LOG_DIR" >&2; exit 2; }
[ ! -d "$LOG" ] || { echo "error: --log points to a directory, not a file: $LOG" >&2; exit 2; }
[ ! -d "$STDERR_LOG" ] || { echo "error: stderr log path points to a directory, not a file: $STDERR_LOG" >&2; exit 2; }
FINDINGS_DIR="$(dirname "$FINDINGS")"
{ [ -d "$FINDINGS_DIR" ] && [ -w "$FINDINGS_DIR" ]; } || { echo "error: --findings parent directory missing or not writable: $FINDINGS_DIR" >&2; exit 2; }
[ ! -d "$FINDINGS" ] || { echo "error: --findings points to a directory, not a file: $FINDINGS" >&2; exit 2; }
if [ -n "$WRAPPER_STDERR_LOG" ]; then
  WRAPPER_STDERR_DIR="$(dirname "$WRAPPER_STDERR_LOG")"
  { [ -d "$WRAPPER_STDERR_DIR" ] && [ -w "$WRAPPER_STDERR_DIR" ]; } || { echo "error: --wrapper-stderr-log parent directory missing or not writable: $WRAPPER_STDERR_DIR" >&2; exit 2; }
  [ ! -d "$WRAPPER_STDERR_LOG" ] || { echo "error: --wrapper-stderr-log points to a directory, not a file: $WRAPPER_STDERR_LOG" >&2; exit 2; }
fi

# Reject input/output and output/output aliasing BEFORE creating or truncating
# outputs. `-ef` only works after both files exist, so compare canonical path
# identities first; retain `-ef` for existing hardlink aliases.
same_path() {
  local a b ak bk
  a="$1"
  b="$2"
  ak="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$a")" || return 1
  bk="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$b")" || return 1
  [ "$ak" = "$bk" ] && return 0
  { [ -e "$a" ] && [ -e "$b" ] && [ "$a" -ef "$b" ]; } && return 0
  return 1
}

OUTPUT_PATHS=("$LOG" "$FINDINGS" "$STDERR_LOG")
OUTPUT_LABELS=("--log" "--findings" "<log>.stderr")
if [ -n "$WRAPPER_STDERR_LOG" ]; then
  OUTPUT_PATHS+=("$WRAPPER_STDERR_LOG")
  OUTPUT_LABELS+=("--wrapper-stderr-log")
fi

for in_path in "$PROMPT" "$SCHEMA"; do
  for idx in "${!OUTPUT_PATHS[@]}"; do
    out_path="${OUTPUT_PATHS[$idx]}"
    if same_path "$in_path" "$out_path"; then
      echo "error: input and output paths must be distinct (collision: $in_path == $out_path)" >&2
      exit 2
    fi
  done
done

for i in "${!OUTPUT_PATHS[@]}"; do
  j=$((i + 1))
  while [ "$j" -lt "${#OUTPUT_PATHS[@]}" ]; do
    if same_path "${OUTPUT_PATHS[$i]}" "${OUTPUT_PATHS[$j]}"; then
      echo "error: ${OUTPUT_LABELS[$i]} and ${OUTPUT_LABELS[$j]} must be distinct files (collision: ${OUTPUT_PATHS[$i]} == ${OUTPUT_PATHS[$j]})" >&2
      exit 2
    fi
    j=$((j + 1))
  done
done

# Touch outputs only after alias checks pass, then truncate them together below
# so stale files cannot be mistaken for this run.
: >> "$LOG"        || { echo "error: cannot create/write --log file: $LOG" >&2; exit 2; }
: >> "$FINDINGS"   || { echo "error: cannot create/write --findings file: $FINDINGS" >&2; exit 2; }
: >> "$STDERR_LOG" || { echo "error: cannot create/write stderr log file: $STDERR_LOG" >&2; exit 2; }
if [ -n "$WRAPPER_STDERR_LOG" ]; then
  : >> "$WRAPPER_STDERR_LOG" || { echo "error: cannot create/write --wrapper-stderr-log file: $WRAPPER_STDERR_LOG" >&2; exit 2; }
fi

# Establish FRESH, empty outputs after all collision checks pass, before the
# no-spend exit-3 gates so stale outputs are never mistaken for this run.
: > "$LOG"        || { echo "error: cannot truncate --log file: $LOG" >&2; exit 2; }
: > "$FINDINGS"   || { echo "error: cannot truncate --findings file: $FINDINGS" >&2; exit 2; }
: > "$STDERR_LOG" || { echo "error: cannot truncate stderr log file: $STDERR_LOG" >&2; exit 2; }
if [ -n "$WRAPPER_STDERR_LOG" ]; then
  : > "$WRAPPER_STDERR_LOG" || { echo "error: cannot truncate --wrapper-stderr-log file: $WRAPPER_STDERR_LOG" >&2; exit 2; }
fi
WRAPPER_LOG_READY=1

# Managed settings have higher precedence than CLI flags and can contain env or
# apiKeyHelper routes. Fail closed if local managed settings are present;
# external review is optional, so skip beats hidden API billing.
MANAGED_SETTINGS_PATHS=(
  "/Library/Application Support/ClaudeCode/managed-settings.json"
  "/Library/Application Support/ClaudeCode/managed-settings.d"
  "/etc/claude-code/managed-settings.json"
  "/etc/claude-code/managed-settings.d"
)
for managed_path in "${MANAGED_SETTINGS_PATHS[@]}"; do
  if [ -e "$managed_path" ]; then
    wrapper_log "external-review-claude: AUTH PREFLIGHT FAILED (managed Claude Code settings present: $managed_path)"
    wrapper_log "external-review-claude: not invoking review (no spend); managed settings may reintroduce env/apiKeyHelper routes"
    exit 3
  fi
done

# Print all transitive descendant PIDs of $1 (BFS over the ps ppid table);
# snapshot the tree BEFORE killing so a reparented orphan is still named.
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

# Reap the reviewer robustly. The empty-`${REVIEW_PID:-}` guard is kept because
# the pre-launch exit-2/exit-3 preflight paths run the EXIT trap before any
# launch. Guard on the PID's OWN liveness (never the group alone), and kill the
# DIRECT PID + its snapshotted descendant tree + the process group.
kill_review_group() {
  [ -n "${REVIEW_PID:-}" ] || return 0
  if ! kill -0 "$REVIEW_PID" 2>/dev/null && ! kill -0 -- "-$REVIEW_PID" 2>/dev/null; then
    return 0
  fi
  _targets="$REVIEW_PID $(_descendant_pids "$REVIEW_PID")"
  kill -TERM $_targets 2>/dev/null
  kill -TERM -- "-$REVIEW_PID" 2>/dev/null
  _waited=0
  while [ "$_waited" -lt 10 ]; do
    kill -0 "$REVIEW_PID" 2>/dev/null || break
    sleep 1
    _waited=$((_waited + 1))
  done
  kill -KILL $_targets 2>/dev/null
  kill -KILL -- "-$REVIEW_PID" 2>/dev/null
  return 0
}

# Run both auth preflight and review in the same throwaway cwd so an invocation
# cwd CLAUDE.md cannot auto-discover into either surface.
WORK="$(mktemp -d)" || { echo "error: cannot create scratch working dir" >&2; exit 2; }

# ONE merged EXIT-only handler: bash `trap` REPLACES the handler per signal, so
# the group-kill and the scratch cleanup must share a body.
cleanup() {
  kill_review_group
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- AUTH/BILLING fail-closed preflight (LOCAL keychain read, NO spend) ------
# Runs under the SAME scrubbed env and scratch cwd the review uses, and under
# --setting-sources '' so the observed auth surface matches the review's.
AUTH_JSON="$(
  cd "$WORK" && "${SCRUB[@]}" claude --setting-sources '' auth status --json 2>>"$STDERR_LOG"
)"
AUTH_STATUS=$?
if [ "$AUTH_STATUS" -ne 0 ]; then
  wrapper_log "external-review-claude: AUTH PREFLIGHT FAILED (auth-status-exit=$AUTH_STATUS)"
  wrapper_log "external-review-claude: not invoking review (no spend); orchestrator should skip external phase (exit 3)"
  exit 3
fi
# Pass the auth JSON as argv (NOT on stdin): the program itself is read from the
# heredoc on stdin, so stdin is unavailable for data.
AUTH_VERDICT="$(python3 - "$AUTH_JSON" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except (json.JSONDecodeError, ValueError, IndexError):
    print("FAIL unparseable-auth-status")
    sys.exit(0)
if not isinstance(d, dict):
    print("FAIL non-object-auth-status"); sys.exit(0)
logged_in = d.get("loggedIn") is True
method = d.get("authMethod")
provider = d.get("apiProvider")
sub = d.get("subscriptionType")
approved_subscriptions = {"pro", "max"}
sub_ok = isinstance(sub, str) and sub.lower() in approved_subscriptions
if logged_in and method == "claude.ai" and provider == "firstParty" and sub_ok:
    print(f"OK subscription={sub}")
else:
    print(
        "FAIL "
        f"loggedIn={d.get('loggedIn')} authMethod={method} "
        f"apiProvider={provider} subscriptionType={sub}"
    )
PY
)"
case "$AUTH_VERDICT" in
  OK*)
    wrapper_log "external-review-claude: AUTH OK ($AUTH_VERDICT) -- first-party subscription, proceeding"
    ;;
  *)
    wrapper_log "external-review-claude: AUTH PREFLIGHT FAILED ($AUTH_VERDICT)"
    wrapper_log "external-review-claude: not invoking review (no spend); orchestrator should skip external phase (exit 3)"
    exit 3
    ;;
esac

# ---- sterile, billing-safe review invocation --------------------------------
# Tool posture: prompt-only by default (most sterile); read-only file tools when
# a --repo is supplied. Never any write-capable tool (no Edit/Write/Bash).
TOOL_ARGS=(--tools "")
REPO_ARGS=()
PERMISSION_ARGS=()
if [ -n "$REPO" ]; then
  TOOL_ARGS=(--tools "Read,Grep,Glob")
  REPO_ARGS=(--add-dir "$REPO")
fi
if [ "$WEB_SEARCH" = "on" ]; then
  PERMISSION_ARGS=(--permission-mode auto)
  if [ -n "$REPO" ]; then
    TOOL_ARGS=(--tools "Read,Grep,Glob,WebSearch,WebFetch")
  else
    TOOL_ARGS=(--tools "WebSearch,WebFetch")
  fi
fi

# `--json-schema` takes the schema CONTENT (not a path); read the file in.
SCHEMA_CONTENT="$(cat "$SCHEMA")"

# Background job under scoped set -m: the subshell gets its OWN process group so
# the watchdog/trap can kill claude AND any descendants. set +m immediately
# after keeps later foreground children in the wrapper's own group.
set -m
(
  cd "$WORK" || exit 2
  exec "${SCRUB[@]}" claude -p \
    --setting-sources '' \
    --strict-mcp-config \
    --disable-slash-commands \
    --no-session-persistence \
    --no-chrome \
    --prompt-suggestions false \
    ${PERMISSION_ARGS[@]+"${PERMISSION_ARGS[@]}"} \
    "${TOOL_ARGS[@]}" \
    ${REPO_ARGS[@]+"${REPO_ARGS[@]}"} \
    --model "$MODEL" \
    --effort "$EFFORT" \
    --max-budget-usd "$MAX_BUDGET_USD" \
    --output-format json \
    --json-schema "$SCHEMA_CONTENT" \
    < "$PROMPT" > "$LOG" 2>>"$STDERR_LOG"
) &
REVIEW_PID=$!
set +m
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
REVIEW_STATUS=$?
if [ "$TIMED_OUT" -eq 1 ]; then
  wrapper_log "external-review-claude: review timed out after ${WATCHDOG_SECONDS}s"
else
  : "$REVIEW_STATUS"
fi

# ---- structural health check on the result envelope -------------------------
# HEALTHY iff the single JSON envelope parses AND type=="result" AND is_error is
# false AND subtype=="success" AND structured_output is present, schema-valid,
# and billed under --model. On HEALTHY, structured_output is written to the
# findings-file. total_cost_usd / token usage is surfaced to stderr regardless.
python3 - "$LOG" "$FINDINGS" "$MODEL" "$SCHEMA" "$WRAPPER_STDERR_LOG" <<'PY'
import json, sys

log_path, findings_path, want_model, schema_path, wrapper_stderr_log = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]


def emit(message):
    sys.stderr.write(message)
    if wrapper_stderr_log:
        with open(wrapper_stderr_log, "a", encoding="utf-8") as wf:
            wf.write(message)


def _matches_type(value, want):
    if want == "object":
        return isinstance(value, dict)
    if want == "array":
        return isinstance(value, list)
    if want == "string":
        return isinstance(value, str)
    if want == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if want == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if want == "boolean":
        return isinstance(value, bool)
    if want == "null":
        return value is None
    return True


def _validate_schema(value, schema, path="$"):
    errors = []
    if not isinstance(schema, dict):
        return [f"{path}: schema node is not an object"]

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} not in enum {schema['enum']!r}")

    want_type = schema.get("type")
    if isinstance(want_type, str) and not _matches_type(value, want_type):
        errors.append(f"{path}: expected {want_type}, got {type(value).__name__}")
        return errors

    if want_type == "object":
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append(f"{path}: missing required property {key!r}")
        if schema.get("additionalProperties") is False and isinstance(props, dict):
            for key in value:
                if key not in props:
                    errors.append(f"{path}: unexpected property {key!r}")
        if isinstance(props, dict):
            for key, child_schema in props.items():
                if key in value:
                    errors.extend(_validate_schema(value[key], child_schema, f"{path}.{key}"))

    if want_type == "array":
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(_validate_schema(item, item_schema, f"{path}[{idx}]"))

    return errors

try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read().strip()
    env = json.loads(raw) if raw else None
except (OSError, json.JSONDecodeError, ValueError):
    env = None

if not isinstance(env, dict):
    emit("external-review-claude: UNHEALTHY (no parseable result envelope)\n")
    sys.exit(1)

try:
    with open(schema_path, "r", encoding="utf-8") as sf:
        output_schema = json.load(sf)
except (OSError, json.JSONDecodeError, ValueError):
    emit("external-review-claude: UNHEALTHY (schema unreadable during health check)\n")
    sys.exit(1)

is_result = env.get("type") == "result"
is_error_false = env.get("is_error") is False
subtype = env.get("subtype")
structured = env.get("structured_output")  # schema-validated reviewer output

# Surface spend/usage regardless of verdict (graceful — never raises).
cost = env.get("total_cost_usd")
usage = env.get("usage") if isinstance(env.get("usage"), dict) else {}
def _g(k):
    v = usage.get(k)
    return v if isinstance(v, int) and not isinstance(v, bool) else 0
inp = _g("input_tokens")
out = _g("output_tokens")
cache_read = _g("cache_read_input_tokens")
emit(
    f"external-review-claude: USAGE cost_usd={cost} input={inp} "
    f"cache_read={cache_read} output={out}\n"
)

# Model cross-check: fail if the requested model is not among the billed models.
model_usage = env.get("modelUsage")
model_match = isinstance(model_usage, dict) and want_model in model_usage
if not isinstance(model_usage, dict):
    emit("external-review-claude: UNHEALTHY modelUsage missing or non-object\n")
elif want_model not in model_usage:
    emit(
        f"external-review-claude: UNHEALTHY requested model {want_model} not in "
        f"modelUsage keys {sorted(model_usage)}\n"
    )

schema_errors = []
if structured is not None:
    schema_errors = _validate_schema(structured, output_schema)
    if schema_errors:
        preview = "; ".join(schema_errors[:5])
        emit(
            f"external-review-claude: UNHEALTHY structured_output schema-invalid: {preview}\n"
        )

healthy = (
    is_result
    and is_error_false
    and subtype == "success"
    and structured is not None
    and not schema_errors
    and model_match
)
if not healthy:
    emit(
        f"external-review-claude: UNHEALTHY (type={env.get('type')} "
        f"is_error={env.get('is_error')} subtype={subtype} "
        f"structured_output={'present' if structured is not None else 'absent'})\n"
    )
    sys.exit(1)

try:
    with open(findings_path, "w", encoding="utf-8") as ff:
        json.dump(structured, ff, ensure_ascii=False, indent=2)
        ff.write("\n")
except OSError:
    emit("external-review-claude: UNHEALTHY (could not write findings file)\n")
    sys.exit(1)

sys.exit(0)
PY
health=$?

if [ "$health" -eq 0 ]; then
  wrapper_log "external-review-claude: HEALTHY (result/success, structured_output extracted) -- findings=$FINDINGS log=$LOG"
  exit 0
fi

if [ -n "$WRAPPER_STDERR_LOG" ]; then
  wrapper_log "external-review-claude: UNHEALTHY -- inspect $LOG, $STDERR_LOG, and $WRAPPER_STDERR_LOG to classify retry-vs-skip"
else
  wrapper_log "external-review-claude: UNHEALTHY -- inspect $LOG and $STDERR_LOG to classify retry-vs-skip"
fi
exit 1
