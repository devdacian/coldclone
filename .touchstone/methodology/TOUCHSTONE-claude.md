# Claude Code notes (Touchstone)

The shared, runtime-neutral process lives in `TOUCHSTONE.md`. **Read `TOUCHSTONE.md`
first** — it carries the whole methodology (the process, the lens catalogue, the
review-prompt skeleton, the external-review contract, and the record contracts). This file
only carries the Claude-Code-specific *mechanisms* that implement those rules: how to spawn
an arms-length consult/review, the concrete key formats of the durable records, and how to
drive the external cross-model reviewer.

When `TOUCHSTONE.md` says "the active runtime's subagent/delegation mechanism," this
file is the concrete answer for Claude Code.

## The skill-creator consult & review delegation

`TOUCHSTONE.md` step 3 requires the expert **consult** to run in a **fresh delegated
context that did not build the rationale**. The Claude consult path is a fresh delegated
agent (the `Agent` tool, e.g. a `general-purpose` subagent) that **itself invokes the
`/skill-creator` Skill tool in its own context**, so it gets first-hand skill-creator
expertise AND genuine independence, and it is backgroundable via the `Agent` tool's
`run_in_background`.

**Bounding a delegated reviewer's exploration (the Claude binding of `TOUCHSTONE.md`
§ Prevent the stall by bounding exploration).** Give each delegated reviewer a small
explicit tool-call/read budget in its prompt and tell it not to verify unrelated
repo invariants unless the delta or named seams require it — a reviewer handed the
whole repo with "verify everything" over-explores and trips the agent stall watchdog
without finding a defect. Backgrounded reviewers are polled by reading their task
output file and complete via the same completion notification used everywhere else.

Arms-length plan/implementation **reviews** also run in a fresh delegated agent for
the same independence, but they carry the *review* expertise via the lens catalogue
in `TOUCHSTONE.md` — they are not required to invoke `/skill-creator`.

Do NOT satisfy the consult by invoking `/skill-creator` in the **main** session and
self-authoring the advice: that loads the skill into the very context that built
the rationale. "`/skill-creator` can't be backgrounded" is a reason to delegate it,
not a reason to run the consult inline.

### Parallel external skill-creator consult (Claude mechanism)

Run the external consult (`TOUCHSTONE.md` step 3) through the SAME
`.touchstone/methodology/scripts/external-review/external-review-codex.sh` wrapper as the
external REVIEW — the difference is purely the prompt framing: tell the external model to
apply skill-creator's principles and emit DESIGN-LEVEL recommendations against the same
brief (gathered context + initial suggestions), encoded per step 3's schema mapping.
Background it alongside the internal consult so the two arms run concurrently.

## The open-dilemma record (Claude mechanism)

`TOUCHSTONE.md` § A deferred dilemma blocks termination defines the record: its two
homes, the append-only `OPEN <key>:` / `RESOLVED <key>:` markers, and the reader. The
Claude-Code concretes:

- **Key minting.** `<dilemma-key>` is a short distinctive slug of the dilemma's own content
  (the same distinctive-substring-of-the-content, not-a-bare-label discipline the
  prompt-completeness self-check uses), chosen unique among **all** marker keys ever recorded
  in the active record — every `OPEN` AND every `RESOLVED` line, including orphan
  resolutions — by scanning them before appending; a slug that already appeared is
  suffixed/disambiguated. That keeps a resolved-then-re-raised dilemma's new key
  byte-distinct from its stale one and stops a fresh `OPEN` from colliding with an orphan
  `RESOLVED`. Re-deferring a still-open dilemma appends nothing.
- **Matching.** A `RESOLVED` marker closes only a byte-identical key; an orphan or duplicate
  `RESOLVED` is inert, so it can never cause a false-terminate.
- **Both homes are line markers.** In the plan file as in `.touchstone/.open-dilemmas.md`,
  resolution is recorded by *appending* a `RESOLVED` line, never by editing or erasing the
  `OPEN` line — so the before-append scan and the open-set computation are identical for
  both, even though the plan file is otherwise mutated each round.

## The session-state record (Claude mechanism)

`TOUCHSTONE.md` § Long-running session reliability defines the state note
(`.touchstone/.session-state.md`), its markers, and the in-flight set. Per-command logs live
under **`.touchstone/logs/<topic>/`** (the state note is the index, the logs are the
indexed). The Claude-Code concretes:

- **Keys.** Each command key is a **durable Touchstone run id + a command nonce**. The run
  id is a durable token written into `.touchstone/.session-state.md` at run start — NOT the
  ephemeral runtime session id, which a restart/compaction can reassign to the same logical
  run (making prior in-flight work look "foreign" and defeating reconcile). Before writing a
  key, scan existing keys and disambiguate a collision, as for dilemma keys.
- **Reconcile reasons.** A `reconciled` marker records its reason: `effects-landed`,
  `confirmed-not-landed`, or `superseded-by-rerun=<fresh-key>`. Reconcile-on-resume
  re-touching a command that is `dispatched` (or `reconcile-pending`) with no terminal marker
  keeps its existing key and appends NO duplicate `dispatched`/`reconcile-pending`.
- **Run-id open-ness.** A run id is "open" iff it prefixes ≥1 in-flight key. A run whose
  commands are all terminal is closed; a fresh run with no in-flight keys mints a new run
  id. Because a `reconcile-pending` key keeps its run open, discharge it at the resume that
  FIRST observes it (open its keyed dilemma then), not in a later run.
- **One session per checkout.** This record assumes one active Touchstone session per
  checkout; it is not a lock. On cold resume, adopt the single open run id and reconcile
  only that run's in-flight keys; if **multiple run ids are open**, STOP and surface the
  multi-run conflict — never treat a foreign `dispatched` key as a current-run obligation.
- **Dispatch/completion binding.** Write `dispatched` (+ key + non-secret
  command/cwd/log/start context) BEFORE the background launch returns. A backgrounded
  `Bash` (`run_in_background`) or `Agent` task **re-invokes the model with a completion
  notification** on finish; poll interim state by **reading the task's output/log file**
  (the launch reports its path). **Capture the exit status durably AT DISPATCH** — wrap the
  backgrounded command so its real exit status is appended to the log path as it exits — so
  `completed` + exit status is derivable even if the live handle is gone. If neither the
  handle nor a captured status is available, never fabricate `completed`: confirm effects
  from the artifact/log and append `reconciled`, or append `reconcile-pending` when effects
  are unconfirmable. Bound any retry of the launch itself (`TOUCHSTONE.md` § Bounded
  tool-retry) to ~30s, 2–3 attempts. If a future Claude Code changes the completion/poll
  handle, this section is its home — degrade to manual liveness/artifact reconciliation
  rather than depending on a specific tool name.

## The review-state record (Claude mechanism)

Claude Code uses `TOUCHSTONE.md` § Long-running session reliability → *Durable per-topic
review state* unchanged, at `.touchstone/logs/<topic>/review-state.md`.

## The consult-evidence record (Claude mechanism)

`TOUCHSTONE.md` § The consult gates review-loop entry defines the gate, its scope and its
fail-closed reader. The Claude-Code concretes:

- **Planned change:** a `## Consult evidence` section in `.touchstone/plans/<topic>-plan.md`,
  matched by its **`Consult evidence` heading base label** — an optional parenthetical suffix
  such as `## Consult evidence (step-3)` is allowed, so a natural heading variant does not
  false-block the fail-closed reader. The section has **exactly three fields** (the gate
  parses these names):
  - `internal:` — the internal consult's agent-id AND its output/log path, or an explicit
    `output-unavailable: <reason>` when the runtime exposes no durable transcript path (an
    agent-id alone is insufficient — the gate needs a resolvable pointer to the advice).
  - `external:` — the external findings path, OR `SKIPPED: <logged reason + log path>`.
  - `step-4 disposition:` — a one-line pointer to where each recommendation was verified
    and disposed.
- **Planning-skipped change:** one line appended to `.touchstone/.consult-evidence.md` carrying
  the change's topic slug as its key plus the same three fields. This is a presence check,
  not an open-set computation; a stale or duplicate-ambiguous entry fails closed.

## The Claude skill loader signal (optional)

Claude Code's skill loader emits a line of the form:

```text
Base directory for this skill: <absolute-path>
```

If a skill needs to bind its own absolute base directory (e.g. to invoke a
colocated script), it can treat that loader line as the positive Claude-Code
runtime signal and bind a path token to the literal path. This loader signal is
Claude-specific; other runtimes use their own explicit signals.

## External cross-model review — Claude orchestrates, GPT reviews (forward path)

`TOUCHSTONE.md` § External cross-model review describes the runtime-neutral loop. This is
the Claude-Code mechanism: Claude Code is the orchestrator and an external GPT model (via
the Codex CLI) is the reviewer.

**Invocation.** Claude shells out to `.touchstone/methodology/scripts/external-review/external-review-codex.sh`,
which owns the deterministic invocation only (flag assembly, sandbox/model pins,
the key scrub, capture wiring, the watchdog, and the structural health check). The
wrapper is named for the reviewer CLI it drives (`codex`), per the
`external-review-<reviewer>.sh` convention its file header documents; its sibling
`external-review-claude.sh` drives the reverse path.
Claude assembles the prompt-file each round per the `TOUCHSTONE.md` prompt-assembly
contract — and for the implementation loop concatenates the `git diff` into that
same file, because `codex exec` has a single stdin channel and no prompt-file flag.

**The wrapper's OWN CLI surface** (how Claude calls the wrapper — distinct from the
inner `codex exec` command shown below, which is what the wrapper assembles and runs
internally): `external-review-codex.sh --prompt <file> --schema <file> --findings <file>
--log <file> --cd <repo>` are **all required flags** — a missing one is a loud **exit-2**
config error — plus optional `--model` (default `gpt-6.1-sol`), `--effort` (default `high`),
`--web-search <on|off>` (default `off`), and `--watchdog-seconds` (default `600`).
Path validation differs by role and is also exit-2: `--prompt`/`--schema` must be
**existing readable files**; `--cd` an **existing directory**; `--findings`/`--log` are
**output** paths whose **parent directory must exist and be writable** (the files themselves
are created fresh, and must not point at a directory). `--prompt` is the assembled
prompt-file the wrapper pipes to `codex` on bare stdin (the wrapper does NOT read the prompt
from its own stdin).

**Artifact-directory precondition (Claude mechanism).** Run
`mkdir -p .touchstone/ext-review/<topic>/` before assembling the prompt-file or invoking the
wrapper (`TOUCHSTONE.md` § External cross-model review → **Output-directory precondition**).
The wrapper runs:

```
env -u OPENAI_API_KEY codex [--search] exec --ephemeral --cd <repo> --sandbox read-only \
  --skip-git-repo-check -m gpt-6.1-sol -c model_reasoning_effort="high" [-c web_search=disabled] \
  --output-schema .touchstone/methodology/scripts/external-review/findings.schema.json --json \
  -o <findings> < <prompt> > <log> 2>&1
```

Key points:

- **`-m gpt-6.1-sol -c model_reasoning_effort="high"`** — the reviewer is pinned
  explicitly so it stays deterministic even if the user's Codex default changes.
  Model-id caution: use the plain published model id, not a `-codex`-suffixed
  variant — a suffixed variant is not guaranteed to resolve under ChatGPT auth.
  `high` (not `xhigh`) is the field-validated effort; a round's cost is input-dominated
  (the repo reads), so escalate a specific thin round to `xhigh` only if it comes back thin.
- **`--json` is boolean** — it prints the JSONL event stream to stdout (redirected
  to the json-log); **`-o`** captures the clean final structured message, validated
  against the schema. The prompt is piped on bare stdin.
- **`OPENAI_API_KEY` scrub** — `env -u OPENAI_API_KEY` ensures a stray key cannot
  silently divert the reviewer to per-token API billing; the run stays on the
  included subscription quota.
- **`--web-search <on|off>`** — default off. `on` inserts Codex's top-level `--search`
  flag before `exec`; `off` passes `-c web_search=disabled`, so the forward wrapper is
  fail-closed by default. When to turn it on is `TOUCHSTONE.md` § External cross-model
  review → **Web-search policy**.
- **`--watchdog-seconds <N>` (default 600)** — the wrapper SELF-ENFORCES a per-round
  wall-clock watchdog (`codex exec` exposes no time/turn/tool-call cap, and a
  runaway tool-use loop can run for hours). On expiry it reaps the reviewer's full
  process tree (direct PID + snapshotted descendant tree + process group; TERM, 10s
  grace, KILL) — a group-only kill misses workers that re-`setpgid`/`setsid`
  themselves out of the shell-assigned group. Per-round value policy: `--watchdog-
  seconds 300` for a small/focused diff, `600` (the default) for a large diff.

**Health contract (structural — never the exit code).** A round is HEALTHY iff the
json-log contains a `{"type":"turn.completed"}` event AND no `{"type":"turn.failed"}`
event AND every `{"type":"error"}` event is a Codex transport notice — its string `message`
starts `Reconnecting...` (for example `Reconnecting... 2/5 (unexpected status 503 ...)`): the
stream resumed, and `turn.completed` proves it. Match the JSONL event's `type` field
exactly, never a substring of the stream — a review whose content discusses "error" would
false-positive a naive grep. `codex exec` can surface an in-band error event while the pipe
still exits 0, so the shell exit code is never trusted; the wrapper's own exit code (0
healthy / 1 unhealthy / 2 config) is the round verdict.

**Graceful degradation (classifier).** When a round is unhealthy, read the json-log
(it carries the failure event text) and classify retry-vs-skip per `TOUCHSTONE.md` §
Graceful degradation. A watchdog trip typically leaves no failure event in the log
(only the absence of `turn.completed`) — classify it from the wrapper's
`WATCHDOG-TIMEOUT` stderr marker (which matches the retryable `timed out` pattern) →
bounded retry → skip-and-proceed. A wrapper-exit-0 round whose findings file is
EMPTY or fails to parse is NOT a clean round — treat it like the unhealthy case
(bounded retry). The wrapper emits `WATCHDOG-CLEANUP` (no timeout-shaped token) when
a HEALTHY round merely needed a lingering process tree reaped; that marker can never
classify as a transient failure. Check non-retryable patterns first, then retryable;
cap retries at 2–3 attempts. (The retry cap bounds transient transport unhealth, a
different concept from review-round non-convergence — the loop itself carries no hard
round cap; see `TOUCHSTONE.md` § Three teeth guard the auto-disposition →
*Non-convergence health signal*.)

**Cost.** Each real round consumes the orchestrating model's subscription quota and
is input-dominated (the repo reads). Reasoning effort scales only the small output
slice, so `high` vs `xhigh` barely moves quota. This quota cost is the rationale for
why the EXTERNAL arm — never the mandatory internal floor — is the one gated on
availability/skip.

**Bash allowlist (local precondition, never committed).** Autonomous runs need
`Bash(./.touchstone/methodology/scripts/external-review/external-review-codex.sh:*)` granted in the **gitignored**
`.claude/settings.local.json`. Grant the wrapper path, not `codex exec:*` — the
wrapper is the thing invoked, and the narrower grant is cleaner. Stage this locally
per checkout; never commit it.

## The reverse direction — Codex orchestrates, Claude reviews

The reverse wrapper (`external-review-claude.sh`) contract lives in
`references/external-review-reverse.md`.
