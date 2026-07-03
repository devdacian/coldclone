# Claude Code notes (Touchstone)

The shared, runtime-neutral process lives in `TOUCHSTONE.md`. **Read `TOUCHSTONE.md`
first** — it carries the whole methodology (the process, the lens catalogue, the
review-prompt skeleton, the external-review contract). This file only carries the
Claude-Code-specific *mechanisms* that implement the runtime-neutral rules — among them:
how to spawn an arms-length consult/review, where the open-dilemma record lives, and how
to drive the external cross-model reviewer. A runtime with no separate notes file (a Codex
CLI orchestrator) is served by `TOUCHSTONE.md`'s runtime-neutral defaults plus its native
delegation mechanism; this file is Claude Code's elaboration on those defaults.

When `TOUCHSTONE.md` says "the active runtime's subagent/delegation mechanism," this
file is the concrete answer for Claude Code.

## The skill-creator consult & review delegation

`TOUCHSTONE.md` step 3 requires the expert **consult** to run in a **fresh delegated
context that did not build the rationale** (independence is about *who* runs the
consult, not *where* the skill loads).

The Claude consult path is a fresh delegated agent (the `Agent` tool, e.g. a
`general-purpose` subagent) that **itself invokes the `/skill-creator` Skill tool
in its own context**. The skill's instructions load into the *subagent's* context,
so the subagent gets first-hand skill-creator expertise AND genuine independence,
and it is backgroundable via the `Agent` tool's `run_in_background`.

**Bounding a delegated reviewer's exploration (the Claude binding of `TOUCHSTONE.md`
§ Prevent the stall by bounding exploration).** Give each delegated reviewer a small
explicit tool-call/read budget in its prompt and tell it not to verify unrelated
repo invariants unless the delta or named seams require it — a reviewer handed the
whole repo with "verify everything" over-explores and trips the agent stall watchdog
without finding a defect. Backgrounded reviewers are polled by reading their task
output file and complete via the same completion notification used everywhere else.

Arms-length plan/implementation **reviews** also run in a fresh delegated agent for
the same independence, but they carry the *review* expertise via the lens catalogue
in `TOUCHSTONE.md` — they are not required to invoke `/skill-creator`. The
fresh-delegated-context property is shared by consult and review; the
first-hand-`/skill-creator` property is specific to the consult.

Do NOT satisfy the consult by invoking `/skill-creator` in the **main** session and
self-authoring the advice: that loads the skill into the very context that built
the rationale, losing the independence step 3 exists to provide (and it can inherit
the orchestrator's own false premises). "`/skill-creator` can't be backgrounded" is
a reason to delegate it (so it occupies the subagent, not the main session), not a
reason to run the consult inline.

### Parallel external skill-creator consult (Claude mechanism)

When the external model is available, run an EXTERNAL skill-creator consult IN
PARALLEL with the internal delegated consult (`TOUCHSTONE.md` step 3). Reuse the SAME
`.touchstone/methodology/scripts/external-review/external-review-codex.sh` wrapper as the external REVIEW — the
difference is purely the prompt framing. Because this consult reuses the wrapper and is
often the run's FIRST external-review activity, satisfy `TOUCHSTONE.md` § External cross-model
review's **Output-directory precondition** first (`mkdir -p .touchstone/ext-review/<topic>/`).
Assemble a CONSULT-FRAMED prompt: tell the
external model to apply skill-creator's principles and emit DESIGN-LEVEL
recommendations against the same brief (gathered context + initial suggestions),
encoded as the findings-schema JSON. The schema
(`.touchstone/methodology/scripts/external-review/findings.schema.json`) still requires every
review-finding field; for consult-framed output the consult-specific content lives in
`claim` (recommendation headline) and `suggested_fix` (concrete change), while
non-applicable review fields use schema-valid placeholders. Background it alongside the
internal consult so the two arms run concurrently. The external consult, like the external review,
is an ENHANCEMENT, never a hard dependency: on an unavailable provider it is
SKIPPED (a logged skip, not a failure), and the orchestrator proceeds
internal-consult-only.

## The open-dilemma record location (Claude mechanism)

`TOUCHSTONE.md` § A deferred dilemma blocks termination requires the deferred-dilemma note
to live in a durable, **discoverable** record whose concrete location the runtime notes
file fixes — so a fresh or resumed Claude session can find an open record and be blocked
by it, without the writing context's in-memory state. The Claude-Code concrete rule:

- **Plan-phase:** the open-dilemma note is an entry in the active plan file
  (`.touchstone/plans/<topic>-plan.md`) — already discoverable, since that file is the artifact
  under review.
- **Implementation-phase / any phase with no live plan file:** the note lives in a single
  fixed file, **`.touchstone/.open-dilemmas.md`** (repo-relative, ignored via the
  `/.touchstone/*` negation rule, like the other review scratch there). Any Claude terminator checks that exact path before treating
  a round as terminating. Because the path is
  fixed and convention-derived (not held only in chat context), a resumed session
  re-derives it deterministically.

**The keyed marker shape (the Claude binding of `TOUCHSTONE.md`'s keying requirement).** On defer,
first check whether this dilemma already has an `OPEN <dilemma-key>:` entry with no matching
`RESOLVED` line — i.e. it is still open. If so it KEEPS that key and the defer appends nothing:
re-deferring a still-open dilemma must not create a duplicate `OPEN` (the runtime-neutral
"still open → keep the key" rule). Otherwise — a brand-new dilemma, or one that was resolved and
is now re-raised — the defer step appends a fresh `OPEN <dilemma-key>:` entry, where
`<dilemma-key>` is a short distinctive slug of the dilemma's own content (the same
distinctive-substring-of-the-content, not-a-bare-label discipline the prompt-completeness
self-check uses), chosen unique among **all** marker keys ever recorded in the active record —
every `OPEN` AND every `RESOLVED` line — by scanning them before appending; a slug that already
appeared (whether its dilemma is still open or already resolved) is suffixed/disambiguated,
which keeps a resolved-then-re-raised dilemma's new key byte-distinct from its stale one AND
stops a fresh `OPEN` from colliding with an orphan `RESOLVED`. "Clear" appends a `RESOLVED <dilemma-key>:` marker repeating that key **verbatim**
(the record is append-only — closure is recorded, not erased). A terminator computes the open
set as the `OPEN` keys with no byte-identical matching `RESOLVED` marker and treats a round as
terminating only when that set is empty (an orphan or duplicate `RESOLVED` is inert — it
removes nothing from the open set, so it can never cause a false-terminate). **Both homes use
the same line-oriented keyed markers:** in the append-only `.touchstone/.open-dilemmas.md` and in the
plan-phase plan-file home alike, resolution is recorded by *appending* a `RESOLVED` line, never
by editing or erasing the `OPEN` line — so the before-append uniqueness scan and the open-set
computation are defined identically for both, even though the plan file is otherwise mutated
each round.

This is the Claude binding of the runtime-neutral requirement. `TOUCHSTONE.md`'s
runtime-neutral default (the fixed `.touchstone/.open-dilemmas.md` path + the open/RESOLVED
keyed-marker shape) already serves a runtime without its own notes file; this section is
Claude Code's elaboration of those concretes.

## The session-state record location (Claude mechanism)

`TOUCHSTONE.md` § Long-running session reliability requires the checkpoint state note and command
logs to live in a durable, **discoverable** record whose concrete location and key format the
runtime notes file fixes — so a fresh or resumed Claude session can find in-flight work without
the writing context's in-memory state. The Claude-Code concrete rule, structured parallel to
§ The open-dilemma record location above:

- **Fixed path.** The state note is a single fixed file, **`.touchstone/.session-state.md`**
  (repo-relative) — the resume-discoverable index a cold-resumed session checks WITHOUT knowing
  any topic slug, exactly the property `.touchstone/.open-dilemmas.md` relies on. Per-command logs live
  under **`.touchstone/logs/<topic>/`** (per-topic — the state note is the index, the logs are
  the indexed).
- **Gitignore coverage.** Both paths are covered by the `/.touchstone/*` negation rule (no extra
  `.gitignore` edit needed), like the other review scratch there.
- **Cold-resume re-derivability.** Because the path is fixed and convention-derived (not held only
  in chat context), a resumed session re-derives it deterministically — the same rationale
  § The open-dilemma record location states for `.open-dilemmas.md` (not restated here).
- **Keyed markers (the Claude binding of `TOUCHSTONE.md`'s keying requirement).** Each command entry
  carries a **distinctive key** minted from a **durable Touchstone run id + a command nonce**. The
  run id is a durable token written into `.touchstone/.session-state.md` at run start — NOT the ephemeral
  runtime session id, which a restart/compaction can reassign to the same logical run (which would
  make prior in-flight work look "foreign" and defeat reconcile). `dispatched` writes the key. Each
  subsequent marker repeats that key **verbatim** on a new line (the record is **append-only** — never
  edit or erase the `dispatched`/`reconcile-pending` line, exactly like the open-dilemma record) and is
  one of three states (the Claude binding of the runtime-neutral three-state checkpoint model):

  | marker | exit status | meaning | terminal? | in in-flight set? | on resume |
  |---|---|---|---|---|---|
  | `completed` | known | finished; exit status recorded | yes | no | nothing |
  | `reconciled` | unrecoverable | reconcile obligation terminally disposed; **reason recorded** (`effects-landed` / `confirmed-not-landed` / `superseded-by-rerun=<fresh-key>` — for which the fresh key's `dispatched` is written FIRST, see escalation-bridge) | yes | no | nothing |
  | `reconcile-pending` | unrecoverable | non-idempotent command whose **effects are unconfirmed** | **no** | **yes** | resolve (escalation-bridge below): confirm effects → append a `reconciled` marker for the same key; else open a keyed deferred dilemma and LEAVE it `reconcile-pending` |

  The **in-flight / open set = `DISPATCHED` keys MINUS (`COMPLETED` ∪ `RECONCILED`) keys** — only the
  two TERMINAL markers subtract. A `reconcile-pending` key is non-terminal and stays in-flight until a
  resume appends a terminal marker *for that same key*; it is never silently retired (that would drop
  an unconfirmed non-idempotent command) and never blindly re-run. Use the same before-write uniqueness
  scan the open-dilemma record uses (scan existing keys, disambiguate a collision) — by reference to
  § The open-dilemma record location, not restated. Reconcile-on-resume re-touching a command that is
  `dispatched` (or `reconcile-pending`) with no terminal marker keeps its existing key and appends NO
  duplicate `dispatched`/`reconcile-pending` (the command analogue of the open-dilemma "still-open →
  keep the key, append nothing" rule).
- **Escalation-bridge (how a `reconcile-pending` key leaves the in-flight set — the bridge to the
  open-dilemma record).** When effects are unconfirmable, the observing resume opens a **deferred-dilemma
  entry keyed to the command** (§ The open-dilemma record location) and leaves the session-state key
  `reconcile-pending` — escalation itself appends NO terminal marker. The key is retired only when that
  dilemma receives a real disposition, at which point the resume APPENDS a terminal marker for the same
  key: `reconciled` with the disposition's recorded reason (`effects-landed` | `confirmed-not-landed` |
  `superseded-by-rerun`), or `completed`+status if the exit was genuinely recovered. A disposition that
  directs a re-run is an ADDITIONAL `dispatched` under a *fresh* key with its own lifecycle; the fresh
  key NEVER retires the original (only the original's own terminal marker does), so the re-run branch
  can neither wedge the original open forever nor mis-attribute another command's exit status to it.
  **Write order matters** (the record is append-only, with no atomic multi-marker write): append the fresh
  key's `dispatched` marker FIRST, and only THEN append the original's
  `reconciled[superseded-by-rerun=<fresh-key>]`. A crash between the two then leaves the original still
  in-flight — whether it was `dispatched` or `reconcile-pending` at re-run time (the in-flight math keeps
  either in-flight) — never terminal-without-a-live-replacement; the benign residual (both keys in-flight)
  is swept on the next resume, and "the fresh key never retires the original" keeps that coexistence sound.
  The command checkpoint thus stays open precisely as long as the dilemma it spawned — the concrete
  binding of the runtime-neutral "separate records, separate lifecycles," now with the bridge between
  them made explicit.
- **Run-id open-ness (no separate marker layer).** A run id is "open" iff it prefixes ≥1 in-flight
  command key (a key in `DISPATCHED` − (`COMPLETED` ∪ `RECONCILED`)). A run whose commands are all
  terminal is closed, and its persisted run-start token is inert (never misread as open); a fresh run
  with no in-flight keys simply mints a new run id; the multi-run STOP (below) fires only when ≥2 run
  ids each still prefix an in-flight key. Because a non-terminal `reconcile-pending` key is in-flight,
  it keeps its run id open — so the escalation-bridge obligation must be discharged at the resume that
  FIRST observes the `reconcile-pending`, not deferred to a later run; otherwise a stale
  `reconcile-pending` would trip the multi-run STOP for an unrelated future run (acceptable only as a
  backstop, never the intended primary path).
- **Concurrency precondition + cold-resume safety.** This record assumes **one active Touchstone
  session per checkout** — a NEW Claude-runtime precondition this section introduces (`TOUCHSTONE.md`'s
  "discoverable per-run location" guarantees discoverability, NOT a single-writer lock; the
  open-dilemma record merely shares the same unstated assumption, so neither locks). On cold resume,
  adopt the single open run id and reconcile only that run's in-flight keys; if **multiple run ids
  are open**, STOP and surface the multi-run conflict — never treat a foreign `dispatched` key as a
  current-run obligation.
- **Reader-disjointness.** `.touchstone/.session-state.md` is **NEVER consulted by the termination gate**
  (§ A deferred dilemma blocks termination) — only by the resume/reconcile path and the out-of-loop
  retention pass (below). The terminator reads `.touchstone/.open-dilemmas.md`; keeping the
  *terminator's* readers disjoint from the command record is what stops a stale `dispatched` from ever
  reading as a termination blocker.
- **The retention reader (out-of-loop).** The session-artifact retention pass (TOUCHSTONE.md § Long-running
  session reliability) READS this record's in-flight set (guard 3) to gate a delete, but it is **not the
  termination gate** — it runs *after* a loop has already terminated (same-session self-clean) or in a
  later session (cross-session sweep). It is therefore a defined ADDITIONAL out-of-loop reader of
  `.touchstone/.session-state.md`; the invariant above still holds because the terminator's read set is
  unchanged (still only `.open-dilemmas.md`), so a stale `dispatched` cannot false-block TERMINATION. The
  retention pass writes NO marker file (no reset, no truncation, no prune): the state/dilemma records are
  append-only and inert-by-computation once all keys are terminal (§ Run-id open-ness), and
  `.touchstone/.consult-evidence.md` is a survival record whose only mutation is copy-on-delete's
  idempotent per-change-key overwrite/no-op. Retention mutates only the per-topic `logs/`/`ext-review/`/plan
  artefacts, and fails closed on any uncertainty (retain).
- **The dispatch/completion binding.** Write `dispatched` (+ key + non-secret command/cwd/log/start
  context) BEFORE the background launch returns. Signal `completed` + exit status when the work
  finishes via the runtime's completion handle: in current Claude Code, a backgrounded `Bash`
  (`run_in_background`) or `Agent` task **re-invokes the model with a completion notification** on
  finish, and you poll interim state by **reading the task's output/log file** (the launch reports
  its path). **Capture the exit status durably AT DISPATCH** — wrap the backgrounded command so its
  real exit status is appended to the log path as it exits — so `completed` + exit status is
  derivable from the artifact even if the live handle is gone. If neither the handle nor a captured
  status is available, do NOT fabricate a `completed`: confirm the command's effects from its
  artifact/log — if effects are CONFIRMED, append `reconciled` (reason `effects-landed` or
  `confirmed-not-landed`); if effects are UNCONFIRMABLE, append `reconcile-pending` (non-terminal — it
  stays in-flight and is resolved via the escalation-bridge above, never silently retired). "never
  strands a `dispatched`" means every entry eventually reaches a TERMINAL marker (`completed` or
  `reconciled`) — possibly only after a `reconcile-pending` interlude and a deferred-dilemma
  disposition — not that a real exit code is always recoverable. Bound any
  retry of the launch itself (§ Bounded tool-retry) to ~30s, 2–3 attempts. If a future Claude Code
  changes the completion/poll handle, this section is its home — degrade to manual liveness/artifact
  reconciliation rather than depending on a specific tool name.

This is the Claude binding of the runtime-neutral requirement. `TOUCHSTONE.md`'s runtime-neutral
default (the fixed `.touchstone/.session-state.md` path + the dispatched/completed/reconciled token
shape and in-flight-set math) already serves a runtime without its own notes file; this section is
Claude Code's elaboration of those concretes (the key format, the runtime-tool dispatch/completion
handles).

## The consult-evidence record location (Claude mechanism)

`TOUCHSTONE.md` § The consult gates review-loop entry requires durable, **discoverable** evidence that the
step-3 consult ran *for this change* (and was disposed under step 4) before the first round of whichever
review loop the change reaches (step-5 plan-review, or step-7 implementation-review for a planning-skipped
change) — re-derivable by a fresh or resumed Claude session WITHOUT the writing
context's in-memory state, so inherited/resumed work cannot walk into the loop unguarded. The
Claude-Code concrete rule, structured parallel to § The open-dilemma record location and § The
session-state record location:

- **Planned change → a `## Consult evidence` section IN the plan file** (`.touchstone/plans/<topic>-plan.md`),
  matched by its **`Consult evidence` heading base label** — an optional parenthetical suffix such as
  `## Consult evidence (step-3)` is allowed, so a natural heading variant does not false-block the
  fail-closed reader. The plan file IS the artifact under review, so a resuming/inheriting session
  ALWAYS opens it — the evidence is unmissable, diffable, and the gate-reader and the artifact are the
  same file (strictly better than a separate file for the planned case). The section has **exactly
  three fields** (the gate parses these names):
  - `internal:` — the internal consult's agent-id AND its output/log path (or an explicit
    `output-unavailable: <reason>` when the runtime exposes no durable transcript path; an agent-id
    alone is insufficient — the gate needs a resolvable pointer to the advice that was evaluated).
  - `external:` — the external findings path, OR `SKIPPED: <logged reason + log path>`.
  - `step-4 disposition:` — a one-line pointer to where each recommendation was verified and disposed
    (so the record proves the advice was *evaluated*, not merely obtained).
- **No-plan-file residual** (a skill/methodology change that legitimately skips planning yet still needs
  a consult): append one line to a fixed **`.touchstone/.consult-evidence.md`** (repo-relative, ignored via
  the `/.touchstone/*` negation rule) carrying a **stable change-key** (the change's topic slug) plus the same
  three fields. This is a presence check — a single identifying label per entry so the reader can match
  THIS change — NOT the `.open-dilemmas.md` open-set/marker-difference apparatus (existence evidence,
  not an open-set computation).
- **Gate reader (fails CLOSED, scope-first at step-7).** Before the first round of whichever review loop
  the change reaches (step-5 plan-review, or step-7 implementation-review for a planning-skipped change),
  read the consult-evidence record: the plan file's `## Consult evidence` section, or — for a
  planning-skipped change, or a planned change whose plan file was already deleted (see copy-on-delete
  below) — the `.touchstone/.consult-evidence.md` entry whose change-key matches the current change. Because
  *every* implemented change reaches step-7, the step-7 reader checks **scope first**: a change outside the
  class step 3 governs (a typo or mechanical fix) is not gated and proceeds; only an in-scope
  skill/methodology change requires the record. For an in-scope change, treat the consult as **not done —
  do not start the loop** on a missing, empty, or unparseable record (and, for the fallback, a
  stale/duplicate-ambiguous one); inherited or resumed work lacking it resumes at step 3, not at the review
  loop it was about to enter (step 5 plan-review, or step-7 implementation-review for a planning-skipped
  change). Failing closed is deliberate — a fail-open reader would wave a change through on absent or stale
  evidence, the exact silent skip this gate exists to prevent.
- **Scope.** The gate fires only for the class step 3 governs — consult-required skill/methodology
  changes. It does not turn typo fixes or mechanical edits into consult-required work, even though they
  reach step-7's review loop; a change that *voluntarily* uses a plan/review loop is gated only when the
  governing process required step 3 for it — plan-presence is not itself a consult trigger.
- **Plan-deletion survival (copy-on-delete).** A *planned* change keeps its evidence in the plan file's
  `## Consult evidence` section, but `TOUCHSTONE.md` deletes the plan file when the review loop exits clean —
  so a planned change that later resumes at step-7 (after a clean step-5 plan-review deleted the plan)
  would find no record and fail closed back to step 3 despite having satisfied the gate. Therefore, before
  deleting a clean plan file, **copy its consult evidence into the fixed `.touchstone/.consult-evidence.md`
  fallback in the residual reader's schema** — synthesize the **stable change-key** from the plan's topic
  slug (the `<topic>` in `.touchstone/plans/<topic>-plan.md`) and emit the same three fields under it; a raw section
  paste is NOT matchable, because the in-plan section carries no change-key. Make it **idempotent**:
  re-running copy-on-delete for the same change-key overwrites/no-ops rather than appending a second entry,
  so it can never create the duplicate-ambiguous record the residual reader rejects. This is purely
  evidence *survival* — the gate stays the side-effect-free presence check above; a step-7 resume of a
  plan-deleted change simply reads this fallback entry in place of the gone plan-file section.

This is the Claude binding of the runtime-neutral requirement. `TOUCHSTONE.md`'s runtime-neutral
default (the in-plan `## Consult evidence` section or the fixed `.touchstone/.consult-evidence.md`
fallback, keyed by topic slug, with the internal / external / step-4-disposition change-key fields)
already serves a runtime without its own notes file; this section is Claude Code's elaboration of
those concretes.

## The Claude skill loader signal (optional)

Claude Code's skill loader emits a line of the form:

```text
Base directory for this skill: <absolute-path>
```

If a skill needs to bind its own absolute base directory (e.g. to invoke a
colocated script), it can treat that loader line as the positive Claude-Code
runtime signal and bind a path token to the literal path. This loader signal is
Claude-specific; other runtimes use their own explicit signals.

## Optional: auto-loading the lenses

In this minimal package the full lens catalogue lives inside `TOUCHSTONE.md`, which the
process tells you to read. Claude Code also auto-loads files under `.claude/rules/**`
when you edit matching paths. If you prefer the lenses to auto-load while editing
skill content, you can extract the *lens catalogue + review-prompt skeleton*
sections of `TOUCHSTONE.md` into a `.claude/rules/skill-review-lenses.md` file with
path-scoped frontmatter. This is purely a convenience; it is not required, and it
introduces a two-surface sync burden (keep the two copies aligned). The default
single-file shape avoids that.

## External cross-model review — Claude orchestrates, GPT reviews (forward path)

`TOUCHSTONE.md` describes the runtime-neutral external review loop. This is the
Claude-Code mechanism: Claude Code is the orchestrator and an external GPT model
(via the Codex CLI) is the reviewer.

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
config error — plus optional `--model` (default `gpt-5.5`), `--effort` (default `high`),
`--web-search <on|off>` (default `off`), and `--watchdog-seconds` (default `600`).
(There is **no** `--usage-ledger`/`--round`:
those are cyfrin-deliverables-only, absent from this wrapper.) Path validation differs by
role and is also exit-2: `--prompt`/`--schema` must be **existing readable files**;
`--cd` an **existing directory**; `--findings`/`--log` are **output** paths whose
**parent directory must exist and be writable** (the files themselves are created fresh,
and must not point at a directory). `--prompt` is the assembled prompt-file the wrapper
pipes to `codex` on bare stdin (the wrapper does NOT read the prompt from its own stdin).

**Artifact-directory precondition (Claude mechanism).** The Claude binding of `TOUCHSTONE.md`
§ External cross-model review's **Output-directory precondition** (the authoritative,
runtime-neutral rule lives there): run `mkdir -p .touchstone/ext-review/<topic>/` before
assembling the prompt-file or invoking the wrapper. The wrapper runs:

```
env -u OPENAI_API_KEY codex [--search] exec --ephemeral --cd <repo> --sandbox read-only \
  --skip-git-repo-check -m gpt-5.5 -c model_reasoning_effort="high" [-c web_search=disabled] \
  --output-schema .touchstone/methodology/scripts/external-review/findings.schema.json --json \
  -o <findings> < <prompt> > <log> 2>&1
```

When the wrapper is invoked with `--web-search on`, the inner command inserts the
top-level `--search` flag before `exec`. The default-off path instead passes
`-c web_search=disabled`, matching Codex's documented disable mode and preserving the
wrapper's fail-closed default.

Key points:

- **`-m gpt-5.5 -c model_reasoning_effort="high"`** — the reviewer is pinned
  explicitly so it stays deterministic even if the user's Codex default changes.
  `high` (not `xhigh`) is the field-validated effort; a round's cost is
  input-dominated (the repo reads), so escalate a specific thin round to `xhigh`
  only if it comes back thin.
- **`--json` is boolean** — it prints the JSONL event stream to stdout (redirected
  to the json-log); **`-o`** captures the clean final structured message, validated
  against the schema. The prompt is piped on bare stdin.
- **`OPENAI_API_KEY` scrub** — `env -u OPENAI_API_KEY` ensures a stray key cannot
  silently divert the reviewer to per-token API billing; the run stays on the
  included subscription quota.
- **`--web-search <on|off>`** — default off. `on` inserts Codex's top-level
  `--search` flag before `exec`; `off` passes `-c web_search=disabled`, so the
  forward wrapper is fail-closed by default. Enable it for consults and
  premise-bearing plan-review rounds; enable it for implementation-review only when
  the diff introduces, changes, or leaves unresolved a non-local external premise. A
  reviewer without web capability must raise `unresolved external premise`, not
  return clean, if it cannot resolve a load-bearing external premise locally.
- **`--watchdog-seconds <N>` (default 600)** — the wrapper SELF-ENFORCES a per-round
  wall-clock watchdog (`codex exec` exposes no time/turn/tool-call cap, and a
  runaway tool-use loop can run for hours). On expiry it reaps the reviewer's full
  process tree (direct PID + snapshotted descendant tree + process group; TERM, 10s
  grace, KILL) — a group-only kill misses workers that re-`setpgid`/`setsid`
  themselves out of the shell-assigned group. Per-round value policy: `--watchdog-
  seconds 300` for a small/focused diff, `600` (the default) for a large diff.

**Health contract (structural — never the exit code).** A round is HEALTHY iff the
json-log contains a `{"type":"turn.completed"}` event AND no
`{"type":"turn.failed"}` / `{"type":"error"}` event. Match the JSONL event's `type`
field exactly, never a substring of the stream — a review whose content discusses
"error" would false-positive a naive grep. `codex exec` can surface an in-band error
event while the pipe still exits 0, so the shell exit code is never trusted; the
wrapper's own exit code (0 healthy / 1 unhealthy / 2 config) is the round verdict.

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
round cap; see the Cost note's health-signal pin below.)

**Cost.** Each real round consumes the orchestrating model's subscription quota and
is input-dominated (the repo reads). Reasoning effort scales only the small output
slice, so `high` vs `xhigh` barely moves quota. This quota cost is the rationale for
why the EXTERNAL arm — never the mandatory internal floor — is the one gated on
availability/skip.

<!-- SYNC: the health-signal contract here — the non-blocking thresholds (first at review-round 10, then every 5), the review-round-counting exclusions, the whole-review-loop scope, AND the advisory-grounding of the in-memory round-counter reset (signal is advisory → reset changes timing/visibility only, never correctness/termination; spend unbounded until convergence or interrupt) — mirrors the TOUCHSTONE.md § External cross-model review *Non-convergence health signal (no hard cap)* paragraph; update both together. -->
**Non-convergence health signal (no hard cap) — Claude pin.** The external loop carries
**no hard round cap**; reject-only / adopt-deferred-only convergence with no open
dilemma stays the sole terminator (the authority is TOUCHSTONE.md § Parallel-arm
discipline → *Per-arm convergence / loop close-out*). This pin mirrors **TOUCHSTONE.md
§ External cross-model review — *Non-convergence health signal (no hard cap)*** (the
runtime-neutral authority for the values): surface a **non-blocking** progress summary
**first at review-round 10, then every 5 review-rounds thereafter** (counted since the
loop last (re)started — review rounds that reach disposition only, excluding wrapper
retries, exit-2 config failures, and malformed-attestation re-spawns), and **continue
automatically** unless the user interrupts. The signal is **whole-review-loop scoped** —
it fires for internal-only runs too, not only the external arm this Cost note is about,
so adjacency to the external-only framing above does not narrow it. No new durable
round-counter is minted (`.touchstone/.session-state.md` is command-lifecycle state, not
round accounting). The in-memory round-counter reset is safe because the signal is **advisory**
(non-blocking, user-interruptible): a reset changes the advisory signal's timing/visibility only,
never correctness or termination. Full crash-restart rationale — including why there is no spend
bound to lose — is canonical in TOUCHSTONE.md § Non-convergence health signal (no hard cap); see
there, do not restate it here.

**Bash allowlist (local precondition, never committed).** Autonomous runs need
`Bash(./.touchstone/methodology/scripts/external-review/external-review-codex.sh:*)` granted in the **gitignored**
`.claude/settings.local.json`. Grant the wrapper path, not `codex exec:*` — the
wrapper is the thing invoked, and the narrower grant is cleaner. Stage this locally
per checkout; never commit it.

## The reverse direction — Codex orchestrates, Claude reviews

The reverse direction (Codex orchestrates → Claude reviews) is pinned in
`TOUCHSTONE.md` § External cross-model review (§ The reverse direction) — Codex has no
separate notes file, so its concrete `external-review-claude.sh` wrapper contract lives in
the core, not in this Claude binding.
