# Reverse external review — Codex orchestrates, Claude reviews

This reference holds the concrete contract for driving
`.touchstone/methodology/scripts/external-review/external-review-claude.sh`: a Codex/GPT
orchestrator wanting a Claude reviewer of a different family. Read it before the first use of
that wrapper (which can be the step-3 external consult) and before classifying an unhealthy
reverse round. It is core-owned — that runtime has no notes file of its own — and kept out of
`TOUCHSTONE.md` only so Claude-orchestrated sessions do not load it. Everything runtime-neutral
about external review stays in `TOUCHSTONE.md` § External cross-model review and governs this
direction too: parallel-arm discipline, the output-directory precondition, the web-search
policy, the prompt-assembly contract, the three teeth, and graceful degradation.

## Invocation contract

Drive `external-review-claude.sh` directly as the top-level executable. It owns ONLY the
deterministic invocation; the orchestrator still owns prompt assembly, evidence verification,
finding disposition, retry-vs-skip classification, and loop control — exactly as in the forward
path, including `TOUCHSTONE.md` § External cross-model review's **output-directory
precondition** (`.touchstone/ext-review/<topic>/` must exist before assembling the prompt-file or
invoking the wrapper, or it exits 2). The reverse wrapper validates the parent of
`--wrapper-stderr-log` as well as `--findings`/`--log`; Claude child stderr stays at
`<log>.stderr`, sharing the `--log` parent.

For Codex `auto_review`, command shape is part of the safety contract. Create
`.touchstone/ext-review/<topic>/` in a separate setup command, then invoke the wrapper directly
with normal argv flags, including `--wrapper-stderr-log <file>`. Do not wrap the invocation in
`bash -lc`, `zsh -lc`, `env ...`, `&&`, heredocs, or shell redirection; those shapes can make
Codex evaluate a shell or compound command instead of the narrow, allowlisted wrapper and deny
the request as private workspace disclosure. The local approval rule should name the exact
absolute wrapper executable path for the trusted checkout or host repo, not `claude`, a shell,
a directory, a repo-relative path, or a wildcard.

**Invocation.** It runs headless `claude -p` with a sterile, billing-safe flag set:
`--model` (default `claude-opus-5-5`), `--effort` (default `high`), `--max-budget-usd` (a hard
subscription-spend cap, default `5`), `--web-search <on|off>` (default `off`), `--wrapper-stderr-log <file>`
(durable copy of wrapper-owned status markers), `--output-format json`, and `--json-schema` (the schema
CONTENT, read from the schema file). Sterility is assembled by flag — `--setting-sources ''`
(drops user/project/local settings, so no hooks/plugins/permissions/apiKeyHelper),
`--strict-mcp-config` with no `--mcp-config` (zero MCP servers), `--disable-slash-commands`
(skills off), `--no-session-persistence`, `--no-chrome`, `--prompt-suggestions false` — plus a
non-flag mechanism: the wrapper sets `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` (disables `CLAUDE.md` memory
loading) and runs the review in a throwaway scratch cwd, so a `CLAUDE.md` cannot auto-discover into the prompt.
`--bare` is deliberately NOT used (under `--bare`, OAuth/keychain auth is never read, which would
defeat subscription billing). **Tool posture:** prompt-only by default (`--tools ""`) — the
orchestrator inlines the diff/code into the prompt-file; passing `--repo <dir>` instead grants a
READ-ONLY tool set (`--tools "Read,Grep,Glob"` plus `--add-dir <dir>`) and never any
write-capable tool. When `--web-search on`, the wrapper adds `WebSearch,WebFetch` to that
tool set and passes `--permission-mode auto`; it still grants no write-capable tools and no
Bash. A web-enabled round remains structurally healthy or unhealthy by the same result-envelope
contract; zero web calls is not itself a wrapper failure because the reviewer may decide no
external premise needs checking. When to pass `--web-search on` is `TOUCHSTONE.md` § External
cross-model review's **Web-search policy**.

**Billing fail-closed.** The reviewer MUST bill the interactive first-party subscription, never
API per-token billing, an apiKeyHelper, or a 3P provider (Bedrock/Vertex/Foundry). Two mechanisms
enforce this: a shared **env scrub** unsets every API/provider/gateway/OAuth-token route for both
the preflight and the review (USER/HOME are deliberately preserved/repaired, since the OAuth token
lives in the OS login keychain), and a **fail-closed preflight** — a LOCAL keychain read of
`claude auth status --json` (no inference, no spend) — invokes review ONLY when it reports
`loggedIn==true`, `authMethod=="claude.ai"`, `apiProvider=="firstParty"`, and `subscriptionType`
in `{pro,max,team}`. It also rejects known local managed-settings paths (which could reintroduce
env/apiKeyHelper routes).

**Watchdog + health.** A per-round wall-clock watchdog (`--watchdog-seconds`, default `600`,
positive-integer) reaps the reviewer's full process tree (direct PID + descendant tree + process
group; TERM, grace, KILL) on expiry. The shell exit code of `claude -p` is never trusted; a
structural health check on the JSON result envelope is authoritative (HEALTHY iff it parses,
`type=="result"`, `is_error==false`, `subtype=="success"`, `structured_output` present and
schema-valid, and `--model` is among the billed models).

**Exit codes.** `0` HEALTHY round (findings-file ready to consume); `1` UNHEALTHY round
(missing/garbled envelope, error, non-success subtype, or absent/invalid/model-mismatched
structured output); `2` usage/config error (missing/unreadable arg, bad output dir, path
collision, invalid watchdog); `3` AUTH/BILLING preflight FAILED — fail-closed, the review is NOT
invoked (no spend), and the orchestrator treats it as a non-retryable skip and proceeds
internal-only. So an unverified auth surface costs nothing and degrades gracefully.

**Wrapper stderr capture.** The wrapper writes the full Claude result envelope to `--log` and
the Claude subprocess stderr to `<log>.stderr`, but wrapper-owned status markers — including
`AUTH OK`, health/usage summaries, and the final HEALTHY/UNHEALTHY line — belong to the wrapper
process's own stderr stream. For Codex reverse review, persist them by passing
`--wrapper-stderr-log <file>` on the direct wrapper invocation; that file is the durable per-round artifact
for wrapper process stderr. The wrapper duplicates its own markers to both
process stderr and that file after argument parsing, parent validation, and all path-collision
checks have succeeded. `<log>.stderr` is not a substitute for it. This distinction is
load-bearing for retry-vs-skip classification.

## Classifying an unhealthy reverse round

`TOUCHSTONE.md` § Graceful degradation sets the order (non-retryable first, then retryable with
bounded backoff). For the reverse wrapper, first run the deterministic helper
`.touchstone/methodology/scripts/external-review/classify_external_review_failure.py`
against a JSON payload carrying the wrapper exit code (`exit_code`), attempted wrapper
(`attempted_wrapper`), runtime (`runtime`), route/export metadata (`argv`, `read_root_flag`,
`diff_inlined`), durable wrapper process stderr (`wrapper_stderr`), and the full Claude result
envelope (`result_envelope` or `log_path`). Assemble that `wrapper_stderr` from the
`--wrapper-stderr-log` file produced by the direct reverse-wrapper invocation, distinct from the
child-stderr `<log>.stderr` sink, so the `AUTH OK` marker the predicate gates on is read from the
wrapper's stream and never the reviewer's — see **Wrapper stderr capture** for the full rationale.
The helper deliberately does not classify the
post-preflight 401 case from generic `stderr`, reviewer stderr, or `log_excerpt`; those streams
are diagnostic only. The helper is the executable field-level contract for the exact
zero-usage-401 predicate, and it always emits `allow_unsandboxed_retry=false`.

The one exception to non-retryable-first: if the reverse wrapper passed preflight (`AUTH OK` in
the captured wrapper process stderr) and then exited `1` with classification
`reverse_wrapper_post_preflight_auth_transient`, treat it as a post-preflight transient auth
invocation failure. Run sterile no-repo smoke probes before classifying the external arm
unavailable: `claude --setting-sources '' auth status --json`, then a tiny `claude -p` prompt
such as `Return exactly OK.` from a scratch cwd with wrapper-equivalent sterile no-repo posture
(billing-route env scrub, `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1`, `--setting-sources ''`,
`--strict-mcp-config`, `--disable-slash-commands`, `--no-session-persistence`, `--no-chrome`,
`--prompt-suggestions false`, `--tools ""`, no `--add-dir`, no web tools, the same model/effort
pin, and a small `--max-budget-usd` fuse). If both probes succeed, retry the same
reverse-wrapper command once with fresh `--findings`/`--log`/`--wrapper-stderr-log` paths (the
wrapper truncates each output it is given, so reusing one would erase the first attempt's evidence); if either probe fails or the
retry fails, log external auth unavailable and proceed internal-only. Never request an
unsandboxed repo/diff rerun for this class. That smoke-gated single retry is a semantic
post-preflight recovery path, not the generic transport retry rule.
