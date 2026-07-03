# coldclone — agent instructions

`coldclone` is a **host-side gauntlet for untrusted code**. It neutralizes the
auto-execution and prompt-injection surface of a freshly cloned repo *before* any
editor, agent, or toolchain opens it — turning a live, hostile tree into an inert,
readable one — and flags known-malicious dependencies, **without executing a single
line from the repo**. It is defense-in-depth in front of a stronger isolation
boundary (a throwaway VM, container, or sandbox), not a replacement for one.

## Non-negotiable safety rules (read first)

1. **Never execute, build, install, test, or `source` anything from an untrusted
   repo on the host** — not its scripts, not its `npm install`/`make`/`pip install`,
   not its toolchain, not its git hooks. The entire purpose is to inspect *without*
   running. If a task seems to require running the code, do it inside the disposable
   isolation environment, never on the host.
2. **Run the gauntlet before opening the tree.** Fetch → scan → sanitize, then read.
3. **An injection HALT (exit `3`) is a human decision.** Do NOT auto-acknowledge it.
   Surface the alert to the operator; only a human who has reviewed it re-runs with
   `--ack-injection`. The ack is host-side, never repo-controlled.
4. **A structural fail-closed (exit `2`) is final** — symlinks, Trojan-Source
   filename codepoints, or a non-git tree. No override. Stop and report.

## Workflow

1. **Fetch (hardened clone)** — `./coldclone.sh fetch <url> [scratch-parent] [--ref <branch|tag|commit>] [--submodules]`.
   Clones with symlinks off, LFS filters neutralized, dangerous transports blocked,
   and pinned + path-validated submodules. `./coldclone.sh prep <url> …` does
   fetch + scan + sanitize in one step.
2. **Scan for known-malicious dependencies** — `./coldclone.sh scan <dir>` (or
   `./ioc_scan.py <repo>`). A read-only tripwire that greps lockfiles
   (npm / PyPI / cargo / Go / …) against a maintained indicator list. No install, no execution.
3. **Sanitize** — `./coldclone.sh sanitize <dir>` (or `./sanitize_repo.py <repo>`).
   Quarantines (moves + renames, **never deletes**) every auto-execution /
   prompt-injection trigger (editor tasks, agent configs, git hooks, build-tool
   configs, …); fails closed on symlinks and Trojan-Source codepoints; emits
   non-gating content warnings over the files it must leave live so you can read scope.
4. **Only now open the inert tree** — ideally inside a throwaway VM / container / sandbox.

## Tool & exit-code reference

- **`coldclone.sh`** — `prep | fetch | scan | sanitize | check | push | pull`.
  Exit `0` ok · `1` refusal/usage (a known-malicious-dependency hit surfaces as a
  refusal) · `2` environment problem · `3` injection-halt.
- **`sanitize_repo.py <repo> [--dry-run] [--check] [--quiet] [--json] [--ack-injection]`**.
  Exit `0` ok · `2` structural fail-closed (tier 1) · `3` injection-halt (tier 2).
- **`ioc_scan.py <repo> [--ioc-list <path>]`** — read-only. Exit `0` clean · `2` indicator hit ·
  `3` fail-closed (couldn't scan). (Driven through `coldclone.sh scan`/`prep`, which surface a hit as a refusal.)

## The three-tier sanitize model

1. **Hard fail-closed (tier 1)** — symlinks and Trojan-Source filename codepoints.
   Unambiguous, no override, exit `2`.
2. **Injection HALT + ack (tier 2)** — a high-confidence signal in a near-zero-FP
   context (control tokens in any source file; *any* injection inside an auto-loaded
   agent-config such as `.cursorrules` / `CLAUDE.md` / `.claude/`). The pipeline STOPS
   with a loud alert and exit `3`. An operator who has reviewed the alert can override
   with `--ack-injection` (or `COLDCLONE_ACK_INJECTION=1`) on the same invocation — a
   host-side acknowledgement, recorded in the quarantine manifest as durable provenance.
3. **Advisory WARN (tier 3)** — fuzzier, FP-prone prose injection in ordinary source
   comments / READMEs is surfaced as a prominent but non-gating (exit `0`) advisory.

A scanner **crash always fails open** (no halt) — only a real detection halts.

## Working on coldclone itself (contributors)

This repo is developed with [Touchstone](http://github.com/devdacian/touchstone) — an
adversarial, cross-model plan/implementation review process. When improving coldclone's
own skills or methodology (not when *using* the gauntlet), and only if the framework is
present locally, read `.touchstone/methodology/TOUCHSTONE.md` for the process. This is an
optional, dev-only convenience; it is gitignored and not part of the published tool.
