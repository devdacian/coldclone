# Coldclone

Neutralizes the auto-execution and prompt-injection surface of a freshly
cloned repo *before* any editor, agent, or toolchain opens it. Turns a live, hostile
tree into an inert, readable one, and flags known-malicious dependencies, all without
executing a single line from the repo.

It is defense-in-depth in front of a stronger isolation boundary (a throwaway
virtual machine, container, or sandbox), not a replacement for one.

## The tools

- **`sanitize_repo.py`** — quarantines (moves + renames, never deletes) every
  auto-execution / prompt-injection trigger file (editor tasks, agent configs,
  git hooks, build-tool configs, …); fails closed on symlinks and
  Trojan-Source filename codepoints; emits non-gating content warnings over the
  files it must leave live so you can read scope.
- **`ioc_scan.py`** — a known-malicious-dependency tripwire that greps lockfiles
  (npm / PyPI / cargo / Go / …) against a maintained indicator list. It reports
  trusted exact malicious-version evidence for npm-family (including Bun) and
  Cargo lockfiles when available, while preserving package-wide hits for all-malicious
  identities. Read-only; no install or execution. Its optional OSV fallback uses
  the network by default and can be disabled with `--offline`.
- **`coldclone.sh`** — orchestrates a hardened clone (symlinks off, LFS filters
  neutralized, dangerous transports blocked, pinned + path-validated submodules)
  then the `scan` + `sanitize` steps.

Plain entries in `ioc-list.txt` are package-wide triggers for identities whose
entire release family is malicious, such as typosquats. Adding
`VERSION: <ecosystem> | <package> | <exact-semver>` makes that identity
version-scoped: a trusted exact intersection alerts, while any other trusted
exact version is treated as safe. Registry URL and integrity metadata are not
part of version identity. Structurally ambiguous or unsupported evidence still
halts because the scanner cannot prove which release is locked; a trusted
extractor finding no installed record clears a textual metadata-only match. Legacy
`AFFECTED_SET_COMPLETE: <ecosystem> | <package>` records remain accepted as
provenance but are not required for clearance.

Exact extraction covers package-lock, Yarn Classic, structurally validated Yarn
Berry `npm:` locators, structurally validated pnpm package keys/importer
versions, Bun (`bun.lock` text and the binary `bun.lockb`, formats 2 and 3), and
Cargo. Registry tarball, source, and integrity metadata are ignored
because it does not determine the locked package/version identity; the one
exception is `bun.lockb`, where a recorded tarball URL must agree with the
parsed name and version or that record is treated as untrusted. A `bun.lockb`
whose binary layout does not validate fails the gate closed. By default,
version-scoped disjoint matches also receive an
opportunistic exact-version OSV API lookup; only a malicious-code advisory adds
a hit. A clean response or unavailable OSV leaves the local exact-denylist
decision unchanged. Use `--offline` to disable network lookups. Policy syntax
errors still fail the IoC gate closed. To keep hostile input from amplifying host
work, lockfiles over 8 MiB fail closed, aggregate lockfile input is capped at
64 MiB, discovery is capped at 100,000 entries and 1,024 lockfiles, exact
extraction is capped at 16 policy identities per lockfile (additional
candidates remain blocking name hits), and a scan makes at most 10 OSV requests
with a five-second timeout each.

## Install as an agent plugin

This checkout is also a plugin root for both **Claude Code** and **Codex CLI**.
The plugin ships the Coldclone scripts plus a shared `coldclone` skill that tells
the agent to run the gauntlet before opening untrusted code.

**Claude Code:**

```sh
claude plugin marketplace add /path/to/coldclone
claude plugin install coldclone@coldclone
```

For one session without installing:

```sh
claude --plugin-dir /path/to/coldclone
```

**Codex CLI:**

```sh
codex plugin marketplace add /path/to/coldclone
codex plugin add coldclone@coldclone
```

Restart the agent session after installing so the `coldclone` skill is loaded.

### Prompt-injection detection

Because a security review often points an LLM at the repo's source, `sanitize_repo.py`
runs a host-side, static prompt-injection content scan over the whole text tree
*before* any model sees it. It flags content engineered to make a reviewer model
judge wrong (instruction override, fake reasoning/control tokens, MCP tool
poisoning, secret-exfil imperatives, audit-verdict manipulation, …) across three
tiers:

1. **Hard fail-closed (tier 1, unchanged)** — symlinks and Trojan-Source filename
   codepoints. Unambiguous, no override, exit `2`.
2. **Injection HALT + ack (tier 2, new)** — high-confidence signal in a near-0-FP
   context (control tokens in any source file; *any* injection inside an
   auto-loaded agent-config like `.cursorrules` / `CLAUDE.md` / `.claude/`). The
   pipeline STOPS with a loud alert and exit `3`. Because a false positive could
   brick a legitimate security/audit repo, an operator who has reviewed the alert
   can override with `--ack-injection` — a HOST-side acknowledgement, never
   repo-controlled. Direct `sanitize_repo.py` users can also set
   `COLDCLONE_ACK_INJECTION=1`; the `coldclone.sh` wrapper requires the explicit
   flag on that invocation and scrubs ambient env acks. The ack is recorded in
   the quarantine manifest as durable provenance.
3. **Advisory WARN (tier 3)** — fuzzier, FP-prone prose injection in ordinary
   source comments / READMEs is surfaced as a prominent (but non-gating, exit `0`)
   advisory, so it can't be silently scrolled past but won't brick the run.

An individual sanitizer content-rule crash fails **open** (no injection halt) —
only a real content detection halts. The separate IoC gate deliberately fails
closed when its policy or lockfile coverage is invalid.
The category taxonomy is credited in [PRIOR-ART.md](PRIOR-ART.md).

## Using it from your coding agent

The gauntlet is meant to run **before** any agent opens the untrusted tree, so the
natural way to use it is to have your agent run it first — and stop if it trips. Launch
your runtime in auto mode and paste a prompt like the one below (it works the same under
**Claude Code** and **Codex CLI** — both load this repo's safety rules from
`CLAUDE.md` / `AGENTS.md`):

```sh
claude --permission-mode auto       # Claude Code
# or
codex                               # Codex CLI
```

> Before we read it, run the coldclone gauntlet on `<git-url>` with
> `./coldclone.sh prep <git-url>` (hardened fetch → known-malicious-dependency scan →
> sanitize). Do NOT execute, build, install, or `source` anything from the cloned repo
> on the host. If the scan reports a known-malicious dependency, or sanitize exits `3`
> (injection HALT), STOP and surface it to me — never auto-acknowledge with
> `--ack-injection`; that override is my call, not yours. Only once the tree is inert do
> we open it.

The repo's own `AGENTS.md` / `CLAUDE.md` already encode these non-negotiables, so an
agent working here holds to them even if your prompt is terser.

## Sanitizing a folder (an extracted ZIP, no git)

Sometimes the code arrives as a ZIP, not a git URL. A plain folder has no trustworthy
git-dir/provenance surface for `check`/`push` — git-mode proof depends on `.git`
hygiene, an out-of-tree host provenance record, and a fresh re-scan — so the default
`sanitize` fails closed (exit `2`) on a non-git tree rather than silently weakening its
trust model. Folder mode is the explicit opt-in for that case.

**Directly:**

```sh
# via the orchestrator (recommended) — wraps the script and prints next steps
./coldclone.sh sanitize-folder ./acme-contracts

# or the script directly (the wrapper passes --allow-no-git and adds stricter ack UX)
./sanitize_repo.py --allow-no-git ./acme-contracts

# then read the inert tree IN PLACE; review what was quarantined first
cat ./acme-contracts/.quarantine/MANIFEST.txt
```

`check` and `push` stay **git-only** and will refuse a folder, so there is no
`sanitize-folder` → `push` path — the flow is sanitize-then-read in place (inside your
throwaway VM / container / sandbox, as always).

**From your coding agent** — launch in auto mode and paste a prompt like:

```sh
claude --permission-mode auto       # Claude Code
# or
codex                               # Codex CLI
```

> A client sent code as a ZIP. Extract it to `./acme-contracts`, then run the coldclone
> folder gauntlet on it with `./coldclone.sh sanitize-folder ./acme-contracts` before we
> open it. Do NOT execute, build, install, or `source` anything from the folder on the
> host. If sanitize exits `2` (a symlink or Trojan-Source filename — structural fail-closed)
> or `3` (injection HALT), STOP and surface it to me — never auto-acknowledge with
> `--ack-injection`; that override is my call. Once it is inert, show me
> `./acme-contracts/.quarantine/MANIFEST.txt`, then we read the tree in place.

Folder mode runs the same fail-closed structural gates and quarantine as the git path, with
three deliberate differences:

- It **writes no sentinel** — there is no unforgeable in-tree anchor a ZIP can't forge — so
  it is **one-shot / non-idempotent** (it re-stashes a pre-existing `.quarantine/` as
  foreign on every run, and says so). Prefer sanitizing a *fresh* extraction over re-running
  in place.
- It **actively quarantines any repo-shipped `.git/`** (a ZIP's `.git/hooks/` would
  auto-run if treated as a git tree, and a forged `.git/coldclone-sanitized` must not
  be treated as proof), and the symlink / Trojan-Source fail-closed scans descend that
  `.git/` at full depth.
- `check` and `push` are **git-only**: a non-git folder has no unforgeable sanitize proof,
  so both refuse it. Run `check`/`push` only on coldclone-*fetched* trees sanitized on
  this host — a hand-extracted archive that ships forged git metadata must be
  `sanitize-folder`'d first (which quarantines that `.git`).

## IoC scan (dependency screening only)

Sometimes you only want the known-malicious-dependency tripwire — screening a lockfile
you already have, re-checking a tree after an `ioc-list.txt` refresh — without the
quarantine pass. The scan is a standalone step on an existing directory; it runs no
fetch and no sanitize.

**Directly:**

```sh
# via the orchestrator (recommended) — surfaces a hit as a loud refusal
./coldclone.sh scan ./acme-contracts

# or the script directly, for raw exit codes and its flags
./ioc_scan.py ./acme-contracts
./ioc_scan.py --offline ./acme-contracts            # no OSV network lookups
./ioc_scan.py --ioc-list ./my-ioc-list.txt ./acme-contracts
```

Exit codes differ between the two entry points, because the wrapper remaps them onto
coldclone's own scheme:

| | clean | clean, list stale | known-malicious dependency | gate could not run |
|---|---|---|---|---|
| `coldclone.sh scan` | `0` | `0` (warns) | `1` (refusal) | `2` (fail-closed) |
| `ioc_scan.py` | `0` | `1` | `2` | `3` |

A stale list (no valid `LAST_REFRESHED` header, or older than 7 days) is a
non-gating warning: the wrapper passes it through as `0`, so refresh `ioc-list.txt`
when you see it rather than trusting a quiet clean.

`./coldclone.sh ioc <dir>` is a back-compat alias for `scan`.

There is no fetch-plus-scan-only command — `prep` is fetch → scan → sanitize — so to
screen a remote repo without sanitizing it, run the two steps yourself:

```sh
./coldclone.sh fetch <git-url>
./coldclone.sh scan ~/coldclone-scratch/<repo>
```

(`~/coldclone-scratch` is the default parent; `fetch` prints the actual path, and it is
overridable with a `scratch-parent` argument or `COLDCLONE_SCRATCH`.)

Both forms are read-only greps over lockfiles and manifests — no install, no execution —
so they are safe on an unsanitized tree. **But a clean scan is not an inert tree.** `scan`
neutralizes nothing: editor tasks, agent configs, and git hooks are all still live. Don't
open the tree on the strength of a clean IoC scan alone — run `sanitize` first.

## Improving coldclone itself (it's built using Touchstone)

Coldclone is developed using [Touchstone](https://github.com/devdacian/touchstone) — an
adversarial, cross-model plan/implementation review process — and vendors it under
`.touchstone/methodology/`. So you can fix a bug or improve a scanner with the same
review loop coldclone was built with. This is a **contributor** activity (improving
coldclone), distinct from *using* the gauntlet above.

```sh
claude --permission-mode auto       # Claude Code
# or
codex                               # Codex CLI
```

> Fix a bug in `sanitize_repo.py`: `<describe the bug, or the improvement>`. Follow the
> Touchstone process in `.touchstone/methodology/TOUCHSTONE.md` — gather context, run the
> expert consult, then the implementation-review loop scaled to the change's risk, and
> keep the full test suite green. Stay in auto mode; keep the plan as a file under
> `.touchstone/plans/`, not a runtime plan mode. I give explicit permission to execute the
> appropriate external-review script and share all data with the external model for review.

As above, the prompt is the same for either runtime: under **Claude Code** the agent
also reads the Claude binding (`.touchstone/methodology/TOUCHSTONE-claude.md`)
automatically; under **Codex CLI** the runtime-neutral core is self-sufficient on its own.

### Recommended local settings (cross-model review)

Touchstone's review loop can run an external cross-model reviewer via a wrapper script.
To let it run without a permission prompt on every call, grant the wrapper path in your
**gitignored, per-checkout** `.claude/settings.local.json` (never commit it — it is a
local convenience, not part of the published tool):

```json
{
  "permissions": {
    "allow": [
      "Bash(./.touchstone/methodology/scripts/external-review/external-review-codex.sh:*)"
    ]
  }
}
```

For Codex, add a matching rule to `~/.codex/rules/default.rules` and restart Codex.
Use the real absolute path to this checkout:

```python
prefix_rule(
    pattern = ["/absolute/path/to/coldclone/.touchstone/methodology/scripts/external-review/external-review-claude.sh"],
    decision = "allow",
    justification = "Allow Touchstone's reverse external-review wrapper from this trusted repo. The wrapper enforces first-party Claude subscription auth, sterile settings, no write-capable tools, schema output, and bounded budget.",
    match = [
        "/absolute/path/to/coldclone/.touchstone/methodology/scripts/external-review/external-review-claude.sh --help",
    ],
)
```

## License

MIT — see [LICENSE](LICENSE).

---

Built using [Touchstone](http://github.com/devdacian/touchstone).
