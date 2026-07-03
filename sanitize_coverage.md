# `sanitize_repo.py` — Coverage Reference

What `sanitize_repo.py` handles in an untrusted repo, and what it does with each
item. Generated from the script's `DIR_NAMES` / `FILE_NAMES` / `GLOB_PATTERNS`,
the Phase-2 filename pre-scan, and the Phase-3 content-WARN parser — **the script
itself remains the source of truth; if this doc and the code disagree, the code
wins.**

## How it neutralizes things (four mechanisms)

- **Quarantine (the default action).** The target is **moved** into
  `<repo>/.quarantine/` and **renamed** — files get a `.quarantined.txt` suffix;
  a quarantined directory is moved wholesale and *every* file inside it is
  suffixed. Nothing is ever deleted. Renaming is the neutralizer: an editor only
  auto-runs `.vscode/tasks.json` at that exact path, Claude only loads `CLAUDE.md`
  by that exact name — moved + suffixed, the file is inert but still **readable**
  for the manual skim (what a repo *tried* to auto-run is evidence, and an
  executable config like `hardhat.config.ts`/`build.gradle` is still readable as
  `*.quarantined.txt` for scope).
- **Fail-closed (for symlinks AND hostile filename codepoints).** Real symlinks,
  and any filename containing a control / bidi / zero-width codepoint, make the
  script **refuse to run** (exit 2) and refuse the `--check` gate (exit 1). See
  "Symlink exfiltration" and "Filename structural defenses" below.
- **Filename WARN (non-gating).** Printable non-ASCII filenames and macOS
  case-collisions are flagged in the manifest but do not move anything or fail the
  gate.
- **Content WARN (fail-open, non-gating).** Left-live declarative files
  (`foundry.toml`, `Anchor.toml`, …) are parsed for high-signal danger keys and
  flagged in the manifest. A parse error is itself a WARN — it never changes the
  exit code.

The **quarantine vs left-live decision rule:** *quarantine* a config iff it is
executed as code by an editor/agent/toolchain, OR auto-fires on folder-open / a
non-build command, OR is a pure execution vector with no scope value; *leave live*
a declarative data manifest (TOML/JSON/XML) an auditor reads to understand scope
that only a deliberate build/test tool consumes (the read-only review process
already forbids running those).

Every run also writes a manifest (`.quarantine/MANIFEST.txt` — one append-only
`RUN:` block per invocation) and a host-controlled sentinel under `.git/` that
proves sanitize ran (used by the `coldclone.sh push` freshness gate). Quarantine
is idempotent — a re-run produces no new MOVES (it may re-emit current-state WARNs
in a new RUN block; the manifest is append-only audit history, and `--check`
re-derives state from the tree, not the manifest).

---

## 1. Editor / IDE auto-execution

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.vscode/` | dir | `tasks.json` `runOn: folderOpen`; `launch.json`; `settings.json` re-pointing tools; `extensions.json` | Quarantine dir |
| `*.code-workspace` | glob | Same `tasks`+settings payload as a loose top-level file | Quarantine file |
| `.devcontainer/` | dir | "Reopen in Container?" → Dockerfile / `postCreateCommand` | Quarantine dir |
| `.devcontainer.json` | name | Single-file devcontainer variant (same prompt as the dir form) | Quarantine file |
| `.idea/` | dir | JetBrains run configurations / startup tasks | Quarantine dir |

## 2. AI-agent prompt injection (file/dir based)

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `CLAUDE.md`, `CLAUDE.local.md` | name | Auto-loaded Claude Code instructions | Quarantine file |
| `AGENTS.md`, `AGENT.md`, `AGENTS.override.md` | name | Codex/other-agent instructions; `.override.md` takes precedence | Quarantine file |
| `copilot-instructions.md` | name | GitHub Copilot agent instructions (incl. nested/submodule copies) | Quarantine file |
| `GEMINI.md` | name | Gemini CLI system-level instructions | Quarantine file |
| `.windsurfrules` | name | Windsurf (Codeium) agent rules (CVE-2025-61590..61593 RCE class) | Quarantine file |
| `.aider.conf.yml`, `.aiderrc` | name | Aider config: `--exec` hooks, custom endpoints, shell commands | Quarantine file |
| `.roomodes`, `.roo-instructions.md` | name | Roo Code agent files (full shell tool access) | Quarantine file |
| `.clinerules` | name + dir | Cline rules (file or directory form) | Quarantine |
| `.mcp.json`, `mcp.json` | name | Auto-configured MCP servers (arbitrary commands as "tools") | Quarantine file |
| `.claude/`, `.agents/` | dir | Claude Code / cross-agent hooks, commands, skills, settings | Quarantine dir |
| `.cursor/`, `.cursorrules` | dir/name | Cursor rules / hooks | Quarantine |
| `.gemini/`, `.aider/`, `.continue/`, `.windsurf/`, `.codeium/`, `.junie/` | dir | Agent config/cache/skills trees (MCP configs, custom commands that exec shell) | Quarantine dir |

`.agents/` is retained (a human-review draft had dropped it).

## 3. Shell / environment auto-execution

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.envrc` | name | **direnv** runs arbitrary shell on `cd` — before editor or agent | Quarantine file |
| `.env.local` | name | Sourced by some tooling; can inject `PATH`/env | Quarantine file |
| `.mise.toml`, `mise.toml` | name | **mise/rtx** auto env + task execution on directory entry | Quarantine file |
| `.tool-versions` | name | **asdf** version file | Quarantine file |
| `.python-version` | name | **pyenv** auto-switch on `cd` (custom build hooks can exec) | Quarantine file |

## 4. Toolchain / compiler override

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.cargo/` | dir | `config.toml` aliases/overrides `rustc`/`cargo` with arbitrary executables | Quarantine dir |
| `rust-toolchain`, `rust-toolchain.toml` | name | Pins/overrides the toolchain Rust tools invoke | Quarantine file |
| `build.rs` | name | rust-analyzer **compiles + executes** `build.rs` the moment a trusted Rust project opens (auto-fire-on-open). `Cargo.toml` (declarative) is left live. | Quarantine file |

## 5. Git-hook managers & pre-commit

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.githooks/`, `.husky/` | dir | Committed hook trees wired via `core.hooksPath` / husky | Quarantine dir |
| `lefthook.yml`, `lefthook.yaml`, `.pre-commit-config.yaml` | name | Hook-manager configs | Quarantine file |

## 6. Git-level structural

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.gitattributes` | name | Filter-driver smudge/clean on checkout (CVE-2021-21300, CVE-2025-26625). Belt-and-suspenders: the host clone already neutralized LFS filters, and **no documented workflow step reads it after checkout** — so it is safe to quarantine. | Quarantine file |
| `.gitmodules` | — | Submodule URL poisoning (CVE-2025-48384). **LEFT LIVE** (see the Left-live table + content-WARN): plain `coldclone.sh fetch`, the manual registered-path flow, and the in-isolation submodule fallback all read it at its real path *after* sanitize, so quarantining would strand them. The clone-time vector is already mitigated by the hardened `--no-recurse-submodules` clone + `coldclone.sh` path/protocol validation. | Left live + content-WARN |

The `.gitattributes`-quarantined / `.gitmodules`-live split is the deliberate
asymmetry: only `.gitmodules` is still read by a workflow step after sanitize.

## 7. Package-manager wrapper hijacks

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.yarnrc.yml` | name | `yarnPath:` redirects every `yarn` command to repo JS | Quarantine file |
| `.yarn/` | dir | Yarn Berry `releases/*.cjs` + `plugins/*.cjs` payloads | Quarantine dir |
| `.pnpmfile.cjs` | name | pnpm hooks on every install/resolve | Quarantine file |
| `.npmrc` | name | `script-shell=/path` bypasses global `ignore-scripts=true`; `ignore-scripts=false`; registry redirect (Koi Security, Jan 2026). Fires on any npm command touching lifecycle hooks, incl. `npm ls`. | Quarantine file |

## 8. JVM — Gradle / Maven

Executable build scripts are quarantined (readable copy preserves scope, same
doctrine as `hardhat.config.ts`); the declarative `pom.xml` is left live.

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `gradlew`, `gradlew.bat`, `mvnw`, `mvnw.cmd` | name | Wrapper scripts run attacker code before the real Gradle/Maven | Quarantine file |
| `gradle-wrapper.jar` | name | Opaque committed bytecode `./gradlew` runs directly | Quarantine file |
| `gradle-wrapper.properties` | name | `distributionUrl` supply-chain vector (GHSA-pfq2-hh62-7m96) | Quarantine file |
| `build.gradle`, `build.gradle.kts` | name | Groovy/Kotlin DSL executed on **every** gradle invocation incl. task-list | Quarantine file |
| `settings.gradle`, `settings.gradle.kts` | name | Evaluated *before* `build.gradle` on every invocation | Quarantine file |
| `.mvn/` | dir | Maven wrapper dir: `maven-wrapper.jar` + `maven-wrapper.properties` + jvm/maven.config | Quarantine dir |
| `buildSrc/` | dir | Gradle: auto-compiled and placed on the build classpath | Quarantine dir |
| `pom.xml` | — | Maven POM — **LEFT LIVE** (declarative XML scope file; fires only on `mvn`) | Left live + content-WARN (dangerous plugins / inline `<script>` / DOCTYPE-refusal — see the content-WARN table) |

## 9. Python build & test

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `conftest.py` | name | pytest **auto-imports** every `conftest.py` on `pytest --collect-only` (no tests run) | Quarantine file |
| `setup.py` | name | Executable Python build script (`pip install -e .`); readable copy preserves dep metadata | Quarantine file |
| `sitecustomize.py`, `usercustomize.py` | name | Auto-imported at interpreter startup when cwd/repo is on `sys.path` | Quarantine file |
| `noxfile.py` | name | nox task config (executable Python) | Quarantine file |
| `ape-config.yaml`, `ape-config.yml` | name | ApeWorx config — sibling of the already-quarantined `brownie-config.*` | Quarantine file |
| `pyproject.toml` | — | **LEFT LIVE** (declarative scope manifest; build-hook tables fire only on build) | Left live + content-WARN |

## 10. Container / Compose

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml` | name | CVE-2025-62725: malicious annotation-derived paths traverse outside the cache dir; fires on **any** Compose command incl. `docker compose config` | Quarantine file |

## 11. Nix / Pixi / Deno / Bun

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `flake.nix`, `shell.nix`, `default.nix` | name | Nix expressions evaluated by `nix develop`/`nix-shell` (or `.envrc` `use flake` — `.envrc` already quarantined). Mostly inert here; cheap defense-in-depth. | Quarantine file |
| `pixi.toml` | name | Pixi tasks (arbitrary shell), shell-hook auto-activation | Quarantine file |
| `deno.json`, `deno.jsonc` | name | Deno `tasks` (arbitrary shell), import maps; auto-discovered upward | Quarantine file |
| `bunfig.toml` | name | Bun `[install]`/`[run]`; also auto-loads `.env` | Quarantine file |

## 12. Executable build-tool configs

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `*.config.{js,cjs,mjs,ts,cts,mts}` | glob | `hardhat/vite/webpack/next/babel/…` executable JS/TS configs (`.cts`/`.mts` are the TS CJS/ESM variants added here) | Quarantine file |
| `truffle-config.js` | name | Executable Truffle config (doesn't match `*.config.*`) | Quarantine file |
| `brownie-config.yaml`, `brownie-config.yml` | name | Brownie (Python) compiler/console hooks | Quarantine file |
| `Anchor.toml` | — | **LEFT LIVE** (Solana scope manifest; `[scripts]`/`[test]` fire only on `anchor` commands) | Left live + content-WARN |

## 13. Lint / coverage executable configs (rc-style)

| Target | Match | Attack it neutralizes | Action |
|---|---|---|---|
| `.eslintrc.js`, `.eslintrc.cjs`, `.prettierrc.js`, `.prettierrc.cjs` | name | Executable ESLint/Prettier configs | Quarantine file |
| `.solhintrc.js`, `.solhintrc.cjs` | name | Solidity linter (solhint) executable config (doesn't match `*.config.*`) | Quarantine file |
| `.solcover.js`, `.solcover.cjs`, `.solcover.mjs` | name | solidity-coverage executable config | Quarantine file |

## 14. Monorepo orchestrators

| Target | Match | Disposition |
|---|---|---|
| `nx.json`, `turbo.json` | — | **LEFT LIVE + content-WARN** (declarative JSON task graphs; fire only via `nx`/`turbo` CLI; carry project-graph scope value — treated like `Makefile`). Content-WARN flags `targetDefaults` executor/command + `tasksRunnerOptions` (nx) and `pipeline`/`tasks` entries (turbo). |

---

## Filename structural defenses (Phase 2 — `scan_filenames`)

A single `os.walk` over the worktree (excluding `.git/`, never following
symlinks) checks every path component, in two tiers:

- **Fail-closed (exit 2 sanitize / exit 1 `--check`):** any component containing a
  codepoint with no legitimate filename use — C0 controls (0x00–0x1F), DEL (0x7F),
  C1 controls (0x80–0x9F), bidi marks LRM/RLM/ALM (U+200E/200F/061C), bidi
  overrides + isolates (U+202A–202E, U+2066–2069), and zero-width / invisible / BOM
  (U+200B–200D, U+2060, U+2061–2064, U+FEFF). These are Trojan-Source / review-
  evasion vectors. *NUL (0x00) cannot occur in a POSIX filename — the kernel
  rejects it at `creat`/`rename` — so the C0 range covers it with no NUL-specific
  code.* Runs in the same fail-fast position as the symlink check, before any
  rename and before the sentinel write.
- **WARN (non-gating):** any *other* non-ASCII codepoint (printable, e.g. CJK /
  emoji) — flagged with its Unicode name. A blanket non-ASCII flag (not a brittle
  homoglyph mapping table) catches confusables/homoglyphs in one predicate. And
  macOS **case-collisions** — two entries in a directory whose casefolded names are
  equal — best-effort: on a case-insensitive host volume (the macOS default this
  runs on) the collision already collapsed at clone time and is undetectable, so
  this fires on a case-sensitive volume / Linux host.

The split is load-bearing for `--check`: **fail-closed conditions gate the push
freshness check; WARN conditions never do** (a tree with a CJK filename must still
ship).

## Content WARN over left-live files (Phase 3 — `scan_content_warn`, FAIL-OPEN)

Left-live files can't be neutralized by renaming, so the script parses them for
high-signal danger keys and emits manifest WARNs — a **skim-time nudge, not a
security boundary** (the isolation environment is). Every handler is wrapped: a malformed/odd file
yields `WARN could not parse <f>; review manually` and the scan continues — it
**never** changes the exit code or gates `--check`. Stdlib only (`tomllib` ≥3.11,
`json`); on an older interpreter the TOML handlers degrade to the fail-open path.

**Display safety (no raw clickable URL).** Every attacker-controlled token a WARN
interpolates — a value, path, key, or label — is rendered defanged
(`hxxp[:]//evil[.]example` instead of `http://evil.example`) via `_defang_repr`
(repr'd values) / `_defang_if_url` (bare labels) / `_defang` (URL tokens), so a
reviewer skimming flagged output cannot fat-finger-click a hostile link and a
terminal / editor / CI-log renderer will not auto-link or auto-fetch it. Defanging
is display-only and never feeds a detection decision (which is taken from the raw
value).

| File | Flagged keys |
|---|---|
| `foundry.toml` | `ffi = true` (any profile); non-system `solc`/`solc_version`/`solc_path` (repo-local / not under `/usr`,`/opt`,`/home`,`/Users`,…; `/home` & `/Users` are system so svm-managed `~/.svm/.../solc` is NOT flagged); `fs_permissions` **only on write/read-write grants** (a read-only grant is hardening, not flagged) |
| `Anchor.toml` | non-empty `[scripts]` / `[test]`; `[toolchain]` repo-local pins; `[provider]` cluster (informational) |
| `pyproject.toml` | non-standard `[build-system] build-backend` / `backend-path`; `[tool.hatch.build.hooks.*]`; setuptools `cmdclass`/`ext-modules`; `[tool.pytest.ini_options]` `addopts`/`plugins`; **`[tool.setuptools] data_files`/`data-files` installing to a system/home destination** (`/etc`,`/usr`,`/bin`,`/var`,`~`/`$HOME`/`${HOME}`, component-aware so `/etcetera` is not flagged) — writes outside site-packages on `pip install` (both the `{dest: […]}` table and `[[dest, […]]]` list-of-pairs shapes) |
| `slither.config.json` | `compile_force_framework`; `compile_custom_build` (arbitrary build command); non-system `solc` |
| `pom.xml` | parsed with stdlib ElementTree: known-dangerous plugins (`exec-maven-plugin`, `maven-antrun-plugin`, `groovy-maven-plugin`/`gmaven-plugin`, `maven-invoker-plugin`, `frontend-maven-plugin`, `maven-enforcer-plugin`) matched on `groupId:artifactId` **or artifactId-alone** (Maven defaults an omitted `<groupId>` to `org.apache.maven.plugins`, so a no-groupId declaration cannot evade) + inline `<script>` elements; a clean pom still emits a present/left-live nudge. **DoS guard:** a pom declaring `<!DOCTYPE`/`<!ENTITY>` is refused parsing (stdlib ET expands internal entities → billion-laughs), and a >5MB left-live file is skipped — both WARN. XML build *logic* beyond the plugin allow-list is still trivially evaded (the isolation environment is the boundary). |
| `.gitmodules` | submodule `url` using `ext::`/`file:` (code-exec class) **and** `git://`/`ftp://`/`ftps://` (weak-transport, informational) **and** localhost/loopback hosts (SSRF-equivalent, informational); `path` that is absolute / has a `..` **component** / contains control or CR (CVE-2025-48384). Component-aware: a benign `third_party/foo..bar` path and a relative-to-origin `../sibling.git` url are NOT flagged. |
| `nx.json` | `targetDefaults` entries with `executor`/`command`; `tasksRunnerOptions` present (custom task runner may exec) |
| `turbo.json` | non-empty `pipeline` (v1) / `tasks` (v2) task definitions |
| `package.json` | `scripts` values matching a **loud** danger pattern (IGNORECASE, the script body is never echoed — the WARN names the script + signal): fetch-pipe-to-shell (`curl`/`wget … \| sh/bash/node`), `base64 -d`/`atob(`/`xxd -r` decode-run, `node -e`/`python -c`/`eval`/`bash -c` inline-eval, named-secret exfil (`$NPM_TOKEN`/`$GITHUB_TOKEN`/`$AWS_*`/`printenv`/`env \|`), home/`/etc` writes (`~`/`$HOME`/`${HOME}` `.ssh`/`.bashrc`/`.profile`, `/etc/`); **stager URLs** in any script value (raw.githubusercontent/gist/pastebin/…, link shorteners, `.sh`/`.ps1`-path URLs, bare-IP URLs — shown defanged, DNS-label-boundary so a known host as a prefix of another domain is not a FP). Output capped (`WARN_PKG_SCRIPT_CAP` scripts, `WARN_SCRIPT_VALUE_MAX` bytes/value). |
| `Cargo.toml` | `[package] build = "<name>"` where `<name> ≠ build.rs` (a **custom build script that evades the `build.rs` basename quarantine**); dependency `path` escaping the cloned repo root (`..` component / absolute / Windows-drive / UNC) across `[dependencies]`/`[dev-dependencies]`/`[build-dependencies]` **and target-specific `[target.<triple>.*]` tables**; `[patch]` (2-level) / `[replace]` (1-level) supply-chain overrides + their `git`/`registry` stager URLs (override keys may be URLs → shown defanged). One shared `WARN_CARGO_DEP_CAP` counter bounds all dep + override traversal. |
| `go.mod` / `go.work` | line-scanned (single-line + `replace ( … )` block, `//`-comments stripped). Two-tier: ONE summary line if any `replace` directive exists (dependency-source override), plus a **louder** per-entry WARN when the `=>` RHS is a filesystem path escaping the repo root (`..`/absolute/Windows-drive/UNC). `require`-side ignored (normal declarations). Capped `WARN_GO_REPLACE_CAP`/`WARN_LINE_CAP`. |
| `composer.json` | `scripts` lifecycle events (`pre-`/`post-install-cmd`, `post-autoload-dump`, …) — REUSES the package.json **loud** corpus (incl. `php -r`; `php -d` is NOT flagged) + stager URLs, same display contract (name event + signal, never echo body). Values may be a **string or an array of strings** (both scanned). **LIMIT (conscious):** PHP callable / `@php` / `Vendor\Class::method` scripts run in-process (no shell) and are NOT matched — the isolation boundary is the defense (cf. the pom.xml plugin allow-list admission). |
| requirements family (`requirements*.txt`, `*-requirements.txt`, `constraints*.txt`, `requirements/*.txt` — a name PREDICATE, since the split layout is the norm) | logical-line scan (joins `\`-continuations, strips `#`-comments). Flags: `--index-url`/`--extra-index-url`/`--find-links`/`-i` index redirects (dependency-confusion); `git+`/`hg+`/`svn+`/`bzr+` VCS installs; direct `https?://…(.tar.gz/.tgz/.whl/.zip/.tar.bz2)` and PEP 508 `pkg @ URL` archive installs; `-e`/`--editable` VCS/URL (defanged) or root-escaping path (raw); `-r`/`-c` includes (WARN, not followed). Flag tokens anchored to line-start/whitespace so a path containing `-i`/`-e` is not a FP. URL tokens defanged; `.in` pip-tools / Pipfile deferred. |

---

## Deliberately LEFT LIVE (needed to read scope; fire only on a build/test tool)

A first-class peer of the quarantine tables — quarantining any of these would
blind the auditor to scope (or break a workflow step).

| Target | Why left live | When it WOULD fire | What to watch (content-WARN) |
|---|---|---|---|
| `foundry.toml` | EVM scope: remappings, networks, solc | `forge test`/`script` (cheatcodes) | `ffi`, repo-local `solc`/`solc_version`/`solc_path`, `fs_permissions` (write grants only) |
| `Anchor.toml` | **Solana scope: `[programs.*]` in scope** | `anchor test`/`run` | `[scripts]`/`[test]`/`[toolchain]` |
| `Cargo.toml` | Rust scope manifest | `cargo build` (and `build.rs`, which IS quarantined) | custom `build = "<name≠build.rs>"`; repo-root-escaping dep `path` (incl. `[target.*]`); `[patch]`/`[replace]` overrides + stager `git`/`registry` URLs |
| `pyproject.toml` | Python scope manifest | `pip install` / build | build-backend / hook tables; setuptools `data_files` to a system/home destination |
| `pom.xml` | Maven scope (declarative XML) | `mvn` | dangerous plugins (exec/antrun/groovy/invoker/frontend/enforcer, by `gid:aid` or artifactId-alone) + inline `<script>`; DOCTYPE/ENTITY refused (entity-expansion guard) |
| `nx.json`, `turbo.json` | Monorepo project graph | `nx`/`turbo` CLI | `targetDefaults` executor/command + `tasksRunnerOptions` (nx); `pipeline`/`tasks` entries (turbo) |
| `slither.config.json` | Slither analysis scope (`.json`, not glob-matched — do NOT add a `*.config.json` glob, it would quarantine this) | `slither` | `compile_force_framework`, repo-local `solc` |
| `.gitmodules` | Submodule assembly reads it after sanitize (plain `fetch`, manual flow, in-isolation fallback) | `git submodule update` | `ext::`/`file:`/`git://`/`ftp(s)://` urls + localhost/loopback hosts, traversal/control-char paths |
| `package.json` scripts | npm metadata/scope | `npm install` (`postinstall`, …) | loud `scripts` danger patterns (fetch-pipe-to-shell, decode-run, inline-eval, named-secret exfil, home/`/etc` writes) + stager URLs (defanged) |
| `go.mod` / `go.work` | Go module/workspace scope | `go build`/`go mod` | `replace` directives (summary) + loud per-entry on a repo-root-escaping `=>` path |
| `composer.json` scripts | PHP/Composer scope | `composer install`/`update` | loud `scripts` danger patterns (shared corpus + `php -r`) + stager URLs; PHP-callable scripts not matched (FN) |
| requirements / constraints (`requirements*.txt`, `constraints*.txt`, `requirements/*.txt`) | Python pip scope | `pip install -r` | index/find-links redirects, VCS/`git+` installs, direct-archive URLs, editable VCS/URL or escaping-path, `-r`/`-c` includes |
| `Makefile`/`justfile`/`Taskfile.yml` | build recipes | when you run them | — (high-FP recipe scan deferred) |
| `.git/` | verify commit hash (`git rev-parse HEAD`) | — (fresh clone fetches no remote hooks) | — |

**EVM/Solana asymmetry (why it's not an inconsistency):** executable configs are
quarantined — `hardhat.config.ts`/`build.gradle` are evaluated as code, so they're
moved (the readable `.quarantined.txt` copy preserves their scope value). The
declarative chain-native scope manifests — `foundry.toml`, `Anchor.toml`,
`Cargo.toml` — are pure data a tool only reads on an explicit build, so they stay
live.

## Quarantine-evasion defenses (the repo fighting the sanitizer)

| Scenario | What the script does |
|---|---|
| Repo ships its own root `.quarantine/` (possibly a forged manifest) | First run: stashed as `REPO-SUPPLIED-quarantine/`, fully quarantined, **WARNING** logged |
| A **nested** `.quarantine/` hiding a `CLAUDE.md` | Descended into and quarantined like any directory — only the *root* `.quarantine/` (our output) is skipped |
| A live trigger dropped **into** `.quarantine/` after a run | Swept + suffixed; `--check` flags it so a mutated tree can't be pushed |
| Forged "already sanitized" state | Trust is keyed on the **git-dir sentinel** (a checkout can't write under `.git/`), not the worktree manifest |
| Name collision (`x` and `x.quarantined.txt` both present) | Disambiguated (`.1`, `.2`, …) — quarantine never overwrites / destroys evidence |
| Hostile filename codepoints (control/bidi/zero-width) | **Fail-closed** (exit 2 / `--check` exit 1) — see Filename structural defenses |

## Symlink exfiltration (structural — fail-closed)

A committed symlink such as `lib/dep -> ~/.ssh/id_ed25519` would, when followed by
`scp -r`, exfiltrate host credential **contents**. The defense is the
**`core.symlinks=false` clone** (symlinks materialize as inert text files); the
script **enforces** it — any real symlink → **refuse to run, exit 2** — and never
traverses or moves through a symlink.

## Limits — what this script cannot catch

Filename-based sanitization is necessary but not sufficient. It does **not** catch:

- **Source-embedded prompt injection** — instructions hidden in a docstring,
  comment, README, or obfuscated block in files you must read.
- **Renderer / parser / extension zero-days** — a malicious `.svg`, `.ipynb`
  output, Markdown/Mermaid preview, or extension webview bug.
- **Trojan Source in file CONTENT** — bidirectional/invisible Unicode *inside*
  source. NOTE: the Phase-2 fail-closed scan now catches these codepoints in
  **filenames**, so this is *partially* mitigated; in-content Trojan Source still
  survives (the isolation boundary is the defense).
- **Pre-compiled Python bytecode** — a `.pyc` in `__pycache__/` whose bytecode
  doesn't match the visible `.py`. Requires disassembly, not filename matching.
- **CI/CD workflow files** (`.github/workflows/*.yml`, `.circleci/config.yml`,
  `Jenkinsfile`) — they run on the CI platform after a push, not on local open, so
  they are left in place for scope reading (some agentic PR-event workflows are an
  exception, but they fire on the forge, not your host).

These are why the work should run inside a **disposable isolation environment with
no host credentials**: the residual costs an environment delete, not your `gh`
token / SSH agent / funds. The sanitizer shrinks the attack surface; the isolation
boundary bounds the blast radius.

A sibling pre-check, the **IoC gate** (`ioc_scan.py` + `ioc-list.txt`), runs
*before* this sanitizer in `coldclone.sh prep` (greps lockfiles for known-
malicious dependency names; HALTs on a hit). A complementary content scanner,
[GuardDog](https://github.com/DataDog/guarddog), adds behavioral detection over
JS/Python tooling. Both are different layers from this script and complementary.
