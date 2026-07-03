#!/usr/bin/env python3
"""sanitize_repo.py — neutralize auto-execution / prompt-injection files in a
freshly cloned untrusted repo BEFORE it is opened by any tool.

Quarantines (moves + renames, never deletes) every file or directory that an
editor, agent, or toolchain might act on automatically when the repo is
opened. Renaming is the neutralizer: VS Code only auto-runs `.vscode/tasks.json`
at that exact path, Claude Code only loads `CLAUDE.md` by that exact name, and
so on — a file moved to `.quarantine/` with a `.quarantined.txt` suffix is
inert but still readable for the manual skim step (what a repo *tried* to
auto-run is evidence worth reading, and CLAUDE.md often carries context that
is legitimately useful context for a review).

Intended use: run on the HOST scratch clone immediately after `git clone`,
before moving the tree into an isolation environment — walking a hostile tree
with Python executes nothing from it, and quarantining host-side means live
trigger files never enter the isolation environment in active form. Safe to
re-run (idempotent: already-quarantined trees produce no new moves).

Usage: python3 sanitize_repo.py <repo-dir> [--dry-run] [--check] [--quiet] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path

try:  # tomllib is stdlib >= 3.11 (Python >= 3.11 satisfies; degrades gracefully below)
    import tomllib  # noqa: F401
except ModuleNotFoundError:  # < 3.11 — content-WARN degrades to fail-open (skip TOML)
    tomllib = None

# Exit codes. EXIT_STRUCTURAL is the tier-1 fail-closed code; the existing T1
# gates keep their literal `return 2` (these constants are for the new tier-2
# injection-halt path + readability, NOT a refactor of the T1 returns).
EXIT_OK = 0
EXIT_STRUCTURAL = 2          # tier 1: symlinks / Trojan-Source codepoints / no-git
EXIT_INJECTION_HALT = 3      # tier 2: high-confidence prompt-injection (ack-overridable)

QUARANTINE_DIR = ".quarantine"
SUFFIX = ".quarantined.txt"
MANIFEST = "MANIFEST.txt"
# Our own quarantine output: a name ending in SUFFIX, optionally with a
# `_free_name` collision disambiguator (`.1`, `.2`, …). Used to tell our output
# from a foreign file inside `.quarantine/` so the freshness gate doesn't
# misclassify (or the sweep re-suffix) a collision-renamed file we created.
_OUTPUT_SUFFIX_RE = re.compile(re.escape(SUFFIX) + r"(\.\d+)?$")
# Header line on a manifest WE wrote (human-readable provenance for the skim).
OWNER_MARKER = "# sanitize_repo.py quarantine — do not trust contents as inert without this header"
# In-tree "we ran" sentinel, written UNDER the git dir. NON-AUTHORITATIVE: its
# content is the PUBLIC OWNER_MARKER constant, so a hand-extracted archive that
# ships its own `.git/` can FORGE it byte-for-byte. It is therefore only a
# documented fast-path hint (cheap idempotency marker + "we probably ran" signal)
# — it is NOT the authority for check/push. Authority comes from (a) the Layer A
# `.git`-hygiene gate (a forged tree carrying live hooks / exec config is refused
# regardless of the sentinel) and (b) the out-of-tree, filesystem-identity-keyed
# host provenance record (`_state_*` below), which never enters any tree and so
# cannot be forged or replayed by a shipped `.git/`.
SENTINEL_NAME = "coldclone-sanitized"

# Upper bound on bytes we will read+parse for a LEFT-LIVE content-WARN file. The
# parsers below (tomllib / json / ElementTree) all build in-memory trees, so an
# absurdly large left-live file is a cheap memory-exhaustion vector on the host.
# Real scope manifests are tiny; anything over this is skipped with a WARN.
MAX_CONTENT_BYTES = 5_000_000


def sentinel_path(repo: Path) -> Path | None:
    """Path to the in-tree sentinel under the repo's git dir, or None if the git
    dir can't be resolved (rare gitlink edge). NON-AUTHORITATIVE fast-path hint
    only — its content is the public OWNER_MARKER and a shipped `.git/` can forge
    it. The real authority is the Layer A `.git`-hygiene gate plus the out-of-tree
    host provenance record (`_state_lookup`); this path is consumed for cheap
    idempotency, NOT to bless a tree."""
    g = repo / ".git"
    if g.is_dir():
        return g / SENTINEL_NAME
    if g.is_file():  # gitlink worktree/submodule: `gitdir: <path>`
        try:
            for line in g.read_text().splitlines():
                if line.startswith("gitdir:"):
                    gd = (repo / line.split(":", 1)[1].strip()).resolve()
                    return (gd / SENTINEL_NAME) if gd.is_dir() else None
        except OSError:
            return None
    return None


# ============================================================================
# Layer A — required `.git`-hygiene gate (run on git-mode sanitize AND --check)
# ============================================================================
# A forged/hand-assembled `.git/` (or a host `init.templateDir` injecting hooks)
# can carry a live auto-execution surface — non-sample hooks, command-executing
# config directives — that fires on the FIRST `git checkout`/`status`/`diff`
# after the tree reaches the sandbox. The ordinary worktree scans PRUNE the root
# `.git/` (git internals are trusted), so this is a SEPARATE, targeted inspection
# of the effective git-dir set. UNLIKE the content-WARN scan (which fails OPEN on
# a crash), a parse failure HERE FAILS CLOSED (refuse): a security gate that
# silently skipped on error would reopen the hole.


class GitHygieneError(Exception):
    """Raised by the Layer A gate. `.args[0]` is the human-readable reason."""


def _git_config_directives(text: str):
    """Parse git-config TEXT into a list of (section, subsection, name, value)
    tuples. A git-config-aware reader (NOT configparser): handles
    `[section "subsection"]` headers (e.g. `[filter "lfs"]`), lower-cases the
    section and variable names (git is case-insensitive for those; subsection is
    case-SENSITIVE), tolerates duplicate keys, and supports the bare-section
    `[section.subsection]` dotted form. Raises ValueError on a malformed line so
    the caller can FAIL CLOSED.

    Only the structural subset coldclone needs is parsed — enough to surface the
    refused directives below. Values are normalized via `_unquote_value` so the
    URL-form check sees what git sees (a quoted `"ext::…"` cannot hide). NOTE:
    git's backslash-newline VALUE line-continuation is NOT joined here (each
    physical line is parsed alone). This cannot create a fail-OPEN: dangerous KEY
    names are matched before the `=`, and a continuation splitting the only
    value-sensitive token (`ext::`) orphans a `::`-bearing physical line whose name
    fails the variable-name fullmatch → ValueError → FAIL CLOSED."""
    out: list[tuple[str, str | None, str, str]] = []
    section: str | None = None
    subsection: str | None = None
    _hdr_sub = re.compile(r'^\[\s*([A-Za-z0-9.-]+)\s+"((?:[^"\\]|\\.)*)"\s*\]$')
    _hdr_plain = re.compile(r'^\[\s*([A-Za-z0-9.-]+)\s*\]$')
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("["):
            m = _hdr_sub.match(line)
            if m:
                section = m.group(1).lower()
                subsection = m.group(2)  # case-sensitive, unescape backslashes
                subsection = re.sub(r"\\(.)", r"\1", subsection)
                continue
            m = _hdr_plain.match(line)
            if m:
                head = m.group(1)
                if "." in head:  # dotted bare-section form: [section.subsection]
                    section, _, subsection = head.partition(".")
                    section = section.lower()
                else:
                    section = head.lower()
                    subsection = None
                continue
            raise ValueError(f"malformed section header: {line!r}")
        # variable line: `name = value`, or bare `name` (boolean true)
        if section is None:
            raise ValueError(f"variable outside any section: {line!r}")
        if "=" in line:
            name, _, value = line.partition("=")
            name = name.strip().lower()
            value = _unquote_value(value.strip())
        else:
            # bare `name` (boolean true) — but an unquoted inline comment may follow.
            name = _unquote_value(line).strip().lower()
            value = ""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name):
            raise ValueError(f"malformed variable name: {name!r}")
        out.append((section, subsection, name, value))
    return out


def _unquote_value(raw: str) -> str:
    """Normalize a git-config value to its LOGICAL form so value-sensitive checks
    (the remote-helper URL regex) see what git sees: process `"…"` quoted spans,
    backslash escapes (`\\"` `\\\\` `\\n` `\\t` `\\b`), and stop at an UNQUOTED
    `#`/`;` inline comment. An unterminated quote raises ValueError → the caller
    FAILS CLOSED (a quoted `url = "ext::sh -c evil"` must not slip past as a raw
    leading-quote value the `^…::` anchor misses)."""
    out: list[str] = []
    i, n, inq = 0, len(raw), False
    esc = {"n": "\n", "t": "\t", "b": "\b", '"': '"', "\\": "\\"}
    while i < n:
        c = raw[i]
        if c == "\\" and i + 1 < n:
            out.append(esc.get(raw[i + 1], raw[i + 1]))
            i += 2
            continue
        if c == '"':
            inq = not inq
            i += 1
            continue
        if not inq and c in "#;":
            break  # inline comment
        out.append(c)
        i += 1
    if inq:
        raise ValueError("unterminated quote in value")
    return "".join(out).strip()


# Remote-helper transport form: `<transport>::<address>` (e.g. `ext::sh -c …`,
# `fd::…`). A leading scheme component followed by `::`. NOT a scheme-less
# scp-like SSH `git@host:path` (single colon) and NOT a standard `scheme://…`
# (the `://` means the char after the first `:` is `/`, not another `:`).
_REMOTE_HELPER_URL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.-]*::")


def _config_exec_reason(directives) -> str | None:
    """Return a refusal reason for the FIRST command-executing directive in
    `directives` (the parsed (section, subsection, name, value) tuples), or None.
    Covers class (i) open/read-time exec keys, class (ii) transport/credential
    keys (best-effort defense-in-depth), and ANY include/includeIf."""
    for section, sub, name, value in directives:
        # include / includeIf — git inlines the included file's directives, so an
        # attacker could smuggle a class-(i) key past a top-level scan. Refuse any.
        if section in ("include", "includeif"):
            return f"include directive [{section}] — config may pull in exec keys"
        # class (i): open/read-time exec.
        if section == "core" and name in ("hookspath", "fsmonitor"):
            return f"core.{name} set — runs a command on checkout/status"
        if section == "filter" and name in ("process", "clean", "smudge"):
            return (f"filter.{sub}.{name} set — runs a command on "
                    "checkout/diff of matching paths")
        # class (ii): transport/credential (best-effort, fires on later network ops).
        if section == "core" and name in ("sshcommand", "gitproxy", "askpass"):
            return f"core.{name} set — runs a command on a git network operation"
        if section == "credential" and name == "helper":
            return "credential.helper set — runs a command for credentials"
        if section == "remote" and name == "vcs":
            return f"remote.{sub}.vcs set — selects an external remote helper"
        if section == "url" and name in ("insteadof", "pushinsteadof"):
            return f"url.{sub}.{name} set — URL-rewrite smuggling"
        if section == "remote" and name in ("url", "pushurl"):
            if _REMOTE_HELPER_URL_RE.match(value):
                return (f"remote.{sub}.{name} uses the `transport::` remote-helper "
                        "form — arbitrary command exec")
    return None


def _walk_or_refuse(top: Path, what: str):
    """os.walk(top) that FAILS CLOSED: an unreadable directory (the default
    os.walk `onerror=None` SILENTLY skips it, a fail-OPEN in a gate whose whole
    contract is fail-closed) raises GitHygieneError. Does not follow symlinks."""
    def _onerr(e: OSError):
        raise GitHygieneError(f"unreadable {what}: {e}")
    return os.walk(top, onerror=_onerr)


def _looks_like_gitdir(dirnames: list[str], filenames: list[str]) -> bool:
    """A directory under `<gitdir>/modules/**` that is itself a submodule gitdir to
    scan. Identified by a gitdir FILE marker — `HEAD`, `config`, or `packed-refs`.
    FILE markers (not dirnames) are used deliberately: a directory NAMED
    `refs`/`hooks`/`objects` is ambiguous (it may be a submodule with that name, or
    the `modules/` container, or an intermediate path component of a slashed
    submodule name) and a dirname marker would misidentify the container/
    intermediate and prune away the real nested gitdir. Every FUNCTIONAL gitdir has
    a `HEAD` file (git cannot check out — and thus cannot fire a hook — without
    one), so file-marker identification covers every EXPLOITABLE submodule hook
    surface while the `modules/` container, intermediates, and `refs/`/`logs/`
    branch dirs (which have no `HEAD`/`config`/`packed-refs` FILE) never match. An
    identified gitdir is PRUNED from the walk, so its own `refs/heads/hooks` branch
    dir is never reached. (A hook-only directory carrying NONE of these files is
    not a usable gitdir — git will not run its hooks — so it is not an auto-exec
    surface.)"""
    return (
        "HEAD" in filenames or "config" in filenames or "packed-refs" in filenames
    )


def _scan_gitdir_surface(gd: Path) -> None:
    """Scan ONE gitdir's own auto-exec surface (NOT recursing into submodules):
    its `hooks/` dir (non-sample hooks) and its `config`/`config.worktree`
    (command-exec directives, FAIL CLOSED on a parse error). Keyed on the gitdir's
    OWN direct children only — so a branch named `hooks/…` (`<gd>/refs/heads/hooks`)
    or `config` (`<gd>/refs/heads/config`) is never mistaken for the gitdir's hooks
    dir / config file."""
    hooks = gd / "hooks"
    if hooks.is_dir() and not hooks.is_symlink():
        try:
            entries = list(hooks.iterdir())
        except OSError as e:
            raise GitHygieneError(f"could not read hooks dir {hooks}: {e}")
        for h in entries:
            if h.is_symlink():
                raise GitHygieneError(f"symlink in hooks dir: {h}")
            if h.is_file() and not h.name.endswith(".sample"):
                raise GitHygieneError(f"live (non-sample) git hook present: {h}")
    for cfg_name in ("config", "config.worktree"):
        cfg = gd / cfg_name
        if not cfg.is_file() or cfg.is_symlink():
            continue
        try:
            text = cfg.read_text(errors="replace")
        except OSError as e:
            raise GitHygieneError(f"could not read git config {cfg}: {e}")
        try:
            directives = _git_config_directives(text)
        except ValueError as e:
            # FAIL CLOSED — opposite of the content-WARN crash-fails-open rule.
            raise GitHygieneError(f"unparseable git config {cfg}: {e}")
        reason = _config_exec_reason(directives)
        if reason is not None:
            raise GitHygieneError(f"{cfg_name} {reason} (in {cfg})")


def _check_git_hygiene(gitdir: Path) -> None:
    """Layer A: REFUSE (raise GitHygieneError) a git dir carrying a live
    auto-execution surface. Two passes, both FAIL CLOSED on an unreadable subdir:
      1. SYMLINK pass — any real symlink ANYWHERE under the git dir (a forged
         `.git/` has no honest symlink, and `scp -r` follows it).
      2. SURFACE pass — scan each gitdir's OWN `hooks/` + `config`/`config.worktree`
         for the ROOT gitdir and every submodule gitdir found by recursively
         walking `<gitdir>/modules/**` (identified by gitdir markers, then pruned
         so a branch named `hooks/…`/`config` under refs/logs is never reached).
    NOT keyed on a `config` marker (a hook-only forged module gitdir still ships a
    live hook); a submodule NAMED `refs`/`logs` is still scanned (it carries
    markers); refs/logs branch dirs never false-positive (only a gitdir's OWN
    direct `hooks`/`config` children are inspected)."""
    if gitdir.is_symlink():
        raise GitHygieneError(f"symlink at git dir {gitdir}")

    # Pass 1: symlinks anywhere under the whole gitdir tree (incl. refs/objects).
    for dirpath, dirnames, filenames in _walk_or_refuse(gitdir, f"path under git dir {gitdir}"):
        dp = Path(dirpath)
        for nm in list(dirnames) + filenames:
            if (dp / nm).is_symlink():
                raise GitHygieneError(f"symlink under git dir: {(dp / nm)}")

    # Pass 2: each gitdir's own hooks/config — root + nested submodule gitdirs.
    _scan_gitdir_surface(gitdir)
    stack = [gitdir]
    while stack:
        modroot = stack.pop() / "modules"
        if not modroot.is_dir() or modroot.is_symlink():
            continue
        for dirpath, dirnames, filenames in _walk_or_refuse(modroot, f"submodule gitdir under {modroot}"):
            if _looks_like_gitdir(dirnames, filenames):
                gd = Path(dirpath)
                _scan_gitdir_surface(gd)
                stack.append(gd)        # recurse into THIS gitdir's own modules/
                dirnames[:] = []        # prune: do not descend into its refs/logs/objects/hooks


def _resolve_gitdir(repo: Path) -> Path | None:
    """The resolved git directory for a git-mode tree whose root `.git` is a
    DIRECTORY (Layer C requires a directory root). Returns None if `.git` is not
    a directory (a gitlink-FILE root is refused by Layer C before this is used)."""
    g = repo / ".git"
    if g.is_dir() and not g.is_symlink():
        return g
    return None


def _check_nested_git_completeness(repo: Path, gitdir: Path) -> None:
    """Layer A nested-`.git` completeness: walk the WORKTREE (git mode) and REFUSE
    any nested `.git` DIRECTORY below the root (old-form embedded submodule or a
    forged payload — a modern `coldclone fetch` absorbs submodule gitdirs into
    `<gitdir>/modules/**` and leaves a gitlink FILE). For a nested `.git` FILE
    (gitlink), require it resolve INTO the scanned `<gitdir>/modules/**` set, else
    REFUSE. Closes `sub/.git/hooks/evil`, which the ordinary worktree scan prunes
    and the modules-set walk would miss."""
    modroot = (gitdir / "modules").resolve()
    for dirpath, dirnames, filenames in _walk_or_refuse(repo, f"worktree path under {repo}"):
        dp = Path(dirpath)
        # skip the root `.git` (the gitdir itself) and our own quarantine
        if dp == repo:
            dirnames[:] = [d for d in dirnames if d not in (".git", QUARANTINE_DIR)]
        # nested `.git` DIRECTORY below root
        if ".git" in dirnames and dp != repo:
            raise GitHygieneError(
                f"nested .git directory at {(dp / '.git').relative_to(repo)} "
                "(embedded git dir / forged payload)")
        # nested `.git` FILE (gitlink) below root
        if ".git" in filenames and dp != repo:
            gl = dp / ".git"
            if gl.is_symlink():
                raise GitHygieneError(f"symlinked .git gitlink at {gl.relative_to(repo)}")
            try:
                gtxt = gl.read_text(errors="replace")
            except OSError as e:
                raise GitHygieneError(f"could not read gitlink {gl.relative_to(repo)}: {e}")
            target = None
            for line in gtxt.splitlines():
                if line.startswith("gitdir:"):
                    target = (dp / line.split(":", 1)[1].strip()).resolve()
                    break
            if target is None:
                raise GitHygieneError(
                    f"gitlink {gl.relative_to(repo)} has no gitdir: target")
            try:
                target_str = str(target)
                under = (target == modroot or target_str.startswith(str(modroot) + os.sep))
            except Exception:
                under = False
            if not under:
                raise GitHygieneError(
                    f"gitlink {gl.relative_to(repo)} resolves OUTSIDE "
                    f"{modroot} (not an absorbed submodule)")


def run_git_hygiene(repo: Path) -> str | None:
    """Run the full Layer A gate for a git-mode tree (root `.git` is a DIRECTORY).
    Returns a refusal REASON string if the tree is unhygienic, else None. Never
    raises out (any unexpected error is treated as a refusal — fail closed)."""
    gitdir = _resolve_gitdir(repo)
    if gitdir is None:
        return None  # not a directory root — Layer C handles eligibility
    try:
        _check_git_hygiene(gitdir)
        _check_nested_git_completeness(repo, gitdir)
    except GitHygieneError as e:
        return str(e)
    except Exception as e:  # fail closed on any unexpected error
        return f"git-hygiene scan error ({type(e).__name__}: {e})"
    return None


# Mode-aware Layer A refusal message (names BOTH plausible causes).
_GIT_HYGIENE_REMEDIATION = (
    "If you extracted an archive, run `coldclone sanitize-folder <dir>` "
    "(quarantines the whole .git/) or re-fetch. If this is a coldclone-fetched "
    "tree, a host init.templateDir is injecting live hooks — clear it and "
    "re-fetch (coldclone fetch uses an empty template)."
)


# ============================================================================
# Layer B — out-of-tree host provenance record keyed by filesystem identity
# ============================================================================
# The in-tree sentinel leaks into the sandbox via `push` and is replayable, so it
# cannot be the authority. The authority is a host-private record, keyed by the
# worktree-root inode `(st_dev, st_ino)`, that NEVER enters any tree.


class StateError(Exception):
    """Raised on a state-dir anomaly (fails CLOSED, exit 2 structural)."""


def _state_dir() -> Path:
    """The host state dir (NOT yet validated): honor COLDCLONE_STATE, else
    XDG_STATE_HOME/coldclone, else $HOME/.local/state/coldclone."""
    env = os.environ.get("COLDCLONE_STATE")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path(os.path.expanduser("~")) / ".local" / "state"
    return base / "coldclone"


def _effective_scratch() -> Path:
    """Mirror the shell default at coldclone.sh:107 so a state path under the
    DEFAULT scratch (with COLDCLONE_SCRATCH unset) cannot evade containment."""
    env = os.environ.get("COLDCLONE_SCRATCH")
    if env:
        return Path(env)
    return Path(os.path.expanduser("~")) / "coldclone-scratch"


def _unsafe_writable(st) -> bool:
    """True for a component that is group/world-writable WITHOUT the sticky bit
    (a writable, non-sticky dir lets another user swap it)."""
    import stat as _stat
    mode = st.st_mode
    if mode & (_stat.S_IWGRP | _stat.S_IWOTH):
        if not (mode & _stat.S_ISVTX):  # sticky bit set ⇒ safe (e.g. /tmp)
            return True
    return False


def _validate_state_dir(repo: Path) -> Path:
    """Pinned validate algorithm. lstat EVERY component of the state path from the
    root down and fail CLOSED (StateError) on any that is a SYMLINK (unless a
    trusted root-owned system symlink like macOS `/var`) or unsafe-writable; then
    containment-refuse if the path is at/under repo-real OR the effective scratch
    — ALL BEFORE creating anything (validate-before-write: never follow a hostile
    user-owned symlinked parent during creation). Only THEN create the final dir
    0700 and re-validate it (directory, mode 0700, st_uid == getuid()) and the
    resolved containment. Returns the validated state dir Path."""
    import stat as _stat
    state = _state_dir()

    # lstat EVERY EXISTING component from the root down, on the ORIGINAL (lexical)
    # path, BEFORE any mkdir — so a hostile user-owned symlinked parent is rejected
    # and never traversed/created-through. A not-yet-existing component cannot be a
    # pre-existing symlink, so stopping at the first missing one is safe.
    abs_state = Path(os.path.abspath(state))
    accum = Path(abs_state.anchor or "/")
    comps = abs_state.parts[1:] if abs_state.anchor else abs_state.parts
    chain = [accum]
    for c in comps:
        accum = accum / c
        chain.append(accum)
    for comp in chain:
        try:
            st = os.lstat(comp)
        except OSError:
            continue  # not yet existing — created fresh below, can't be a symlink
        if _stat.S_ISLNK(st.st_mode):
            # A symlinked component is an anomaly UNLESS it is a trusted ROOT-owned
            # system symlink (e.g. macOS `/var`->`/private/var`, `/tmp`, `/etc`):
            # an attacker cannot create a root-owned symlink in a place they don't
            # already control. A user-owned (or non-root) symlinked component is a
            # swap/redirect vector → fail CLOSED.
            if st.st_uid != 0:
                raise StateError(f"state path component is a symlink: {comp}")
            continue
        if _stat.S_ISDIR(st.st_mode) and _unsafe_writable(st):
            raise StateError(f"state path component is unsafe-writable: {comp}")

    # Containment on the LEXICAL path BEFORE creating — refuse a state dir at/under
    # repo-real or the effective scratch without first materializing it there.
    repo_resolved = repo.resolve(strict=False)
    scratch = _effective_scratch()
    scratch_resolved = scratch.resolve(strict=False)

    def _at_or_under(child: Path, parent: Path) -> bool:
        cs, ps = str(child), str(parent)
        return cs == ps or cs.startswith(ps + os.sep)

    def _refuse_if_contained(sform: Path) -> None:
        for forbidden in (repo, repo_resolved, scratch, scratch_resolved):
            if _at_or_under(sform, forbidden) or _at_or_under(sform, Path(os.path.abspath(forbidden))):
                raise StateError(
                    f"state dir {sform} is contained under {forbidden} — "
                    "relocatable/reachable state is a stale-true vector")

    _refuse_if_contained(abs_state)

    # Validation passed on every EXISTING component — now it is safe to create the
    # dir tree (no hostile symlinked parent will be traversed).
    try:
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as e:
        raise StateError(f"cannot create state dir {state}: {e}")

    # Final dir: directory, mode 0700, user-owned.
    try:
        fst = os.lstat(state)
    except OSError as e:
        raise StateError(f"state dir not present after mkdir {state}: {e}")
    if _stat.S_ISLNK(fst.st_mode) or not _stat.S_ISDIR(fst.st_mode):
        raise StateError(f"state dir is not a real directory: {state}")
    if _stat.S_IMODE(fst.st_mode) != 0o700:
        raise StateError(f"state dir mode is not 0700: {state} "
                         f"(is {oct(_stat.S_IMODE(fst.st_mode))})")
    if fst.st_uid != os.getuid():
        raise StateError(f"state dir not owned by current user: {state}")

    # Re-check containment on the RESOLVED final path (belt-and-suspenders: catches
    # a trusted root-owned symlink in the chain that resolves into repo/scratch —
    # not expected, but the lexical pre-mkdir check alone wouldn't see it).
    _refuse_if_contained(state.resolve(strict=False))
    return state


def _record_path(state: Path, st_dev: int, st_ino: int) -> Path:
    return state / f"rec-{st_dev}-{st_ino}.json"


def _state_mint(repo: Path) -> None:
    """Mint a provenance record for `repo` (its worktree root). Keyed by the root
    inode `(st_dev, st_ino)` ONLY; realpath + timestamp stored as diagnostic.
    Written 0600 via temp-file + atomic os.replace. Fails CLOSED (StateError) on
    a state-dir anomaly."""
    import time as _time
    state = _validate_state_dir(repo)
    try:
        rst = os.stat(repo)
    except OSError as e:
        raise StateError(f"cannot stat repo root {repo}: {e}")
    rec = {
        "st_dev": rst.st_dev,
        "st_ino": rst.st_ino,
        "realpath": str(repo.resolve(strict=False)),  # diagnostic, NOT matched
        "minted_at": _time.time(),                     # diagnostic, NOT matched
    }
    dest = _record_path(state, rst.st_dev, rst.st_ino)
    tmp = dest.with_name(dest.name + f".tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(rec, fh)
        os.replace(tmp, dest)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _state_lookup(repo: Path) -> bool:
    """True iff a provenance record matching `repo`'s worktree-root inode
    `(st_dev, st_ino)` exists in the validated state dir. Fails CLOSED (StateError)
    on a state-dir anomaly — the gate is NEVER silently skipped."""
    state = _validate_state_dir(repo)
    try:
        rst = os.stat(repo)
    except OSError as e:
        raise StateError(f"cannot stat repo root {repo}: {e}")
    dest = _record_path(state, rst.st_dev, rst.st_ino)
    if not dest.is_file():
        return False
    try:
        rec = json.loads(dest.read_text())
    except Exception:
        return False
    return rec.get("st_dev") == rst.st_dev and rec.get("st_ino") == rst.st_ino


# Directory basenames quarantined wherever they appear in the tree.
# NOTE: Matching is case-SENSITIVE on Linux (the default host). A repo could
# evade a dir entry by using a differently-cased name (e.g. `BuildSrc` instead
# of `buildSrc`) on a case-sensitive FS. Known limitation — adding case-folded
# matching would require explicit enumeration of all variants.
DIR_NAMES = {
    ".vscode",        # tasks.json (folderOpen auto-run), workspace settings that
                      # can override your rust-analyzer/task hardening,
                      # launch configs, recommended-extension prompts
    ".devcontainer",  # auto-build/run prompts when opened in a container-aware editor
    ".idea",          # JetBrains run configurations / startup tasks
    ".claude",        # Claude Code project hooks, commands, settings
    ".agents",        # cross-agent skills/instructions dir (e.g. .agents/skills/*/SKILL.md) —
                      # auto-loaded agent context, same prompt-injection class as CLAUDE.md/.claude
    ".cursor",        # Cursor rules / hooks
    ".githooks",      # committed hook trees wired via core.hooksPath
    ".husky",         # husky-managed git hooks
    ".cargo",         # config.toml can alias/override rustc & cargo with
                      # arbitrary executables (runners, build overrides)
    ".yarn",          # Yarn Berry: releases/*.cjs + plugins/*.cjs are the
                      # payloads .yarnrc.yml's `yarnPath` points at — repo-shipped
                      # JS that runs on EVERY `yarn` command, before any lifecycle
                      # script, so `--ignore-scripts` does not stop it
    # AI-agent config/instruction dirs (same prompt-injection class as .claude/.cursor)
    ".gemini",        # Gemini CLI settings (settings.json: MCP servers, contextFileName)
    ".aider",         # Aider cache/config tree
    ".continue",      # Continue.dev: custom slash commands / context providers that can exec
    ".windsurf",      # Windsurf (Codeium) workspace agent dir
    ".codeium",       # Codeium agent dir
    ".junie",         # JetBrains Junie agent guidelines
    ".clinerules",    # Cline rules (dir form; the file form is in FILE_NAMES)
    # JVM build trees evaluated/compiled by the toolchain
    ".mvn",           # Maven wrapper dir: maven-wrapper.jar (trojanizable) +
                      # maven-wrapper.properties (distributionUrl) + jvm.config/maven.config
    "buildSrc",       # Gradle: auto-compiled and placed on the build classpath.
                      # Case-sensitive match only — `BuildSrc`/`buildsrc` bypass
                      # this on a case-sensitive FS. Known limitation.
}

# File basenames quarantined wherever they appear in the tree.
# NOTE: Like DIR_NAMES, matching is case-sensitive on Linux. GLOB_PATTERNS
# below (e.g. *.config.js) also match case-sensitively — a repo using
# `Hardhat.Config.JS` would not be caught. Known limitation.
FILE_NAMES = {
    "copilot-instructions.md",    # agent prompt injection (.github/, incl. nested/submodule copies)
    "CLAUDE.md",                  # prompt-injection surface for Claude Code
    "CLAUDE.local.md",
    "AGENTS.md",                  # same, for Codex/other agents
    "AGENT.md",
    ".mcp.json",                  # auto-configured MCP servers (arbitrary commands)
    ".cursorrules",               # Cursor prompt injection
    ".envrc",                     # direnv auto-execution on cd
    ".env.local",                 # occasionally sourced by tooling; cheap to inert
    "rust-toolchain",             # can pin/override the toolchain rust tools invoke
    "rust-toolchain.toml",
    ".mise.toml",                 # mise/rtx auto env + task execution
    "mise.toml",
    ".tool-versions",             # asdf; mostly harmless but cheap to inert
    "lefthook.yml",               # hook managers (only fire if installed, but cheap)
    "lefthook.yaml",
    ".pre-commit-config.yaml",
    # Package-manager wrapper hijacks — run repo-shipped JS BEFORE lifecycle
    # scripts, so "no npm install" / "--ignore-scripts" does not cover them.
    ".yarnrc.yml",                # `yarnPath:` redirects every `yarn` cmd to repo JS
    ".pnpmfile.cjs",              # pnpm hooks: run on every pnpm install/resolve
    # Executable build-tool configs common in Solidity/EVM repos — plain
    # JS/TS that the toolchain runs on `npx hardhat`/`truffle`/task-listing,
    # i.e. a command you might run to read scope. (`hardhat.config.{js,ts,…}`
    # is caught by the *.config.* glob below; truffle/brownie are named here.)
    "truffle-config.js",          # executable Truffle config
    "brownie-config.yaml",        # Brownie (Python): compiler/console hooks
    "brownie-config.yml",
    # rc-style configs that are executable JS but do NOT match *.config.* below.
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".prettierrc.js",
    ".prettierrc.cjs",
    # --- AI-agent prompt-injection (same class as CLAUDE.md / .cursorrules) ---
    "GEMINI.md",                  # Gemini CLI auto-loads as system-level instructions
    "AGENTS.override.md",         # Codex per-dir override taking precedence over AGENTS.md
    ".windsurfrules",             # Windsurf agent rules (CVE-2025-61590..61593 RCE class)
    ".aider.conf.yml",            # Aider config: --exec hooks, custom endpoints, shell cmds
    ".aiderrc",                   # Aider rc variant
    ".roomodes",                  # Roo Code agent modes (full shell tool access)
    ".roo-instructions.md",       # Roo Code instructions
    ".clinerules",                # Cline rules (file form; dir form is in DIR_NAMES)
    "mcp.json",                   # bare MCP server config (alongside .mcp.json)
    # --- Editor ---
    ".devcontainer.json",         # single-file devcontainer ("Reopen in Container?")
    # --- Shell / env ---
    ".python-version",            # pyenv auto-switch on cd (custom build hooks can exec)
    # --- Git-structural (.gitmodules is deliberately LEFT LIVE — see reminder) ---
    ".gitattributes",             # filter-driver smudge/clean on checkout (CVE-2021-21300,
                                  # CVE-2025-26625). Belt-and-suspenders: the host clone already
                                  # neutralized LFS filters; no workflow step reads it post-checkout.
    # --- Package-manager hijack ---
    ".npmrc",                     # script-shell=/path bypasses ignore-scripts (Koi Security 2026)
    # --- Gradle/Maven EXECUTABLE configs/scripts (quarantine; readable copy preserves scope,
    #     same doctrine as the *.config.* glob already applies to hardhat.config.ts) ---
    "gradlew",                    # Gradle wrapper shell script
    "gradlew.bat",
    "mvnw",                       # Maven wrapper script
    "mvnw.cmd",
    "gradle-wrapper.jar",         # opaque committed bytecode run by ./gradlew before real Gradle
    "gradle-wrapper.properties",  # distributionUrl supply-chain vector (GHSA-pfq2-hh62-7m96)
    "build.gradle",               # Groovy DSL executed on EVERY gradle invocation incl. task-list
    "build.gradle.kts",           # Kotlin DSL, same
    "settings.gradle",            # evaluated BEFORE build.gradle on every invocation
    "settings.gradle.kts",
    # --- Python EXECUTABLE (auto-import / build scripts) ---
    "conftest.py",                # pytest auto-IMPORTS on `pytest --collect-only` (no tests run)
    "setup.py",                   # executable Python build script (pip install -e .)
    "sitecustomize.py",           # auto-imported at interpreter startup when cwd/repo on sys.path
    "usercustomize.py",
    "noxfile.py",                 # nox task config (executable Python)
    "ape-config.yaml",            # ApeWorx config — sibling of the already-quarantined brownie-config
    "ape-config.yml",
    # --- Rust auto-fire-on-open: rust-analyzer compiles+executes build.rs the moment a
    #     trusted Rust project opens. Cargo.toml stays LEFT LIVE. ---
    "build.rs",
    # --- Container / Compose (CVE-2025-62725 fires on `docker compose config`) ---
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    # --- Nix (mostly inert here — the .envrc `use flake` auto-path is already covered;
    #     kept as cheap defense-in-depth since nix evaluation runs arbitrary code) ---
    "flake.nix",
    "shell.nix",
    "default.nix",
    # --- Pixi / Deno / Bun runtime task configs ---
    "pixi.toml",
    "deno.json",                  # `tasks` (arbitrary shell), import maps; auto-discovered upward
    "deno.jsonc",
    "bunfig.toml",                # Bun [install]/[run]; also auto-loads .env
    # --- Solidity EXECUTABLE configs (do NOT match *.config.*) ---
    ".solhintrc.js",              # solhint executable config
    ".solhintrc.cjs",
    ".solcover.js",               # solidity-coverage executable config
    ".solcover.cjs",
    ".solcover.mjs",
}

# Glob patterns matched against basenames anywhere in the tree.
# NOTE: Path.match() on Linux is case-sensitive, so *.Config.js etc. won't
# match. A repo adversarially capitalizing e.g. `Hardhat.Config.JS` bypasses
# this on a case-sensitive FS. Known limitation.
GLOB_PATTERNS = (
    "*.code-workspace",  # carries workspace settings + tasks like .vscode/
    # `<tool>.config.{js,cjs,mjs,ts}` — executable JS/TS config evaluated by the
    # tool/extension when it runs (hardhat, vite, webpack, next, babel, eslint,
    # prettier, tailwind, rollup, jest, vitest, …). Latent in Restricted Mode /
    # read-only review, but cheap insurance and quarantine keeps a readable copy
    # for scope (e.g. hardhat remappings/solc/network config).
    "*.config.js",
    "*.config.cjs",
    "*.config.mjs",
    "*.config.ts",
    "*.config.cts",   # TypeScript CommonJS config variant
    "*.config.mts",   # TypeScript ESM config variant
)


def find_symlinks(repo: Path, folder_mode: bool = False) -> list[Path]:
    """Every real symlink in the worktree. os.walk does not follow symlinked
    dirs (followlinks=False), so this can't escape the tree. An unreadable
    directory is reported (onerror) rather than silently skipped — a dir we
    cannot descend could hide a symlink.

    Git mode (default) prunes a ROOT `.git/` (git internals are trusted). Folder
    mode descends every `.git/` at full depth — a repo-shipped `.git/` is
    untrusted, so a symlink hidden anywhere inside it (incl. `.git/objects/`)
    must trip the fail-closed before quarantine() moves it."""
    out: list[Path] = []

    def _onerror(e: OSError) -> None:
        print(f"warning: could not read during symlink scan: {e}", file=sys.stderr)

    for dirpath, dirnames, filenames in os.walk(repo, onerror=_onerror):
        dp = Path(dirpath)
        if dp == repo and not folder_mode:
            dirnames[:] = [d for d in dirnames if d != ".git"]
        for nm in list(dirnames) + filenames:
            p = dp / nm
            if p.is_symlink():
                out.append(p)
    return out


# --- Phase 2: filename structural pre-scan --------------------------------------
# FAIL-CLOSED codepoints have no legitimate use in a filename — pure
# review-evasion (Trojan-Source / invisible / control). A worktree containing one
# makes sanitize (and --check) refuse the tree, same posture as a real symlink.
# NUL (0x00) cannot occur in a POSIX filename (the kernel rejects it at
# creat/rename), so it is covered by the C0 range below with no NUL-specific code.
def _forbidden_codepoint(name: str) -> str | None:
    """Label for the first fail-closed codepoint in `name`, or None."""
    for ch in name:
        o = ord(ch)
        if o <= 0x1F or o == 0x7F or 0x80 <= o <= 0x9F:
            return f"control U+{o:04X}"
        if o in (0x200E, 0x200F, 0x061C):                    # LRM, RLM, ALM marks
            return f"bidi-mark U+{o:04X}"
        if 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069:   # overrides + isolates
            return f"bidi-format U+{o:04X}"
        if (0x200B <= o <= 0x200D or o == 0x2060 or 0x2061 <= o <= 0x2064
                or o == 0xFEFF):                             # zero-width/invisible/BOM
            return f"zero-width U+{o:04X}"
    return None


def _nonascii_codepoints(name: str) -> list[str]:
    """Printable non-ASCII codepoints in `name` NOT in the fail-closed set —
    WARN-only (homoglyph/confusable surface). A blanket flag avoids an
    unmaintainable homoglyph mapping table."""
    out: list[str] = []
    for ch in name:
        if ord(ch) > 0x7F and _forbidden_codepoint(ch) is None:
            out.append(f"U+{ord(ch):04X} {unicodedata.name(ch, '?')}")
    return out


def scan_filenames(repo: Path, folder_mode: bool = False) -> tuple[list[tuple[Path, str]], list[str]]:
    """Single os.walk producing (fatal, warn). `fatal` = (path, label) for any
    entry name with a fail-closed codepoint (caller refuses the tree). `warn` =
    informational lines for printable non-ASCII names and case-collisions.
    Prunes a ROOT `.git/` in git mode (like find_symlinks); in folder mode
    descends every `.git/` at full depth so a Trojan-Source codepoint in a name
    inside a repo-shipped `.git/` trips the fail-closed. Never follows symlinks."""
    fatal: list[tuple[Path, str]] = []
    warn: list[str] = []

    def _onerror(e: OSError) -> None:
        print(f"warning: could not read during filename scan: {e}", file=sys.stderr)

    for dirpath, dirnames, filenames in os.walk(repo, onerror=_onerror):
        dp = Path(dirpath)
        if dp == repo and not folder_mode:
            dirnames[:] = [d for d in dirnames if d != ".git"]
        entries = list(dirnames) + filenames
        for nm in entries:
            lab = _forbidden_codepoint(nm)
            if lab is not None:
                fatal.append((dp / nm, lab))
                continue
            na = _nonascii_codepoints(nm)
            if na:
                warn.append(f"WARN non-ascii filename {(dp / nm).relative_to(repo)}"
                            f" — {', '.join(na)}")
        # Case-collision (best-effort): two entries casefold-equal. On a
        # case-insensitive host volume (the macOS default this runs on) the
        # collision already collapsed at clone time and is undetectable here;
        # this fires on a case-sensitive volume / Linux host.
        seen: dict[str, str] = {}
        for nm in entries:
            key = nm.casefold()
            if key in seen and seen[key] != nm:
                where = dp.relative_to(repo) if dp != repo else Path(".")
                warn.append(f"WARN case-collision in {where}/ — {seen[key]!r} vs "
                            f"{nm!r} (one shadows the other on a case-insensitive FS)")
            else:
                seen.setdefault(key, nm)
    return fatal, warn


# --- Phase 3: content WARN over LEFT-LIVE files (FAIL-OPEN) ----------------------
# These files are NOT quarantined (needed to read scope / workflow), so renaming
# can't neutralize them; the WARN is a skim-time nudge, NOT a security boundary
# (the isolation environment is). Every handler is wrapped so a parse error
# yields a WARN and the scan continues — never an exit code, never gates --check.
#
# Anchor.toml is deliberately left live (like foundry.toml) because it carries
# scope info (cluster, programs, IDL paths) needed for the manual audit. It only
# fires if you run `anchor test`/`anchor run`, which read-only review avoids.
#
# nx.json / turbo.json are left live because they are primarily CI orchestration
# metadata. They only execute shell on `nx run` / `turbo run`, which read-only
# review avoids. Content-WARN flags pipeline/task definitions for manual review.
# package.json / Cargo.toml are LEFT LIVE (like foundry.toml) — needed to read
# the dependency graph / build config for review; they only EXECUTE under
# `npm/yarn/pnpm install` resp. `cargo build`, which read-only review avoids.
# The A2 content-WARN is a skim nudge over their dangerous-content patterns.
#
# A2 DELIBERATELY scopes to package.json / Cargo.toml / pyproject.toml. Other
# left-live executable manifests are CONSCIOUSLY DEFERRED (noted here so the
# omission is intentional, not an oversight — cf. the LEFT_LIVE test invariant
# and the Makefile mention in the manifest text): Makefile (recipe scanning is
# high-FP and already flagged generically in MANIFEST), Gemfile (out of the
# Solidity/Rust/Python/JS/Go core), Pipfile / `.in` pip-tools variants, and
# lockfiles (the IoC scanner's job, not content-WARN). A2.1 covers go.mod/go.work
# `replace`, composer.json `scripts`, and the requirements-file family.
CONTENT_WARN_NAMES = {
    "foundry.toml", "Anchor.toml", "pyproject.toml",
    "slither.config.json", "pom.xml", ".gitmodules",
    "nx.json", "turbo.json",
    "package.json", "Cargo.toml",
    "go.mod", "go.work", "composer.json",
}

# A2 caps (DoS: a 5MB manifest can carry a huge scripts/deps map; bound the
# entries scanned AND the per-value regex input). Mirrors INJ_PER_FILE_CAP.
WARN_PKG_SCRIPT_CAP = 200          # script entries scanned per package.json
WARN_SCRIPT_VALUE_MAX = 4096       # bytes of a string value fed to the regex set
WARN_CARGO_DEP_CAP = 500           # dep + patch + replace entries per Cargo.toml
                                   #   (ONE shared counter spans ALL traversals)
# A2.1 caps for the line-oriented handlers.
WARN_LINE_CAP = 2000               # max logical lines scanned in a line-file
WARN_GO_REPLACE_CAP = 200          # max go.mod/go.work replace entries inspected
WARN_COMPOSER_ELEM_CAP = 50        # max str elements scanned per array composer script


# requirements/constraints files are a SPLIT family (requirements-dev.txt,
# requirements/base.txt, constraints.txt, …) — a PREDICATE, not a name-set
# member, or the modal split layout silently never fires.
_REQUIREMENTS_NAME_RE = re.compile(   # bounded quantifiers (ReDoS invariant)
    r"(?:requirements[\w.-]{0,128}|[\w.-]{1,128}-requirements|constraints[\w.-]{0,128})\.txt")


def _is_requirements_file(dp: Path, nm: str) -> bool:
    if _REQUIREMENTS_NAME_RE.fullmatch(nm):
        return True
    if nm.endswith(".txt") and dp.name == "requirements":   # requirements/*.txt
        return True
    return False
_STD_PY_BACKENDS = {"setuptools.build_meta", "setuptools.build_meta:__legacy__",
                    "flit_core.buildapi", "hatchling.build", "poetry.core.masonry.api",
                    "pdm.backend", "maturin"}

# Known dangerous Maven plugin groupId:artifactId pairs — can execute arbitrary
# code when their bound goals run during the build lifecycle.
_DANGEROUS_MAVEN_PLUGINS = {
    "org.codehaus.mojo:exec-maven-plugin",
    "org.apache.maven.plugins:maven-antrun-plugin",
    "org.codehaus.gmaven:groovy-maven-plugin",
    "org.codehaus.gmaven:gmaven-plugin",
    "org.apache.maven.plugins:maven-invoker-plugin",
    "com.github.eirslett:frontend-maven-plugin",  # downloads + runs Node
    "org.apache.maven.plugins:maven-enforcer-plugin",  # custom rules can run beanshell/groovy
}
# Artifact-id-only set: Maven defaults an omitted <groupId> to
# org.apache.maven.plugins, so a <plugin> declaring only the artifactId (e.g.
# maven-antrun-plugin) is a real, evasive dangerous declaration the exact
# groupId:artifactId match would miss.
_DANGEROUS_MAVEN_ARTIFACTS = {k.split(":", 1)[1] for k in _DANGEROUS_MAVEN_PLUGINS}


def _toml_load(path: Path):
    if tomllib is None:
        raise RuntimeError("tomllib unavailable (Python < 3.11)")
    with path.open("rb") as fh:
        return tomllib.load(fh)


# Absolute compiler/build locations that are NOT repo-local — a `solc` set to
# one of these is a normal system/managed install, not a hijack. Anything
# relative (./, lib/solc) or absolute-but-outside-these (/tmp/evil-solc) is
# suspicious. A bare version string ("0.8.20") has no separator and is never
# flagged.
#
# NOTE: /home and /Users ARE included on purpose. The svm / solc-select compiler
# managers install managed solc under the user home dir (~/.svm/<ver>/solc,
# ~/.solc-select/...), which is the NORMAL Foundry setup — flagging those would
# false-positive on essentially every real repo. The threat this catches is a
# repo pointing solc at a *repo-local* binary it ships (./bin/solc, lib/solc),
# which stays caught because those are relative/non-system; and this is a
# fail-open WARN, not a security boundary (the isolation environment is), so
# home-dir coverage is the right precision trade.
_SYSTEM_PATH_PREFIXES = ("/usr", "/opt", "/bin", "/sbin", "/nix", "/home",
                         "/Users", "/Library", "/var", "/private", "/etc")


def _suspicious_path(s) -> bool:
    """True for a path-like value that is repo-local / non-system (a compiler or
    build path a malicious repo could point at its own binary). A bare version
    string ("0.8.20") is never path-like. POSIX system prefixes are matched on a
    COMPONENT boundary (so `/usrmal/solc` is NOT mistaken for `/usr/...`)."""
    if not isinstance(s, str):
        return False
    path_like = ("/" in s or "\\" in s or s.startswith((".", "~"))
                 or bool(re.match(r"^[A-Za-z]:", s)))  # incl. Windows drive / UNC
    if not path_like:
        return False
    return not any(s == p or s.startswith(p + "/") for p in _SYSTEM_PATH_PREFIXES)


def _warn_foundry(rel: Path, data) -> list[str]:
    out: list[str] = []
    sections: dict[str, dict] = {}
    profiles = data.get("profile")
    if isinstance(profiles, dict):
        sections.update({f"profile.{_defang_if_url(k)}": v
                         for k, v in profiles.items() if isinstance(v, dict)})
    top = {k: v for k, v in data.items() if not isinstance(v, dict)}
    if top:
        sections["<top-level>"] = top
    for sname, sec in sections.items():
        if sec.get("ffi") is True:
            out.append(f"WARN {rel} [{sname}] ffi = true — FFI cheatcode enables "
                       "host binary exec under forge test/script")
        # Check each documented solc key INDEPENDENTLY — a benign `solc = "0.8.20"`
        # (a version, never path-like) must not short-circuit an `or` chain and
        # mask a repo-local `solc_path = "./bin/solc"`. `solc` is the current key
        # (version OR path), `solc_version` the older alias, `solc_path` checked
        # defensively. A bare version is never path-like, so only a path value
        # trips _suspicious_path.
        for k in ("solc", "solc_version", "solc_path"):
            v = sec.get(k)
            if _suspicious_path(v):
                out.append(f"WARN {rel} [{sname}] {k} = {_defang_repr(v)} — "
                           "repo-local compiler path")
        # `fs_permissions` WARN only on permissive (write/read-write) grants.
        # A restrictive value like [{access="read",path="out"}] is a hardening
        # practice — warning on it would be a false positive.
        perms = sec.get("fs_permissions")
        if perms is not None:
            if isinstance(perms, list):
                for perm in perms:
                    if isinstance(perm, dict):
                        acc = str(perm.get("access", "")).lower().replace("-", "")
                        pth = perm.get("path", "")
                        if "write" in acc:
                            out.append(
                                f"WARN {rel} [{sname}] fs_permissions grants write "
                                f"access to {_defang_repr(pth)} — review filesystem exposure")
            else:
                out.append(f"WARN {rel} [{sname}] fs_permissions has unexpected "
                           f"type ({type(perms).__name__}) — review manually")
    return out


def _warn_anchor(rel: Path, data) -> list[str]:
    out: list[str] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict) and scripts:
        out.append(f"WARN {rel} [scripts] defines {len(scripts)} command(s) — run on "
                   "`anchor run`/`anchor test`")
    if data.get("test"):
        out.append(f"WARN {rel} [test] present — runs on `anchor test`")
    tc = data.get("toolchain")
    if isinstance(tc, dict) and tc:
        out.append(f"WARN {rel} [toolchain] pins {_defang_repr(sorted(tc))} — "
                   "review for repo-local binaries")
    prov = data.get("provider")
    if isinstance(prov, dict) and prov.get("cluster"):
        # cluster is frequently an RPC URL (e.g. https://api.devnet.solana.com) —
        # defang so a flagged value can't be auto-linked / fat-finger-clicked.
        out.append(f"WARN {rel} [provider] cluster = {_defang_repr(prov['cluster'])} "
                   "— informational (which cluster anchor commands target)")
    return out


def _warn_pyproject(rel: Path, data) -> list[str]:
    out: list[str] = []
    bs = data.get("build-system")
    if isinstance(bs, dict):
        be = bs.get("build-backend")
        if isinstance(be, str) and be not in _STD_PY_BACKENDS:
            out.append(f"WARN {rel} [build-system] build-backend = {_defang_repr(be)} — "
                       "non-standard backend runs on pip install / build")
        if bs.get("backend-path"):
            out.append(f"WARN {rel} [build-system] backend-path set — in-tree build backend")
    tool = data.get("tool")
    if isinstance(tool, dict):
        hatch = tool.get("hatch")
        if (isinstance(hatch, dict) and isinstance(hatch.get("build"), dict)
                and "hooks" in hatch["build"]):
            out.append(f"WARN {rel} [tool.hatch.build.hooks.*] present — custom build hooks")
        st = tool.get("setuptools")
        if isinstance(st, dict) and ("cmdclass" in st or "ext-modules" in st
                                     or "ext_modules" in st):
            out.append(f"WARN {rel} [tool.setuptools] cmdclass/ext-modules present — "
                       "custom build code")
        pt = tool.get("pytest")
        ini = pt.get("ini_options") if isinstance(pt, dict) else None
        if isinstance(ini, dict):
            if ini.get("addopts"):
                out.append(f"WARN {rel} [tool.pytest.ini_options] addopts = "
                           f"{_defang_repr(ini['addopts'])} — injected into every pytest run")
            if ini.get("plugins"):
                out.append(f"WARN {rel} [tool.pytest.ini_options] plugins = "
                           f"{_defang_repr(ini['plugins'])} — auto-loaded pytest plugins")
        # A2: setuptools `data_files` writing to a system/home destination drops
        # files outside site-packages on `pip install`. APPENDED after the
        # existing checks (line-stability: do not reorder the WARNs above).
        # `st` is assigned above; re-guard for the no-tool/no-setuptools paths.
        if isinstance(st, dict):
            for df_key in ("data_files", "data-files"):
                df = st.get(df_key)
                dests: list = []
                if isinstance(df, dict):
                    dests = list(df.keys())                  # {dest: [files]} table form
                elif isinstance(df, list):
                    for pair in df:                          # [[dest, [files]], …] form
                        if (isinstance(pair, (list, tuple)) and pair
                                and isinstance(pair[0], str)):
                            dests.append(pair[0])
                for dest in dests:
                    if _pyproject_system_dest(dest):
                        out.append(f"WARN {rel} [tool.setuptools] data_files installs "
                                   f"to {_defang_repr(dest)} — writes outside "
                                   "site-packages on pip install; review")
    return out


def _warn_slither(rel: Path, data) -> list[str]:
    out: list[str] = []
    if not isinstance(data, dict):
        return out
    if data.get("compile_force_framework"):
        out.append(f"WARN {rel} compile_force_framework = "
                   f"{_defang_repr(data['compile_force_framework'])}")
    if data.get("compile_custom_build"):
        out.append(f"WARN {rel} compile_custom_build = "
                   f"{_defang_repr(data['compile_custom_build'])} — "
                   "runs an arbitrary build command")
    # Check each key INDEPENDENTLY (same or-masking class as foundry solc /
    # turbo keys) — a benign `solc` version must not mask a repo-local
    # `solc_solcs_bin`.
    for k in ("solc", "solc_solcs_bin"):
        v = data.get(k)
        if _suspicious_path(v):
            out.append(f"WARN {rel} {k} = {_defang_repr(v)} — non-system compiler path")
    return out


def _warn_pom(rel: Path, text: str) -> list[str]:
    """Parse pom.xml with ElementTree and flag known-dangerous Maven plugins
    (exec-maven-plugin, maven-antrun-plugin, groovy-maven-plugin, frontend-maven-plugin,
    etc.) and inline <script> elements. Fail-open: parse errors return a generic WARN.

    DoS guard: stdlib ElementTree EXPANDS internal entities (a `billion laughs`
    payload would exhaust memory/CPU, and that is NOT an ET.ParseError so the
    try/except below would not catch it). We run on untrusted input, so refuse
    to parse any pom that declares a DOCTYPE or ENTITY — a real Maven pom never
    does. (External-entity resolution is already disabled in stdlib ET; this
    closes the internal-entity-expansion hole the stdlib leaves open, without
    pulling in a non-stdlib dependency like defusedxml.) The whole-text scan is
    bounded because scan_content_warn already caps the read at MAX_CONTENT_BYTES."""
    out: list[str] = []
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        out.append(f"WARN {rel} declares a DOCTYPE/ENTITY — not parsed "
                   "(XML entity-expansion risk); review manually before running mvn")
        return out
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        out.append(f"WARN {rel} could not parse XML ({e}); review manually for dangerous plugins")
        return out

    # Strip default namespace prefix so local-name XPath works without URIs.
    _ns_re = re.compile(r"\{[^}]+\}")

    def _tag(elem) -> str:
        return _ns_re.sub("", elem.tag)

    plugins_warned: set[str] = set()
    for plugin in (e for e in root.iter() if _tag(e) == "plugin"):
        children = list(plugin)
        gid = next((e.text or "" for e in children if _tag(e) == "groupId"), "").strip()
        aid = next((e.text or "" for e in children if _tag(e) == "artifactId"), "").strip()
        key = f"{gid}:{aid}"
        # Match the full groupId:artifactId when a groupId is present; fall back
        # to artifactId-alone ONLY when <groupId> is OMITTED (Maven then defaults
        # it to org.apache.maven.plugins), so a no-groupId declaration can't evade
        # — without false-flagging an explicit, different (benign) groupId that
        # merely happens to reuse a dangerous artifactId.
        if (key in _DANGEROUS_MAVEN_PLUGINS
                or (not gid and aid in _DANGEROUS_MAVEN_ARTIFACTS)) \
                and key not in plugins_warned:
            plugins_warned.add(key)
            shown = key if gid else f"(groupId omitted):{aid}"
            out.append(f"WARN {rel} dangerous Maven plugin: {shown} — "
                       "executes code during build lifecycle; review before running mvn")

    # Check for inline <script> elements (groovy-maven-plugin / antrun).
    for script_el in (e for e in root.iter() if _tag(e) == "script"):
        out.append(f"WARN {rel} contains inline <script> element — "
                   "review for embedded build-time code execution")
        break  # one warning per file is enough

    if not out:
        out.append(f"WARN {rel} present (left live) — no known dangerous plugins detected; "
                   "review for custom executions before running mvn")
    return out


def _warn_nx(rel: Path, data) -> list[str]:
    """nx.json: flag executor/command entries in targetDefaults / tasksRunnerOptions
    that could run arbitrary shell on `nx run`."""
    out: list[str] = []
    if not isinstance(data, dict):
        return out
    td = data.get("targetDefaults")
    if isinstance(td, dict) and td:
        risky = [t for t, v in td.items()
                 if isinstance(v, dict) and ("executor" in v or "command" in v)]
        if risky:
            out.append(f"WARN {rel} targetDefaults defines executor/command for "
                       f"{_defang_repr(risky[:5])} — runs on `nx run`")
    if isinstance(data.get("tasksRunnerOptions"), dict):
        out.append(f"WARN {rel} tasksRunnerOptions present — custom task runner may exec code")
    return out


def _warn_turbo(rel: Path, data) -> list[str]:
    """turbo.json: flag pipeline/tasks entries that execute shell via `turbo run`."""
    out: list[str] = []
    if not isinstance(data, dict):
        return out
    # Turbo v1 uses "pipeline", v2 uses "tasks". Check both INDEPENDENTLY — an
    # `or` chain lets a truthy non-dict value under one key mask a valid dict
    # under the other (the same masking class as the foundry solc keys).
    for key in ("pipeline", "tasks"):
        section = data.get(key)
        if isinstance(section, dict) and section:
            out.append(f"WARN {rel} defines {len(section)} {key} task(s) — "
                       "executed by `turbo run`; review for shell injection in scripts")
    return out


# --- A2: per-ecosystem dangerous-content WARN (package.json / Cargo.toml /
#         pyproject data_files) ---------------------------------------------------
# All NON-GATING WARN, reached only from scan_content_warn's per-file try/except
# (so a raise here fail-opens). Every regex uses ONLY bounded quantifiers (ReDoS
# discipline carried from the A1 injection scanner — no `\s*`/`.*`/unbounded `+`).

# Stager / fetch-from-internet URL signals. Scanned ONLY over execution-bearing
# strings (package.json script values; Cargo patch/replace git+registry), never
# arbitrary manifest text. IGNORECASE (domains are case-insensitive). Matches are
# defanged (only the matched token) before display.
# Host-only sets use DNS-LABEL boundaries (not `\b`) so a known host as a PREFIX
# of a longer, different domain does NOT match — `raw.githubusercontent.com.evil`
# / `bit.ly.evil.example` are a different host and must not false-positive
# (ext-r1-LOW). Lookarounds are zero-width → no backtracking cost.
_DNS_L = r"(?<![A-Za-z0-9.-])"      # not preceded by a label char/dot
_DNS_R = r"(?![A-Za-z0-9.-])"       # not followed by a label char/dot
_STAGER_URL_RES = [
    re.compile(_DNS_L + r"(?:raw\.githubusercontent\.com|gist\.github(?:usercontent)?\.com"
               r"|pastebin\.com|hastebin\.com|ghostbin\.com|ix\.io|0x0\.st"
               r"|transfer\.sh|termbin\.com)" + _DNS_R, re.IGNORECASE),
    re.compile(_DNS_L + r"(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly)" + _DNS_R,
               re.IGNORECASE),
    re.compile(r"https?://[^\s'\"]{1,512}\.(?:sh|ps1|bash)\b", re.IGNORECASE),
    re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE),
]

# package.json script-value danger tokens (loud-only; IGNORECASE). Each fires a
# WARN naming the script + label — the script BODY is NEVER echoed (no
# raw-clickable-URL / dot-mangling risk; the reviewer opens the named script).
_PKG_SCRIPT_RES = [
    (re.compile(r"\b(?:curl|wget)\b[^\n]{0,512}?\|\s{0,8}(?:sh|bash|node|zsh)\b",
                re.IGNORECASE), "pipes a network fetch into a shell"),
    (re.compile(r"\bbase64\s{0,8}(?:-d|--decode)\b", re.IGNORECASE),
     "decodes base64 (obfuscated payload)"),
    (re.compile(r"\batob\s{0,8}\(", re.IGNORECASE),
     "decodes base64 via atob() (obfuscated payload)"),
    (re.compile(r"\bxxd\s{0,8}-r\b", re.IGNORECASE),
     "hex-decodes via xxd -r (obfuscated payload)"),
    (re.compile(r"\bnode\s{0,8}(?:-e|--eval)\b", re.IGNORECASE),
     "runs inline node -e code"),
    (re.compile(r"\bpython3?\s{0,8}-c\b", re.IGNORECASE),
     "runs inline python -c code"),
    # `php -r` (inline PHP code) is the composer-script idiom; shared here (zero FP
    # in a package.json that never contains it). NOT `php -d` (benign ini options).
    (re.compile(r"\bphp\s{0,8}-r\b", re.IGNORECASE), "runs inline php -r code"),
    (re.compile(r"\beval\s{0,8}[\"'(]", re.IGNORECASE), "calls eval"),
    (re.compile(r"\bbash\s{0,8}-c\b", re.IGNORECASE), "runs inline bash -c code"),
    (re.compile(r"\$\{?NPM_TOKEN\b", re.IGNORECASE),
     "reads $NPM_TOKEN (secret exfil)"),
    (re.compile(r"\$\{?GITHUB_TOKEN\b", re.IGNORECASE),
     "reads $GITHUB_TOKEN (secret exfil)"),
    (re.compile(r"\$\{?AWS_(?:SECRET|ACCESS)_[A-Z_]{0,32}\b", re.IGNORECASE),
     "reads an AWS secret (exfil)"),
    (re.compile(r"\bprintenv\b", re.IGNORECASE), "dumps the environment (printenv)"),
    # INTENTIONALLY broad (any `env |` pipe, not only network sinks): piping the
    # full environment anywhere is anomalous in a package.json script, and this
    # is a non-gating WARN — conscious divergence from D2's "piped to network".
    (re.compile(r"\benv\s{0,4}\|", re.IGNORECASE),
     "pipes the full environment to another command"),
    (re.compile(r"(?:~|\$HOME|\$\{HOME\})/(?:\.ssh|\.bashrc|\.profile)\b",
                re.IGNORECASE), "touches ~/.ssh or shell rc files"),
    (re.compile(r">>\s{0,8}(?:~|\$HOME|\$\{HOME\})/", re.IGNORECASE),
     "appends to a file under the home dir"),
    (re.compile(r"\s/etc/", re.IGNORECASE), "writes under /etc"),
]


def _stager_url_hits(value) -> list[str]:
    """DEFANGED matched URL/host tokens in `value` (never the whole value).
    Callers pre-slice to WARN_SCRIPT_VALUE_MAX. Total — never raises.

    A single URL can match two rules (e.g. the host-only rule AND the full
    `.sh`-path rule), producing two character spans for ONE URL. We drop any span
    strictly CONTAINED within a wider one (keep the widest, most-informative
    token) — span-based, not string-based, so two genuinely distinct URLs at
    different positions (even `a.com` vs `a.com.evil.com`) are both kept."""
    out: list[str] = []
    try:
        if not isinstance(value, str):
            return out
        spans: list[tuple[int, int]] = []
        for rx in _STAGER_URL_RES:
            for m in rx.finditer(value):
                spans.append((m.start(), m.end()))
        seen: set = set()
        for i, (s, e) in enumerate(spans):
            contained = any(
                j != i and ss <= s and e <= ee and (ee - ss) > (e - s)
                for j, (ss, ee) in enumerate(spans))
            if contained:
                continue
            tok = _defang(value[s:e])
            if tok not in seen:
                seen.add(tok)
                out.append(tok)
    except Exception:
        return out
    return out


def _cargo_escape_path(s) -> bool:
    """GENERIC repo-root-escape predicate (despite the name — reused by the Cargo,
    go.mod/go.work, and requirements handlers). True for a path that escapes the
    cloned repo root: a `..` traversal COMPONENT, a POSIX-absolute path, a Windows
    drive, or a UNC path. NOT _suspicious_path — that helper treats /home,/Users as
    benign (correct for compiler paths, WRONG for a dependency/replace escape)."""
    if not isinstance(s, str):
        return False
    comps = s.replace("\\", "/").split("/")
    if ".." in comps:                       # component-aware (foo..bar not flagged)
        return True
    if s.startswith("/"):                   # POSIX absolute
        return True
    if re.match(r"^[A-Za-z]:", s):          # Windows drive
        return True
    if s.startswith("\\\\"):                # UNC
        return True
    return False


def _pyproject_system_dest(dest) -> bool:
    """True for a setuptools data_files DESTINATION that writes outside
    site-packages to a system root or home dir. COMPONENT-AWARE (mirrors
    _suspicious_path's boundary check) so `/etcetera` does not false-positive."""
    if not isinstance(dest, str):
        return False
    for p in ("/etc", "/usr", "/bin", "/var"):
        if dest == p or dest.startswith(p + "/"):
            return True
    for h in ("~", "$HOME", "${HOME}"):
        if dest == h or dest.startswith(h + "/"):
            return True
    return False


def _warn_package_json(rel: Path, data) -> list[str]:
    """Flag dangerous patterns in package.json `scripts` values (loud-only):
    fetch-pipe-to-shell, decode-run, inline eval, secret exfil, home/system
    writes, and stager URLs. NON-GATING. The script BODY is never echoed — each
    WARN names the script + matched signal; stager hits show only the defanged
    URL token."""
    out: list[str] = []
    if not isinstance(data, dict):
        return out
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return out
    seen: set = set()
    names = sorted(scripts)
    for name in names[:WARN_PKG_SCRIPT_CAP]:
        val = scripts.get(name)
        if not isinstance(val, str):
            continue
        v = val[:WARN_SCRIPT_VALUE_MAX]
        dname = _defang_if_url(name)   # a URL-valued script KEY must not leak raw
        for rx, label in _PKG_SCRIPT_RES:
            if rx.search(v) and (name, label) not in seen:
                seen.add((name, label))
                out.append(f"WARN {rel} [scripts.{dname}] matches {label} — runs on "
                           f"npm/yarn install or `npm run {dname}`; review")
        for tok in _stager_url_hits(v):
            key = (name, "stager", tok)
            if key not in seen:
                seen.add(key)
                out.append(f"WARN {rel} [scripts.{dname}] fetches {tok} — external "
                           "stager URL; review")
    if len(names) > WARN_PKG_SCRIPT_CAP:
        out.append(f"WARN {rel} [scripts] +{len(names) - WARN_PKG_SCRIPT_CAP} more "
                   "script(s) not scanned (cap)")
    return out


def _warn_cargo_toml(rel: Path, data) -> list[str]:
    """Flag dangerous Cargo.toml patterns (NON-GATING WARN): a custom build
    script that evades the build.rs basename quarantine; dependency `path` values
    that escape the cloned repo root (incl. target-specific tables); and
    [patch]/[replace] supply-chain overrides + their stager git/registry URLs.
    ONE shared WARN_CARGO_DEP_CAP counter spans all dep + override traversals."""
    out: list[str] = []
    if not isinstance(data, dict):
        return out
    seen: set = set()
    budget = [WARN_CARGO_DEP_CAP]
    truncated = [False]

    # 1. custom build-script evasion of the build.rs basename quarantine.
    pkg = data.get("package")
    if isinstance(pkg, dict):
        b = pkg.get("build")
        if isinstance(b, str) and b != "build.rs":
            out.append(f"WARN {rel} [package] build = {_defang_repr(b)} — custom build "
                       "script NOT caught by the build.rs basename quarantine; "
                       "auto-compiles/runs under cargo build & rust-analyzer; review")

    def _scan_dep_table(label: str, tbl) -> None:
        if not isinstance(tbl, dict):
            return
        for crate in sorted(tbl):
            if budget[0] <= 0:
                truncated[0] = True
                return
            budget[0] -= 1                    # consume per ENTRY VISITED (ext-r1):
            spec = tbl.get(crate)             # bound work even for skipped str deps
            if not isinstance(spec, dict):   # `foo = "1.0"` str dep: can't escape
                continue
            p = spec.get("path")
            if _cargo_escape_path(p) and (label, crate, p) not in seen:
                seen.add((label, crate, p))
                out.append(f"WARN {rel} [{label}.{_defang_if_url(crate)}] path = "
                           f"{_defang_repr(p)} — dependency path points outside the "
                           "cloned repo root; review")

    # 2. top-level + target-specific dependency tables.
    for t in ("dependencies", "dev-dependencies", "build-dependencies"):
        _scan_dep_table(t, data.get(t))
    tgt = data.get("target")
    if isinstance(tgt, dict):
        for triple in sorted(tgt):
            sect = tgt.get(triple)
            if isinstance(sect, dict):
                # the target-table KEY (triple) is attacker-controlled and flows
                # into the displayed label — defang it (crate/path already are).
                for t in ("dependencies", "dev-dependencies", "build-dependencies"):
                    _scan_dep_table(f"target.{_defang_if_url(triple)}.{t}", sect.get(t))

    # 3. [patch] (two-level {registry:{crate:spec}}) + [replace] (one-level)
    #    supply-chain overrides + their stager git/registry URLs.
    def _scan_override_spec(label: str, crate: str, spec) -> None:
        if budget[0] <= 0:                    # consume per ENTRY VISITED (ext-r1):
            truncated[0] = True               # bound work even for non-dict specs
            return
        budget[0] -= 1
        if not isinstance(spec, dict):
            return
        p = spec.get("path")
        dcrate = _defang_if_url(crate)
        if _cargo_escape_path(p) and (label, crate, p) not in seen:
            seen.add((label, crate, p))
            out.append(f"WARN {rel} [{label}.{dcrate}] path = {_defang_repr(p)} — "
                       "override path points outside the cloned repo root; review")
        for field in ("git", "registry"):
            sv = spec.get(field)
            if isinstance(sv, str):
                for tok in _stager_url_hits(sv[:WARN_SCRIPT_VALUE_MAX]):
                    key = (label, crate, field, tok)
                    if key not in seen:
                        seen.add(key)
                        out.append(f"WARN {rel} [{label}.{dcrate}] {field} = {tok} — "
                                   "override fetches from an external URL; review")

    # A [patch] registry / [replace] spec KEY may itself be a URL
    # (`[patch."https://github.com/evil/repo"]`) — DEFANG it everywhere it is
    # displayed (overrides list + label), the same no-raw-clickable-URL contract
    # the package.json side keeps (int-r1-LOW).
    patch = data.get("patch")
    if isinstance(patch, dict) and patch:
        out.append(f"WARN {rel} [patch] overrides "
                   f"{[_defang(k) for k in sorted(patch)][:5]} — redirects crates "
                   "to repo-controlled sources; review for supply-chain override")
        for registry in sorted(patch):
            crates = patch.get(registry)
            if isinstance(crates, dict):
                for crate in sorted(crates):
                    _scan_override_spec(f"patch.{_defang(registry)}", crate,
                                        crates.get(crate))
    replace = data.get("replace")
    if isinstance(replace, dict) and replace:
        out.append(f"WARN {rel} [replace] overrides "
                   f"{[_defang(k) for k in sorted(replace)][:5]} — redirects crates "
                   "to repo-controlled sources; review for supply-chain override")
        for spec_name in sorted(replace):
            _scan_override_spec("replace", _defang(spec_name), replace.get(spec_name))

    if truncated[0]:
        out.append(f"WARN {rel} — Cargo dep/override scan hit the "
                   f"{WARN_CARGO_DEP_CAP}-entry cap; remaining entries not scanned")
    return out


# --- A2.1: go.mod/go.work, composer.json, requirements-family --------------------
# All NON-GATING WARN, fail-open, reached only from scan_content_warn. Line-scanned
# (go.mod/requirements) or json.loads (composer). Bounded regex; URL tokens defanged,
# filesystem paths shown raw (mirror _warn_gitmodules).

def _go_first_token(rhs: str) -> str:
    """First whitespace token of a go.mod replace RHS (the target module/path)."""
    rhs = rhs.strip()
    return rhs.split()[0] if rhs.split() else ""


def _warn_go_mod(rel: Path, text: str) -> list[str]:
    """go.mod / go.work `replace` directives (single-line + `replace ( … )` block).
    Two-tier: ONE summary line if any replace exists; a LOUDER per-entry WARN when
    the `=>` RHS is a filesystem path escaping the repo root. require-side ignored."""
    out: list[str] = []
    seen: set = set()
    in_block = False
    n_replace = 0
    truncated = False
    block_open = re.compile(r"replace\s{0,8}\(\s*$")
    single = re.compile(r"replace\s{1,8}")
    lines = text.splitlines()
    if len(lines) > WARN_LINE_CAP:
        lines = lines[:WARN_LINE_CAP]
        truncated = True

    def _handle_entry(seg: str) -> None:
        # called only with `=>` in seg. Consume one budget unit per entry; mark
        # truncated only when the cap is actually exceeded (no false over-report).
        nonlocal n_replace, truncated
        if n_replace >= WARN_GO_REPLACE_CAP:
            truncated = True
            return
        n_replace += 1
        target = _go_first_token(seg.split("=>", 1)[1])
        if _cargo_escape_path(target) and ("esc", target) not in seen:
            seen.add(("esc", target))
            out.append(f"WARN {rel} replace => {_defang_repr(target)} — replacement "
                       "points outside the repo root; review for local/source override")

    for raw in lines:
        line = raw.split("//", 1)[0]          # strip a //-to-EOL comment FIRST
        s = line.strip()
        if not s:
            continue
        if not in_block and block_open.match(s):
            in_block = True
            continue
        if in_block:
            if s == ")":
                in_block = False
                continue
            if "=>" in s:
                _handle_entry(s)
            continue
        if single.match(s) and "=>" in s:
            _handle_entry(s)
    if n_replace:
        out.append(f"WARN {rel} {n_replace} replace directive(s) present — "
                   "dependency source override; review")
    if truncated:
        out.append(f"WARN {rel} — replace/line scan hit a cap; "
                   "remaining entries not scanned")
    return out


def _warn_composer_json(rel: Path, data) -> list[str]:
    """composer.json `scripts` events (string OR array-of-strings values). REUSES the
    shared _PKG_SCRIPT_RES corpus + _stager_url_hits, SAME display contract as
    package.json (name the event + signal, never echo the body; stager defanged).
    NOTE: PHP callable / `@php` / `Vendor\\Class::method` scripts run in-process and
    are NOT matched — an accepted FN; the isolation boundary is the defense."""
    out: list[str] = []
    if not isinstance(data, dict):
        return out
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return out
    seen: set = set()
    names = sorted(scripts)
    for event in names[:WARN_PKG_SCRIPT_CAP]:
        val = scripts.get(event)
        vals = val if isinstance(val, list) else [val]
        for v0 in vals[:WARN_COMPOSER_ELEM_CAP]:
            if not isinstance(v0, str):
                continue
            v = v0[:WARN_SCRIPT_VALUE_MAX]
            devent = _defang_if_url(event)   # a URL-valued script KEY must not leak raw
            for rx, label in _PKG_SCRIPT_RES:
                if rx.search(v) and (event, label) not in seen:
                    seen.add((event, label))
                    out.append(f"WARN {rel} [scripts.{devent}] matches {label} — "
                               "runs on composer install/update; review")
            for tok in _stager_url_hits(v):
                key = (event, "stager", tok)
                if key not in seen:
                    seen.add(key)
                    out.append(f"WARN {rel} [scripts.{devent}] fetches {tok} — "
                               "external stager URL; review")
    if len(names) > WARN_PKG_SCRIPT_CAP:
        out.append(f"WARN {rel} [scripts] +{len(names) - WARN_PKG_SCRIPT_CAP} more "
                   "script(s) not scanned (cap)")
    return out


# requirements-file danger rules. Module-level so the ReDoS test can reach them.
# Every flag token is anchored to line-start-or-whitespace so a path containing
# `-i`/`-e` (e.g. `./my-i-pkg`) does not false-match. URL tokens defanged on display.
_REQ_INDEX_RE = re.compile(
    r"(?:^|\s)(?:--index-url|--extra-index-url|--find-links|-i)(?=[\s=]|$)", re.IGNORECASE)
_REQ_VCS_RE = re.compile(r"\b(?:git|hg|svn|bzr)\+[a-z]{1,8}://", re.IGNORECASE)
_REQ_ARCHIVE_RE = re.compile(
    r"https?://[^\s'\"]{1,512}\.(?:tar\.gz|tgz|whl|zip|tar\.bz2)\b", re.IGNORECASE)
_REQ_PEP508_URL_RE = re.compile(r"\S{1,128}\s{0,4}@\s{0,4}https?://", re.IGNORECASE)
_REQ_EDITABLE_RE = re.compile(r"(?:^|\s)(?:-e|--editable)\s{1,8}(\S{1,512})", re.IGNORECASE)
_REQ_INCLUDE_RE = re.compile(
    r"^(?:-r|--requirement|-c|--constraint)\s{1,8}(?P<target>\S{1,512})", re.IGNORECASE)
_REQ_URL_TOKEN_RE = re.compile(r"https?://\S{1,512}", re.IGNORECASE)
# exposed for test_a2_redos_regexes_bounded
_REQ_RULE_RES = [_REQ_INDEX_RE, _REQ_VCS_RE, _REQ_ARCHIVE_RE, _REQ_PEP508_URL_RE,
                 _REQ_EDITABLE_RE, _REQ_INCLUDE_RE, _REQ_URL_TOKEN_RE]


def _req_logical_lines(text: str, cap: int) -> list[str]:
    """Join `\\`-continuation physical lines into logical lines, strip #-comments.
    CAP-AWARE: stops after `cap`+1 logical lines so join/strip work is bounded by
    the cap (not just by MAX_CONTENT_BYTES) — the caller flags truncation."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        buf += raw
        out.append(buf)
        buf = ""
        if len(out) > cap:
            break
    if buf and len(out) <= cap:
        out.append(buf)
    cleaned = []
    for line in out:
        # strip a #-comment (leading, or preceded by whitespace); a mid-token
        # `egg=#...` is a rare accepted edge.
        m = re.search(r"(?:^|\s)#", line)
        if m:
            line = line[:m.start()]
        cleaned.append(line.strip())
    return cleaned


def _req_url_token(line: str) -> str:
    """First defanged http(s) URL token in `line`, or '' (display-only)."""
    m = _REQ_URL_TOKEN_RE.search(line)
    return _defang(m.group(0)) if m else ""


def _warn_requirements(rel: Path, text: str) -> list[str]:
    """pip requirements/constraints lines that fetch+install code from outside PyPI:
    index/find-links redirects (dependency-confusion), VCS installs, direct-archive
    URLs, editable VCS/URL or root-escaping paths, and `-r`/`-c` includes. URL tokens
    defanged; `-e`/include path args shown raw."""
    out: list[str] = []
    seen: set = set()
    lines = _req_logical_lines(text, WARN_LINE_CAP)
    if len(lines) > WARN_LINE_CAP:
        lines = lines[:WARN_LINE_CAP]
        out.append(f"WARN {rel} — requirements scan hit the {WARN_LINE_CAP}-line "
                   "cap; remaining lines not scanned")
    for raw in lines:
        if not raw:
            continue
        L = raw[:WARN_SCRIPT_VALUE_MAX]

        def _emit(fam: str, msg: str) -> None:
            if (fam, msg) not in seen:
                seen.add((fam, msg))
                out.append(f"WARN {rel} {msg}")

        if _REQ_INDEX_RE.search(L):
            tok = _req_url_token(L)
            _emit("index", f"index/source override{' ' + tok if tok else ''} — "
                  "dependency-confusion / registry redirect; review")
        if _REQ_VCS_RE.search(L):
            tok = _req_url_token(L)
            _emit("vcs", f"[VCS install]{' ' + tok if tok else ''} — fetches+builds "
                  "code from a VCS URL; review")
        if _REQ_ARCHIVE_RE.search(L) or _REQ_PEP508_URL_RE.search(L):
            tok = _req_url_token(L)
            _emit("url", f"[direct URL install]{' ' + tok if tok else ''} — installs "
                  "an archive from a URL; review")
        me = _REQ_EDITABLE_RE.search(L)
        if me:
            arg = me.group(1)
            if _REQ_VCS_RE.search(arg) or arg.lower().startswith(("http://", "https://")):
                _emit("edit", f"[editable] fetches {_defang(arg)} — editable "
                      "VCS/URL install; review")
            elif _cargo_escape_path(arg):
                _emit("edit", f"[editable] {_defang_repr(arg)} — editable install "
                      "outside the repo root; review")
        mi = _REQ_INCLUDE_RE.search(L)
        if mi:
            # a remote include (`-r https://…/req.txt`, pip-supported) must not
            # leak a raw clickable URL; a local path target stays raw.
            _emit("inc", f"include {_defang_if_url(mi.group('target'))!r} present "
                  "(not followed); review the referenced file")
    return out


# Suspicious .gitmodules URL transports — flag on the `url` key.
# `ext::` and `file:` are the established dangerous ones (code exec / local
# access, CVE-2025-48384 class); `git://` is unauthenticated (MITM-able);
# `ftp://` has no auth; localhost/IP targets point at the host machine
# (SSRF-equivalent). The latter are informational WARNs, not the RCE class.
_GITMODULES_BAD_TRANSPORTS = re.compile(
    r"^(ext::|file:|git://|ftp://|ftps://)",
    re.IGNORECASE,
)
# Optional `userinfo@` (e.g. `ssh://git@localhost/...`) is consumed before the
# host. Host is anchored on a boundary (`:` port, `/` path, or end) so
# `localhostess` does not match `localhost`; bracketed IPv6 (`[::1]`, the normal
# git form) is accepted alongside the bare form.
_GITMODULES_LOCALHOST = re.compile(
    r"^[a-z+.\-]+://(?:[^/@\s]*@)?(\[::1\]|localhost|127(?:\.\d+){3}|0\.0\.0\.0|::1)(?=[:/]|$)",
    re.IGNORECASE,
)
# scp-like syntax `[user@]host:path` (no `scheme://`) is the common git form and
# the `://` regex above misses it. The `(?!/)` after the host's colon excludes a
# real `scheme://` (which the regex above already handles), so the two don't overlap.
_GITMODULES_SCP_LOCALHOST = re.compile(
    r"^(?:[^/@\s]+@)?(\[::1\]|localhost|127(?:\.\d+){3}|0\.0\.0\.0):(?!/)",
    re.IGNORECASE,
)


def _defang(s: str) -> str:
    """Render a URL/host/IP inert for HUMAN display in WARN / manifest output, so a
    reviewer skimming a flagged submodule URL cannot fat-finger-click it and a
    terminal, editor, or CI-log renderer will not auto-link or auto-fetch it.

    Display-only and deliberately NOT reversed: the transport classification and
    the `transport` label are derived from the RAW value by the caller (this never
    feeds a decision), so defanging only the *displayed* string changes nothing the
    code acts on. Only the LEADING scheme colon is bracketed, never an internal
    colon — so IPv6 literals (`[::1]`) and scp-form `host:path` / `:port` colons
    stay legible. Idempotent: re-applying never double-brackets an already-defanged
    value — every rule is either anchored at `^` (so it cannot re-match its own
    `[:]`/`hxxp` output) or skips an already-bracketed `@`/`.` via a negative
    lookaround.

    Scope: only fetchable / auto-linkable tokens are neutralized (schemes, dotted
    hosts/IPs, userinfo). A dotless schemeless loopback scp-form (`localhost:repo`,
    `[::1]:repo`) is shown raw BY DESIGN — no renderer auto-links it, the `:` is the
    legible scp marker, and the WARN already carries a 'localhost/loopback' reason."""
    s = re.sub(r"^ext::", "ext[:][:]", s, flags=re.IGNORECASE)      # ext:: RCE transport
    s = re.sub(r"^([A-Za-z][A-Za-z0-9+.\-]*)://", r"\1[:]//", s)    # any leading scheme://
    s = re.sub(r"^file:", "file[:]", s, flags=re.IGNORECASE)        # file: (no //) local-access
    s = re.sub(r"^http", "hxxp", s, flags=re.IGNORECASE)            # http(s) -> hxxp(s)
    s = re.sub(r"(?<!\[)@(?!\])", "[@]", s)                         # userinfo / scp separator
    s = re.sub(r"(?<!\[)\.(?!\])", "[.]", s)                        # every bare dot; skip [.]
    return s


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"]{1,512}", re.IGNORECASE)


def _defang_if_url(s: str) -> str:
    """Defang ONLY embedded http(s):// URL substrings in an attacker-controlled
    DISPLAY field (a script/event name, an include target) so no raw clickable URL
    leaks into terminal/CI output — while leaving a non-URL name (e.g.
    `test.watch`) untouched. Reuses `_defang` on each URL match (each is
    leading-scheme within the match, so `_defang` neutralizes it fully)."""
    if not isinstance(s, str):
        return s
    return _URL_IN_TEXT_RE.sub(lambda m: _defang(m.group(0)), s)


def _defang_repr(v) -> str:
    """`repr(v)` with any embedded http(s):// URL defanged — the universal
    display form for an attacker-controlled content-WARN VALUE field of arbitrary
    type (str / list / dict / bool / int). Replaces a bare `{v!r}`: byte-identical
    for any value with no URL substring (so existing exact-match assertions hold),
    and neutralizes a URL that an untrusted manifest embeds in a path/value/key so
    a terminal or CI-log renderer cannot auto-link it. (Use `_defang_if_url` for a
    bare, unquoted label component instead.)"""
    return _defang_if_url(repr(v))


def _warn_gitmodules(rel: Path, text: str) -> list[str]:
    """Line-scan (stdlib, no git shell-out). Flag dangerous submodule URLs
    (ext::/file:, git://, ftp://, localhost/IP) and absolute / `..`-component /
    control-char (incl. embedded CR) paths (CVE-2025-48384). `..` is
    COMPONENT-AWARE so a benign `third_party/foo..bar` is not flagged.

    `text` MUST be read WITHOUT universal-newline translation (scan_content_warn
    passes `newline=""`), or every `\\r` would already have become `\\n` and the
    CR detection below would be dead. A `.gitmodules` whose lines are uniformly
    CRLF-terminated is normal — its per-line trailing `\\r` is the line ending, so
    it is stripped and NOT flagged; an LF-file's `\\r` (trailing CVE vector or
    mid-value) survives stripping and IS caught by `_forbidden_codepoint`."""
    out: list[str] = []
    lines = text.split("\n")
    terminated = lines[:-1]
    crlf_uniform = bool(terminated) and all(line.endswith("\r") for line in terminated)
    cur = "?"
    last = len(lines) - 1
    for i, line in enumerate(lines):
        if crlf_uniform and i < last and line.endswith("\r"):
            line = line[:-1]
        s = line.strip()
        m = re.match(r'\[submodule\s+"?(.*?)"?\]\s*$', s)
        if m:
            # display-only label; defang so a URL-shaped submodule name can't leak
            # a raw clickable link (cur is never used for logic, only display).
            cur = _defang_if_url(m.group(1))
            continue
        m = re.match(r'(\w+)\s*=\s*(.*)$', line.strip(" \t"))
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2)
        if key == "url":
            stripped = val.strip()
            if _GITMODULES_BAD_TRANSPORTS.match(stripped):
                # `transport` is split from the RAW url (the label the human needs);
                # only the displayed url VALUE is defanged so it can't be auto-linked.
                transport = stripped.split(":")[0]
                out.append(f"WARN {rel} [submodule {cur}] url = {_defang(stripped)!r} — "
                           f"dangerous transport ({transport}:)")
            elif _GITMODULES_LOCALHOST.match(stripped) or _GITMODULES_SCP_LOCALHOST.match(stripped):
                out.append(f"WARN {rel} [submodule {cur}] url = {_defang(stripped)!r} — "
                           "localhost/loopback submodule URL")
        elif key == "path":
            sval = val.strip()
            comps = sval.replace("\\", "/").split("/")
            cp = _forbidden_codepoint(val)
            if sval.startswith("/"):
                out.append(f"WARN {rel} [submodule {cur}] path = {_defang_repr(sval)} "
                           "— absolute path")
            elif ".." in comps:
                out.append(f"WARN {rel} [submodule {cur}] path = {_defang_repr(sval)} — "
                           "'..' traversal component")
            elif cp is not None:
                out.append(f"WARN {rel} [submodule {cur}] path = {_defang_repr(sval)} has "
                           f"{cp} — CVE-2025-48384 control/CR vector")
    return out


def scan_content_warn(repo: Path) -> list[str]:
    """FAIL-OPEN content WARNs over LEFT-LIVE files. Never raises, never affects
    exit code: a parse error yields `WARN could not parse ...; review manually`.
    Skips `.git/` and `.quarantine/` — the latter avoids re-WARNing on quarantined
    copies of foundry.toml etc. that have already been neutralized by renaming."""
    out: list[str] = []

    def _onerror(e: OSError) -> None:
        print(f"warning: could not read during content scan: {e}", file=sys.stderr)

    for dirpath, dirnames, filenames in os.walk(repo, onerror=_onerror):
        dp = Path(dirpath)
        if dp == repo:
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", QUARANTINE_DIR)]
        for nm in filenames:
            # exact-name set first (cheap); only non-named files pay the
            # requirements-predicate regex (short-circuit).
            if nm not in CONTENT_WARN_NAMES and not _is_requirements_file(dp, nm):
                continue
            p = dp / nm
            if p.is_symlink():
                continue
            rel = p.relative_to(repo)
            try:
                # Size guard before any parser builds an in-memory tree: an
                # absurdly large left-live file is a memory-exhaustion vector.
                if p.stat().st_size > MAX_CONTENT_BYTES:
                    out.append(f"WARN {rel} is {p.stat().st_size} bytes "
                               f"(> {MAX_CONTENT_BYTES}) — skipped content scan "
                               "(size guard); review manually")
                    continue
                if nm == "foundry.toml":
                    out += _warn_foundry(rel, _toml_load(p))
                elif nm == "Anchor.toml":
                    out += _warn_anchor(rel, _toml_load(p))
                elif nm == "pyproject.toml":
                    out += _warn_pyproject(rel, _toml_load(p))
                elif nm == "slither.config.json":
                    out += _warn_slither(rel, json.loads(p.read_text(encoding="utf-8")))
                elif nm == "pom.xml":
                    out += _warn_pom(rel, p.read_text(encoding="utf-8", errors="replace"))
                elif nm == ".gitmodules":
                    # newline="" preserves \r so the CVE-2025-48384 CR vector is
                    # not silently translated to \n before _warn_gitmodules sees it
                    out += _warn_gitmodules(
                        rel, p.read_text(encoding="utf-8", errors="replace", newline=""))
                elif nm == "nx.json":
                    out += _warn_nx(rel, json.loads(p.read_text(encoding="utf-8")))
                elif nm == "turbo.json":
                    out += _warn_turbo(rel, json.loads(p.read_text(encoding="utf-8")))
                elif nm == "package.json":
                    out += _warn_package_json(rel, json.loads(p.read_text(encoding="utf-8")))
                elif nm == "Cargo.toml":
                    out += _warn_cargo_toml(rel, _toml_load(p))
                elif nm == "go.mod" or nm == "go.work":
                    out += _warn_go_mod(rel, p.read_text(encoding="utf-8", errors="replace"))
                elif nm == "composer.json":
                    out += _warn_composer_json(rel, json.loads(p.read_text(encoding="utf-8")))
                elif _is_requirements_file(dp, nm):
                    out += _warn_requirements(rel, p.read_text(encoding="utf-8", errors="replace"))
            except Exception as e:  # fail-open: a parse error never breaks sanitize
                out.append(f"WARN could not parse {rel} ({type(e).__name__}); review manually")
    return out


# --- Phase 4: prompt-injection content scan (A1 +A4) -----------------------------
# A host-side, static, pre-LLM scan: BEFORE a human points an auditor/reviewer LLM
# at an untrusted repo's source, flag content engineered to make that model JUDGE
# WRONG (instruction override, fake reasoning/control tokens, exfil imperatives,
# audit-verdict manipulation, …). THREE tiers:
#   TIER 1  hard fail-closed (symlinks / Trojan-Source codepoints) — UNCHANGED,
#           gates at exit 2, fires BEFORE this scanner.
#   TIER 2  injection HALT (this layer) — high-confidence/critical signal in a
#           context where FP is near-0 -> exit 3, LOUD alert, ack-overridable
#           (--ack-injection / COLDCLONE_ACK_INJECTION=1, HOST-side only).
#   TIER 3  advisory WARN (this layer + the existing _warn_* content layer) —
#           exit 0, prominent but non-gating.
#
# CRASH != DETECTION (load-bearing): the whole scanner is wrapped so ANY internal
# exception collapses the WHOLE return to ([], []) — a crash fails OPEN (no halt),
# only a real DETECTION halts. Rule corpus = module-level RAW strings; regex is
# compiled LAZILY inside scan_injection() under that try, so a bad pattern can
# never raise at import.
#
# Categories authored MIT, using cloneguard's categories + public citations as
# INSPIRATION only (no verbatim copy) — credit in PRIOR-ART.md.
#
# Each rule: (rule_id, category, regex_str, halt_scope, anchor_note).
# halt_scope in {"ALWAYS","STRICT","NEVER"} -> HALT MATRIX:
#   ALWAYS — halt in STRICT + STANDARD (never in LENIENT): reasoning_hijack CONTROL
#            TOKENS only. Near-0 FP read verbatim in any file.
#   STRICT — halt ONLY in STRICT agent-config files; WARN in STANDARD + LENIENT:
#            instruction_override, mcp_tool_poisoning, exfil_imperative,
#            audit_verdict_manipulation.
#   NEVER  — always WARN: viral_propagation, behavioral_manipulation,
#            memory_poisoning, authority_impersonation, encoding_obfuscation,
#            markdown_svg_injection, terminal_escape.
# REGEX SAFETY: every pattern is linear-time — NO nested unbounded quantifiers, NO
# backreferences; only bounded `.{0,N}` gaps; `(?i)` ok. A ReDoS guard test runs
# each rule against a 100k-char payload + a long line under a wall-clock budget.
INJECTION_RULES = [
    # --- reasoning_hijack CONTROL TOKENS (ALWAYS-halt) ---------------------------
    ("RH-001", "reasoning_hijack", r"(?i)<\|im_start\|>",                 "ALWAYS", "ChatML control token"),
    ("RH-002", "reasoning_hijack", r"(?i)<\|im_end\|>",                   "ALWAYS", "ChatML control token"),
    ("RH-003", "reasoning_hijack", r"(?i)</?thinking>",                   "ALWAYS", "fake CoT thinking tag"),
    ("RH-004", "reasoning_hijack", r"(?i)</?tool_result>",               "ALWAYS", "fake tool-result tag"),
    ("RH-005", "reasoning_hijack", r"(?i)</?function_result>",           "ALWAYS", "fake function-result tag"),
    ("RH-006", "reasoning_hijack", r"^\s{0,8}(Observation|Thought|Action):", "ALWAYS", "fake ReAct trace line"),
    # --- instruction_override (STRICT-halt) -------------------------------------
    ("IO-001", "instruction_override",
     r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,40}\b(instruction|instructions|prompt|prompts|rule|rules|context)\b",
     "STRICT", "ignore/disregard + previous + instructions"),
    ("IO-002", "instruction_override",
     r"(?i)\bnew\b.{0,20}\bsystem\b.{0,20}\bprompt\b",
     "STRICT", "new system prompt"),
    ("IO-003", "instruction_override",
     r"(?i)\byou\b.{0,12}\b(are|act)\b.{0,20}\b(now|as)\b.{0,20}\b(DAN|jailbroken|jailbreak|developer mode|unrestricted)\b",
     "STRICT", "you-are-now-DAN/jailbroken"),
    ("IO-004", "instruction_override",
     r"(?i)\b(override|replace)\b.{0,30}\b(instruction|instructions|rule|rules|prompt|prompts)\b",
     "STRICT", "override/replace instructions (low-conf)"),
    # --- mcp_tool_poisoning (STRICT-halt) ---------------------------------------
    ("MC-001", "mcp_tool_poisoning",
     r"(?i)\b(before|when|always)\b.{0,40}\b(using|calling|invoking|use|call|invoke)\b.{0,40}\b(this\s{1,8})?tool\b.{0,40}\b(read|send|exfiltrate|fetch|run|execute)\b",
     "STRICT", "MCP tool-description side-effect imperative"),
    ("MC-002", "mcp_tool_poisoning",
     r"(?i)<important>.{0,200}(ignore|do not|secret|exfiltrate|send)",
     "STRICT", "MCP <important> instruction smuggling"),
    # --- exfil_imperative (STRICT-halt): reader/model-directed imperative +
    #     secret/data object + externalize SINK (not generic 'don't leak keys') ----
    ("EX-001", "exfil_imperative",
     r"(?i)\b(send|post|upload|exfiltrate|transmit|leak|email|forward)\b.{0,60}\b(secret|secrets|api[\s_-]?key|api[\s_-]?keys|private[\s_-]?key|password|passwords|credential|credentials|token|tokens|\.env|seed phrase|mnemonic)\b.{0,60}\b(to|http|https|curl|fetch|webhook|endpoint|url)\b",
     "STRICT", "exfil imperative: secret object + external sink"),
    # --- audit_verdict_manipulation (STRICT-halt): 2nd-person/model-directed +
    #     verdict verb (not descriptive 3rd-person 'no findings' prose) -----------
    ("AV-001", "audit_verdict_manipulation",
     r"(?i)\bdo not\b.{0,20}\b(report|flag|mention|disclose)\b.{0,30}\b(this|finding|findings|issue|vulnerability|vuln|bug)\b",
     "STRICT", "do-not-report directive"),
    ("AV-002", "audit_verdict_manipulation",
     r"(?i)\b(mark|rate|classify|treat|consider)\b.{0,20}\bthis\b.{0,20}\bas\b.{0,20}\b(low|safe|benign|informational|out[\s-]?of[\s-]?scope|no[\s-]?risk)\b",
     "STRICT", "mark-this-as-low/safe directive"),
    ("AV-003", "audit_verdict_manipulation",
     r"(?i)\bignore\b.{0,20}\bthis\b.{0,20}\b(finding|issue|vulnerability|vuln|bug|warning)\b",
     "STRICT", "ignore-this-finding directive"),
    ("AV-004", "audit_verdict_manipulation",
     r"(?i)\b(out[\s-]?of[\s-]?scope|skip)\b.{0,20}[—:-].{0,20}\bskip\b",
     "STRICT", "out-of-scope — skip directive"),
    # --- viral_propagation (NEVER -> WARN) --------------------------------------
    ("VP-001", "viral_propagation",
     r"(?i)\b(copy|propagate|replicate|inject|add)\b.{0,30}\b(this|these)\b.{0,30}\b(instruction|instructions|prompt|rule|rules)\b.{0,30}\b(into|to)\b.{0,30}\b(every|all|each|other)\b",
     "NEVER", "self-propagation directive"),
    # --- behavioral_manipulation (NEVER -> WARN) --------------------------------
    ("BM-001", "behavioral_manipulation",
     r"(?i)\b(always|never)\b.{0,30}\b(approve|comply|agree|trust|obey)\b.{0,30}\b(without|regardless)\b",
     "NEVER", "unconditional-compliance directive"),
    # --- memory_poisoning (NEVER -> WARN) ---------------------------------------
    ("MP-001", "memory_poisoning",
     r"(?i)\b(remember|store|save|persist|memorize)\b.{0,30}\b(this|that)\b.{0,30}\b(for|in|across)\b.{0,30}\b(all|every|future|next)\b.{0,20}\b(session|sessions|conversation|conversations|task|tasks)\b",
     "NEVER", "cross-session memory injection"),
    # --- authority_impersonation (NEVER -> WARN) --------------------------------
    ("AI-001", "authority_impersonation",
     r"(?i)\b(as|this is)\b.{0,20}\b(your|the)\b.{0,20}\b(developer|administrator|admin|owner|anthropic|openai|system)\b.{0,30}\b(instruct|instructs|command|order|require|authorize)\b",
     "NEVER", "authority impersonation"),
    # --- encoding_obfuscation (NEVER -> WARN) -----------------------------------
    ("EO-001", "encoding_obfuscation",
     r"(?i)\b(decode|base64\s?decode|rot13|from\s?hex)\b.{0,30}\b(and|then)\b.{0,20}\b(execute|run|follow|obey)\b",
     "NEVER", "decode-then-execute directive"),
    # --- markdown_svg_injection (NEVER -> WARN) ---------------------------------
    ("MS-001", "markdown_svg_injection",
     r"(?i)<svg\b[^>]{0,200}\bonload\s{0,16}=",
     "NEVER", "SVG onload handler"),
    ("MS-002", "markdown_svg_injection",
     r"(?i)!\[[^\]]{0,80}\]\(\s{0,16}(javascript|data):",
     "NEVER", "markdown image javascript:/data: URI"),
    # --- terminal_escape (NEVER -> WARN) ----------------------------------------
    ("TE-001", "terminal_escape", r"\x1b\][0-9];",                       "NEVER", "OSC terminal escape sequence"),
    ("TE-002", "terminal_escape", r"\x1b\[[0-9;]{0,12}[A-Za-z]",         "NEVER", "CSI terminal escape sequence"),
]

# Auto-loaded agent-INSTRUCTION file basenames (STRICT classification anywhere,
# even under tests/). A superset overlap with FILE_NAMES, but a DISTINCT set: a
# file here is treated as instructions the agent auto-loads, so EVERY injection
# category halts in it. Case-SENSITIVE (parity with DIR_NAMES/FILE_NAMES, :121-123).
AGENT_CONFIG_NAMES = {
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md",
    "AGENTS.override.md", "GEMINI.md", "copilot-instructions.md",
    ".cursorrules", ".clinerules", ".windsurfrules", ".roomodes",
    ".roo-instructions.md", ".aider.conf.yml", ".aiderrc",
    ".mcp.json", "mcp.json", "SKILL.md",
}

# The INSTRUCTION/agent-context subset of DIR_NAMES (sanitize_repo.py:91-111) — any
# path SEGMENT here makes a file STRICT (rule 1b). NOT all of DIR_NAMES: the build/
# editor/hook EXECUTION dirs (.vscode .devcontainer .idea .githooks .husky .cargo
# .yarn .mvn buildSrc) are NOT instruction auto-loads and MUST stay STANDARD, so
# benign prose under e.g. .vscode/README.md or buildSrc/notes.md does not wrongly
# HALT. `.quarantine` is deliberately absent (a repo-shipped stash does not
# blanket-STRICT its contents; a nested agent-config inside it is STRICT by its OWN
# segment/basename).
AGENT_CONFIG_DIRS = {
    ".claude", ".agents", ".cursor", ".gemini", ".aider",
    ".continue", ".windsurf", ".codeium", ".junie", ".clinerules",
}

# Binary-extension DENYLIST for the scan ("is this KNOWN-binary" — skip it). The
# model is a denylist, not an allowlist: any file whose extension is NOT here is
# treated as TEXT and scanned, so odd-extension agent-config payloads (e.g.
# `.cursor/rules/evil.mdc`) and a control-token in a root `notes.xyz` still HALT.
# Be conservative — when unsure, TREAT AS TEXT; the null-byte sniff of the first
# 4 KiB inside _scan_file is the real binary guard for anything that slips through.
# `.svg` is deliberately NOT here: it's XML and an injection vector (markdown_svg).
BINARY_EXTS = {
    # images (svg kept TEXT)
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
    # archives
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    # compiled
    ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".class", ".jar", ".wasm", ".pyc",
    # media
    ".mp3", ".mp4", ".mov", ".avi", ".webm", ".wav", ".ogg",
    # fonts
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    # docs-binary / db
    ".pdf", ".sqlite", ".db",
}

# LENIENT classification (WARN-only, HALT-excluded entirely).
# 2a — ANY file type under a genuine non-product bucket (test/vendor fixtures).
LENIENT_ANY_SEGMENTS = {
    "tests", "test", "fixtures", "testdata", "__tests__", "spec", "e2e",
    "vendor", "node_modules", "third_party",
}
# 2b — DOC-ONLY (only .md/.markdown/.txt/.rst) under audit/security buckets.
LENIENT_DOC_SEGMENTS = {"audits", "audit", "security", "reports"}
LENIENT_DOC_NAMES = {"SECURITY.md", "SECURITY.markdown"}
LENIENT_DOC_EXTS = {".md", ".markdown", ".txt", ".rst"}

# Per-file / per-pass scan budgets.
INJ_MAX_LINE_BYTES = 4096          # threshold above which the WARN snippet excerpt is
                                   # match-anchored+bounded (lines are scanned in FULL,
                                   # not truncated — rules are linear-time, file is capped)
INJ_PER_FILE_CAP = 10              # max emitted hits per (rule,file) before "+K more"
INJ_PASS1_FILE_CAP = 5000          # generous file-count cap for the STRICT-target pass
INJ_PASS1_BYTE_BUDGET = 64_000_000   # byte budget for the STRICT-target pass
INJ_BULK_BYTE_BUDGET = 256_000_000   # global byte budget for the bulk pass


def _scan_mode(rel: Path) -> str:
    """Pure, total ScanMode classifier over a repo-RELATIVE path string. No stat/
    resolve -> cannot raise. Returns "STRICT" | "STANDARD" | "LENIENT".

    Precedence (STRICT WINS over LENIENT):
      1. STRICT if EITHER basename in AGENT_CONFIG_NAMES (1a, anywhere) OR any path
         SEGMENT in AGENT_CONFIG_DIRS (1b — so EVERY file under .claude/ etc. is
         STRICT, not only files literally named CLAUDE.md).
      2. LENIENT — 2a (any file type) if a segment is a non-product bucket; 2b
         (doc-prose extensions only) if a segment/basename is an audit/security one.
      3. else STANDARD.
    Case-SENSITIVE (parity with DIR_NAMES/FILE_NAMES, sanitize_repo.py:121-123)."""
    name = rel.name
    parts = rel.parts
    segments = set(parts[:-1])  # directory segments only (basename handled separately)
    # Rule 1 — STRICT (wins).
    if name in AGENT_CONFIG_NAMES:
        return "STRICT"
    if segments & AGENT_CONFIG_DIRS:
        return "STRICT"
    # Rule 2a — LENIENT for ANY file type under a non-product bucket.
    if segments & LENIENT_ANY_SEGMENTS:
        return "LENIENT"
    # Rule 2b — DOC-ONLY LENIENT.
    suffix = rel.suffix
    if suffix in LENIENT_DOC_EXTS:
        if segments & LENIENT_DOC_SEGMENTS:
            return "LENIENT"
        if name in LENIENT_DOC_NAMES:
            return "LENIENT"
        if (name.startswith("report") or name.startswith("audit")) \
                and suffix in (".md", ".markdown"):
            return "LENIENT"
    # Rule 3 — STANDARD.
    return "STANDARD"


def _is_text_target(rel: Path) -> bool:
    """True if the scan should OPEN this file. Binary-DENYLIST model (NOT an
    allowlist): a file is scanned iff its extension is not a known-binary one, so
    odd-extension text files (`.mdc`, `notes.xyz`) are still scanned and an
    ALWAYS/STRICT payload there fires. The null-byte sniff inside _scan_file is the
    real binary guard for anything not on the denylist that is actually binary."""
    return rel.suffix.lower() not in BINARY_EXTS


def _print_injection_alert(halts: list) -> None:
    """LOUD, distinct alert block for tier-2 injection HALTs. TOTAL over the Halt
    tuple (rel, line, category, rule_id, snippet, mode) — must never raise (its
    caller wraps it again, but keep it total). Defanged snippets so a printed
    payload can't auto-link. Always to STDERR (so --json stdout stays clean)."""
    print("=" * 72, file=sys.stderr)
    print("HALT: HIGH-CONFIDENCE PROMPT-INJECTION DETECTED (tier 2)", file=sys.stderr)
    print("Do NOT point an LLM at this repo until you have reviewed the below.",
          file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    for h in halts:
        try:
            rel, line, category, rule_id, snippet, mode = h
            print(f"  INJECTION-HALT {category} [{rule_id}] {rel}:{line} "
                  f"({mode}) — {_defang(str(snippet))}", file=sys.stderr)
        except Exception:
            print(f"  INJECTION-HALT (unprintable finding) — {h!r}", file=sys.stderr)


def _print_injection_alert_safe(halts: list) -> None:
    """CRASH != DETECTION extends past the scanner: a raise in the alert consumer
    must not propagate out of main() (uncaught traceback -> nonzero exit ->
    coldclone.sh `set -e` aborts = crash-causes-halt). Own try/except, never raises."""
    try:
        _print_injection_alert(halts)
    except Exception:
        try:
            print(f"warning: injection alert printer failed ({len(halts)} halt(s) "
                  "detected — review manually)", file=sys.stderr)
        except Exception:
            pass


def _print_acked_injection_record(repo: Path) -> None:
    """G4 checkpoint: print any ACKED-INJECTION lines this tree's manifest carries
    so the human re-review is real even when no live HALT re-fires. Own try/except,
    never raises (consumer-safety)."""
    try:
        manifest = repo / QUARANTINE_DIR / MANIFEST
        if not manifest.is_file():
            return
        lines = [ln for ln in manifest.read_text(errors="replace").splitlines()
                 if ln.startswith("ACKED-INJECTION")]
        if lines:
            print(f"NOTE: this tree carries {len(lines)} previously-ack'd injection "
                  f"finding(s) — re-review {QUARANTINE_DIR}/{MANIFEST}:", file=sys.stderr)
            for ln in lines[:20]:
                print(f"  {ln}", file=sys.stderr)
    except Exception:
        pass


def scan_injection(repo: Path, targets=()):
    """Whole-repo static prompt-injection content scan. Returns
    (warns: list[str], halts: list[Halt]) where
    Halt = (rel:str, line:int, category:str, rule_id:str, snippet:str, mode:str).

    CRASH != DETECTION: ONE outer `try/except Exception: return ([], [])` (does NOT
    catch KeyboardInterrupt/SystemExit). Regex compiled LAZILY inside the try, so a
    bad pattern fails open. Two passes: (1) STRICT-target pass FIRST under its OWN
    bounded budget (walks DIR targets, never read_text on a dir); (2) bulk pass
    under the global byte budget, pruning dir targets from os.walk + skipping file
    targets by .resolve()."""
    try:
        compiled: dict[str, "re.Pattern"] = {}

        def _pat(rule_id: str, rx: str):
            p = compiled.get(rule_id)
            if p is None:
                p = re.compile(rx)
                compiled[rule_id] = p
            return p

        warns: list[str] = []
        halts: list = []
        # Per-(rule_id, rel) emit count, to cap at INJ_PER_FILE_CAP + "+K more".
        emitted: dict[tuple, int] = {}

        def _scan_file(p: Path, rel: Path) -> None:
            mode = _scan_mode(rel)
            relstr = str(rel)
            try:
                if p.stat().st_size > MAX_CONTENT_BYTES:
                    warns.append(f"INJECTION-WARN size-guard {relstr} — "
                                 f"> {MAX_CONTENT_BYTES} bytes, content scan skipped")
                    return
                with p.open("rb") as fh:
                    head = fh.read(4096)
                if b"\x00" in head:
                    return  # binary
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return
            for lineno, line in enumerate(text.splitlines(), 1):
                # Scan the FULL line — NO windowing/truncation. The earlier 4096-byte
                # window was a ReDoS bound, but every INJECTION_RULES pattern is
                # linear-time by construction (no nested unbounded quantifiers /
                # backreferences — proven by the ReDoS test), and the file is already
                # capped at MAX_CONTENT_BYTES, so a full-line re.search is O(n) and
                # safe. Full-line scanning is also strictly MORE correct than windowing,
                # which (a) let a payload past col 4096 escape, (b) let a wide match
                # straddling a window boundary match in NEITHER window, and (c) made an
                # `^`-anchored rule (RH-006) false-match at every mid-line window start.
                for rule_id, category, rx, halt_scope, _note in INJECTION_RULES:
                    m = _pat(rule_id, rx).search(line)
                    if not m:
                        continue
                    key = (rule_id, relstr)
                    seen = emitted.get(key, 0)
                    if seen >= INJ_PER_FILE_CAP:
                        if seen == INJ_PER_FILE_CAP:
                            emitted[key] = seen + 1
                            warns.append(f"INJECTION-WARN {category} {relstr} — "
                                         "+more hits in this file (capped)")
                        continue
                    emitted[key] = seen + 1
                    # Bound the snippet slice so a multi-MB line can't force a huge
                    # .strip() allocation; normal lines keep the from-line-start excerpt.
                    if len(line) <= INJ_MAX_LINE_BYTES:
                        excerpt = line.strip()[:160]
                    else:
                        excerpt = line[m.start():m.start() + 200].strip()[:160]
                    is_halt = (halt_scope == "ALWAYS" and mode in ("STRICT", "STANDARD")) \
                        or (halt_scope == "STRICT" and mode == "STRICT")
                    if is_halt:
                        halts.append((relstr, lineno, category, rule_id, excerpt, mode))
                    else:
                        warns.append(f"INJECTION-WARN {category} {relstr}:{lineno} — {_defang(excerpt)}")

        # --- pass 1: STRICT-target pass, OWN bounded budget --------------------
        pass1_bytes = 0
        pass1_files = 0
        pass1_exhausted = False
        skip_resolved: set = set()
        prune_resolved: set = set()
        for t in targets:
            try:
                t_is_dir = t.is_dir() and not t.is_symlink()
            except OSError:
                continue
            if t_is_dir:
                try:
                    prune_resolved.add(t.resolve())
                except OSError:
                    pass
                if pass1_exhausted:
                    continue
                for dirpath, dirnames, filenames in os.walk(t):
                    dp = Path(dirpath)
                    dirnames[:] = [d for d in dirnames if d != ".git"]
                    for nm in filenames:
                        fp = dp / nm
                        if fp.is_symlink():
                            continue
                        try:
                            rel = fp.relative_to(repo)
                        except ValueError:
                            continue
                        if not _is_text_target(rel):
                            continue
                        pass1_files += 1
                        try:
                            pass1_bytes += fp.stat().st_size
                        except OSError:
                            pass
                        if pass1_files > INJ_PASS1_FILE_CAP or pass1_bytes > INJ_PASS1_BYTE_BUDGET:
                            pass1_exhausted = True
                            break
                        _scan_file(fp, rel)
                    if pass1_exhausted:
                        break
            else:
                if t.is_symlink():
                    continue
                try:
                    skip_resolved.add(t.resolve())
                except OSError:
                    pass
                try:
                    rel = t.relative_to(repo)
                except ValueError:
                    continue
                if not _is_text_target(rel):
                    continue
                if pass1_exhausted:
                    continue
                pass1_files += 1
                try:
                    pass1_bytes += t.stat().st_size
                except OSError:
                    pass
                if pass1_files > INJ_PASS1_FILE_CAP or pass1_bytes > INJ_PASS1_BYTE_BUDGET:
                    pass1_exhausted = True
                else:
                    _scan_file(t, rel)
        if pass1_exhausted:
            warns.append("INJECTION-WARN pass1-budget-exhausted — target files "
                         "unscanned; review the agent-config/quarantine dirs manually")

        # --- pass 2: bulk walk under the global byte budget -------------------
        qroot = repo / QUARANTINE_DIR
        try:
            prune_resolved.add(qroot.resolve())
        except OSError:
            pass
        bulk_bytes = 0
        bulk_exhausted = False
        for dirpath, dirnames, filenames in os.walk(repo):
            dp = Path(dirpath)
            if dp == repo:
                dirnames[:] = [d for d in dirnames if d != ".git"]
            # Dir-level prune: never DESCEND a STRICT-target dir / .git / .quarantine.
            kept = []
            for d in dirnames:
                sub = dp / d
                try:
                    r = sub.resolve()
                except OSError:
                    r = None
                if r is not None and r in prune_resolved:
                    continue
                kept.append(d)
            dirnames[:] = kept
            for nm in filenames:
                fp = dp / nm
                if fp.is_symlink():
                    continue
                try:
                    r = fp.resolve()
                except OSError:
                    r = None
                if r is not None and r in skip_resolved:
                    continue  # already scanned in pass 1
                try:
                    rel = fp.relative_to(repo)
                except ValueError:
                    continue
                if not _is_text_target(rel):
                    continue
                try:
                    sz = fp.stat().st_size
                except OSError:
                    sz = 0
                bulk_bytes += sz
                if bulk_bytes > INJ_BULK_BYTE_BUDGET:
                    bulk_exhausted = True
                    break
                _scan_file(fp, rel)
            if bulk_exhausted:
                break
        if bulk_exhausted:
            warns.append("INJECTION-WARN scan-budget-exhausted — files unscanned; "
                         "review manually")

        return warns, halts
    except Exception:
        return [], []


def find_targets(repo: Path, folder_mode: bool = False) -> list[Path]:
    """DFS enumeration of quarantine targets. An OSError during iterdir() is
    reported as a warning and the offending directory is skipped, rather than
    crashing the whole run.

    Git mode skips `.git` by name at any depth (git internals / submodule
    gitlinks are trusted). Folder mode instead EMITS every `.git` (dir or gitlink
    file, any depth) as a quarantine target — a repo-shipped `.git/` is hostile
    (its hooks would auto-run, its forged sentinel would dodge --check). A `.git`
    DIR is a single wholesale move-unit (NOT descended to emit nested targets —
    that would collide with the wholesale move; quarantine() suffixes its
    contents). The fail-closed scanners cover its interior at full depth.

    Intentionally NOT depth-bounded: the fail-closed structural scanners
    (find_symlinks, scan_filenames) walk the same full tree unbounded, so a
    depth cap here would only create an asymmetric silent-skip gap (a trigger
    buried below the cap would ride through a still-passing run). The explicit
    stack means deep trees cost time, not stack overflow.

    TOCTOU NOTE: there is an inherent race between this scan and the quarantine()
    rename step — a hostile process could add a trigger file in the window between
    find_targets returning and quarantine() moving things. This is acceptable: the
    defense is layered (the isolation boundary), re-running sanitize converges the tree, and
    --check re-derives state from scratch so post-sanitize mutations are caught."""
    qroot = repo / QUARANTINE_DIR
    targets: list[Path] = []
    stack: list[Path] = [repo]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(cur.iterdir())
        except OSError as e:
            print(f"warning: could not read {cur.relative_to(repo)}: {e}", file=sys.stderr)
            continue
        for entry in entries:
            name = entry.name
            # Skip `.quarantine` ONLY at the repo root (our own output). A
            # NESTED `.quarantine/` is hostile content — descend into it so its
            # trigger files get quarantined like any other directory, rather
            # than skipping it by name and letting it hide a CLAUDE.md.
            if entry == qroot:
                continue
            # `.git` (any depth): git mode trusts and skips it; folder mode
            # quarantines it wholesale (a dir is a single move-unit, not
            # descended; a gitlink FILE is quarantined as a file).
            if name == ".git":
                if folder_mode:
                    targets.append(entry)
                continue
            if entry.is_symlink():
                # Never traverse or move through symlinks; with the plan's
                # core.symlinks=false clone these are plain files anyway.
                continue
            if entry.is_dir():
                if name in DIR_NAMES:
                    targets.append(entry)
                else:
                    stack.append(entry)
            else:
                if name in FILE_NAMES or any(entry.match(g) for g in GLOB_PATTERNS):
                    targets.append(entry)
    return sorted(targets)


def _free_name(path: Path) -> Path:
    """`path` if free, else `path.1`, `path.2`, ... — so a quarantine rename
    NEVER clobbers an existing file (POSIX rename replaces silently; a repo
    shipping both `x` and `x.quarantined.txt` could otherwise destroy evidence,
    breaking the never-delete guarantee)."""
    if not path.exists():
        return path
    n = 1
    while True:
        cand = path.with_name(f"{path.name}.{n}")
        if not cand.exists():
            return cand
        n += 1


def _quarantine_intruders(qroot: Path) -> list[Path]:
    """Files inside our own `.quarantine/` that we did NOT put there — anything
    that is neither the MANIFEST nor a `*.quarantined.txt` output. A live trigger
    dropped in here after a prior sanitize lands in this set. Shared by `--check`
    (which flags them) and the sanitize sweep (which suffixes them), so the two
    never disagree.

    Files-only on purpose. A foreign DIRECTORY dropped into `.quarantine/` is
    handled through its files: any live (non-suffixed) file inside it is returned
    here and suffixed by the sweep, which converges --check. We deliberately do
    NOT flag the directory itself — a directory we legitimately quarantined sits
    directly under qroot under its ORIGINAL name (quarantine() suffixes a moved
    dir's CONTENTS, not the dir name), so name-based dir flagging cannot tell our
    own output from an intruder and would false-flag every quarantined `.vscode`/
    `.husky`/… — breaking both --check and re-run convergence. An empty foreign
    dir, or one holding only already-suffixed (already-inert) files, carries no
    live trigger and needs no action."""
    if qroot.is_symlink() or not qroot.is_dir():
        return []  # never follow a symlinked `.quarantine` (caught as a symlink)
    return [f for f in sorted(qroot.rglob("*"))
            if f.is_file() and not f.is_symlink() and f.name != MANIFEST
            and not _OUTPUT_SUFFIX_RE.search(f.name)]


def quarantine(repo: Path, targets: list[Path], dry_run: bool) -> list[str]:
    qroot = repo / QUARANTINE_DIR
    lines = []
    for t in targets:
        rel = t.relative_to(repo)
        if t.is_dir():
            dest = qroot / rel
            if not dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest = _free_name(dest)
                t.rename(dest)
                # Suffix every file inside the moved directory so nothing in it
                # keeps an actionable name/extension — collision-safe so a
                # pre-existing `*.quarantined.txt` twin can't be overwritten.
                for f in sorted(dest.rglob("*")):
                    if f.is_file() and not f.name.endswith(SUFFIX):
                        f.rename(_free_name(f.with_name(f.name + SUFFIX)))
                shown = dest.relative_to(repo)  # actual (post-collision) dest
            else:
                shown = Path(QUARANTINE_DIR) / rel
            lines.append(f"DIR  {rel} -> {shown}/ (contents suffixed)")
        else:
            dest = (qroot / rel).with_name((qroot / rel).name + SUFFIX)
            if not dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest = _free_name(dest)
                t.rename(dest)
                shown = dest.relative_to(repo)  # actual (post-collision) dest
            else:
                shown = Path(f"{QUARANTINE_DIR}/{rel}{SUFFIX}")
            lines.append(f"FILE {rel} -> {shown}")
    return lines


def _sweep_intruders(repo: Path, dry_run: bool) -> list[str]:
    """Suffix any live (non-suffixed, non-MANIFEST) file that ended up inside our
    own root `.quarantine/` after a prior sanitize — e.g. dropped there post-run.
    Uses the same predicate as `--check` so re-running sanitize clears exactly
    what the freshness gate flags (convergence). No-op on a clean tree."""
    lines: list[str] = []
    for intruder in _quarantine_intruders(repo / QUARANTINE_DIR):
        if not dry_run:
            new = _free_name(intruder.with_name(intruder.name + SUFFIX))
            intruder.rename(new)
            shown = new.relative_to(repo)
        else:
            shown = Path(f"{intruder.relative_to(repo)}{SUFFIX}")
        lines.append(f"SWEPT (intruder in .quarantine/) "
                     f"{intruder.relative_to(repo)} -> {shown}")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", type=Path, help="path to the cloned repo to sanitize")
    ap.add_argument("--dry-run", action="store_true", help="report, move nothing")
    ap.add_argument("--check", action="store_true",
                    help="read-only freshness gate: exit 1 if any live symlink "
                         "or un-quarantined trigger file is present right now "
                         "(used by `coldclone push`/`coldclone check` so a tree "
                         "mutated after sanitize can't be moved); moves nothing")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress per-quarantine-item lines; print only the summary "
                         "and WARNs (WARNs are always shown regardless of --quiet)")
    ap.add_argument("--json", action="store_true",
                    help="for a sanitize run (NOT --check), emit a machine-readable "
                         "JSON block as the final stdout output (parseable with `jq` "
                         "for CI assertions); ignored under --check, whose result is "
                         "carried by the exit code")
    ap.add_argument("--ack-injection", action="store_true",
                    help="acknowledge & override a tier-2 prompt-injection HALT after "
                         "reviewing the alert (HOST-side only; also settable via "
                         "COLDCLONE_ACK_INJECTION=1). Default is to HALT (exit 3).")
    ap.add_argument("--allow-no-git", action="store_true",
                    help="FOLDER MODE: sanitize a non-git directory (e.g. an extracted "
                         "ZIP). Default is to fail closed (exit 2) when there is no .git. "
                         "Folder mode skips the host-controlled sentinel ENTIRELY (so it "
                         "is non-idempotent — WARNs on rerun), refuses --check/push "
                         "eligibility, and actively quarantines any repo-shipped .git/ at "
                         "any depth (its hooks would auto-run; its sentinel would be "
                         "forgeable). NEVER defaulted — an explicit operator override, "
                         "like --ack-injection.")
    args = ap.parse_args()
    folder_mode = args.allow_no_git

    # Tier-2 injection ack — read ONCE, here, HOST-side only; never re-exported to
    # a child process. No persisted ack state (v1) -> no forgeable ack surface.
    acked = args.ack_injection or os.environ.get("COLDCLONE_ACK_INJECTION") == "1"

    repo = args.repo.resolve()
    # No-git gate: a missing `.git` is a tier-1 fail-closed (exit 2) UNLESS the
    # operator explicitly opts into folder mode with --allow-no-git. Auto-
    # detecting "no .git -> folder mode" is rejected — it would silently downgrade
    # the fail-closed into a fail-OPEN. Folder mode is opt-in only.
    if not (repo / ".git").exists() and not folder_mode:
        print(f"error: {repo} does not look like a git clone (no .git)", file=sys.stderr)
        return 2

    # FOLDER MODE + --check: refuse BEFORE the `if args.check:` block below, which
    # calls sentinel_path() — on a gitlink `.git` FILE that resolver follows
    # attacker-chosen `gitdir:` bytes to a path OUTSIDE the tree. Folder mode has
    # no trustworthy sentinel, so --check is structurally unsupported here; refuse
    # without ever touching sentinel_path.
    if folder_mode and args.check:
        print("error: --check is not supported in folder mode (--allow-no-git): a "
              "non-git folder has no host-controlled sentinel, so there is no "
              "unforgeable proof a sanitize ran. Sanitize and read the tree in "
              "place, or use a git source to gate a sandbox push.", file=sys.stderr)
        return 1

    # --check: the push freshness gate. Authority is NOT the in-tree sentinel
    # (which is the public OWNER_MARKER and a shipped `.git/` can forge it): it is
    # (a) the Layer C `.git`-is-a-DIRECTORY eligibility, (b) the Layer A
    # `.git`-hygiene gate (refuses a forged tree carrying live hooks / exec
    # config), (c) the out-of-tree provenance record (filesystem-identity-keyed,
    # never enters any tree), AND (d) a fresh re-scan finding no live symlink /
    # un-quarantined trigger. The sentinel is a non-authoritative fast-path hint.
    if args.check:
        # Layer C eligibility FIRST — BEFORE sentinel_path(), which on a gitlink
        # FILE would follow attacker-chosen `gitdir:` bytes. Require a DIRECTORY
        # `.git`; refuse a gitlink-FILE root.
        if not (repo / ".git").is_dir() or (repo / ".git").is_symlink():
            print("error: worktree/gitlink `.git` not supported — re-fetch as a "
                  "standalone clone, or `sanitize-folder`. check/push require a "
                  ".git DIRECTORY at the repo root.", file=sys.stderr)
            return 1
        # Layer A: required `.git`-hygiene gate (forged-`.git` archive / injected
        # hooks are refused here regardless of any sentinel).
        hyg = run_git_hygiene(repo)
        if hyg is not None:
            print(f"error: .git hygiene gate refused this tree — {hyg}. "
                  f"{_GIT_HYGIENE_REMEDIATION}", file=sys.stderr)
            return 1
        # Layer B: require a matching out-of-tree provenance record. A state-dir
        # anomaly fails CLOSED (exit 2 structural). A forged ZIP at a fresh
        # path/inode has no record → refuse.
        try:
            if not _state_lookup(repo):
                print("error: no host provenance record for this tree — it was not "
                      "sanitized by coldclone on this host (or was moved across "
                      "filesystems / replaced). Re-run `coldclone sanitize` here.",
                      file=sys.stderr)
                return 1
        except StateError as e:
            print(f"error: host state dir failed validation — {e}", file=sys.stderr)
            return EXIT_STRUCTURAL
        sent = sentinel_path(repo)
        if sent is None:
            print("error: cannot locate git dir sentinel path (gitlink resolution failed) — "
                  "verify this is a standard clone", file=sys.stderr)
            return 1
        if not sent.exists():
            print("error: not sanitized (no sentinel) — run sanitize first",
                  file=sys.stderr)
            return 1
        # Verify sentinel CONTENT as a NON-AUTHORITATIVE fast-path sanity hint —
        # its content is the PUBLIC OWNER_MARKER, so a shipped `.git/` can forge
        # it byte-for-byte. The real authority (Layers A/B/C above) has already
        # run; this is a cheap "looks like we wrote it" check, not the gate.
        try:
            sentinel_content = sent.read_text()
        except OSError as e:
            print(f"error: could not read sentinel {sent}: {e}", file=sys.stderr)
            return 1
        if not sentinel_content.startswith(OWNER_MARKER):
            print("error: sentinel exists but content is unexpected — possibly tampered",
                  file=sys.stderr)
            return 1

        # Fail FAST on real symlinks, before touching the tree further — never
        # walk a symlink target during the read-only gate.
        syms = find_symlinks(repo)
        if syms:
            print("error: tree is NOT sanitized as-is — real symlinks present:",
                  file=sys.stderr)
            for s in syms[:20]:
                print(f"  symlink: {s.relative_to(repo)}", file=sys.stderr)
            return 1
        # Fail-closed filename codepoints gate --check too (parity with sanitize).
        # WARN-only conditions (non-ASCII / case-collision) deliberately do NOT —
        # a tree with a CJK filename must still pass the push gate.
        fatal, _warn = scan_filenames(repo)
        if fatal:
            print("error: tree is NOT sanitized as-is — forbidden filename codepoints:",
                  file=sys.stderr)
            for p, lab in fatal[:20]:
                print(f"  {lab}: {p.relative_to(repo)!r}", file=sys.stderr)
            return 1
        tgts = find_targets(repo)
        # find_targets skips the root `.quarantine/`; verify it contains ONLY
        # our own output (MANIFEST + suffixed files) so a live trigger dropped
        # in there AFTER sanitize can't ride through the freshness gate. Same
        # predicate the sanitize sweep uses, so "re-run sanitize" actually
        # clears what this flags.
        intruders = _quarantine_intruders(repo / QUARANTINE_DIR)
        if tgts or intruders:
            print("error: tree is NOT sanitized as-is — re-run sanitize. Live items:",
                  file=sys.stderr)
            for t in tgts[:20]:
                print(f"  trigger: {t.relative_to(repo)}", file=sys.stderr)
            for x in intruders[:20]:
                print(f"  non-quarantined file inside .quarantine/: {x.relative_to(repo)}",
                      file=sys.stderr)
            return 1

        # Tier-2 injection re-scan (drift guard). HONEST COVERAGE NOTE: on a
        # sanitized tree the STRICT agent-config files are ALREADY quarantine
        # targets (renamed under .quarantine/, which the scanner skips), so
        # find_targets()==[] for them. Therefore --check injection HALTs fire for
        # ALWAYS-tier rules only (over left-live STANDARD source); the STRICT-tier
        # half of the matrix is structurally unreachable here. NOT a hole: a
        # post-sanitize RE-INTRODUCED agent-config trips the T1 intruder gate
        # (return 1, above) FIRST. We deliberately do NOT re-enter .quarantine/.
        inj_warns, inj_halts = scan_injection(repo, targets=find_targets(repo))
        if inj_halts and not acked:
            _print_injection_alert_safe(inj_halts)
            print("refusing: high-confidence prompt-injection re-detected — review "
                  "the alert above, then re-run with --ack-injection once confirmed "
                  "benign.", file=sys.stderr)
            return EXIT_INJECTION_HALT
        # Surface any ACKED-INJECTION provenance this tree's manifest carries (the
        # G4 audit checkpoint), and advisory injection WARNs, to stderr.
        _print_acked_injection_record(repo)
        if inj_warns:
            print("POTENTIAL PROMPT-INJECTION (advisory — review before pointing an "
                  "LLM here):", file=sys.stderr)
            for w in inj_warns:
                print(f"  {w}", file=sys.stderr)

        # Emit content WARNs to stderr so they appear in the CI log even when
        # --check passes. These are fail-open (do not gate the push) but should
        # not be silently dropped — the skim step depends on them.
        content_warns = scan_content_warn(repo)
        if content_warns:
            print("content WARNs (informational — do not block push):", file=sys.stderr)
            for w in content_warns:
                print(f"  {w}", file=sys.stderr)
        return 0

    # FAIL CLOSED on any real symlink. The whole symlink defense rests on the
    # clone having been made with `core.symlinks=false` (symlinks land as plain
    # text files, so `scp -r` can't follow one to a host file). If real symlinks
    # exist, that clone-time guard was skipped — refuse to sanitize (and thus
    # refuse to write the push sentinel) rather than bless an exfiltration-capable
    # tree. A hostile `.quarantine` symlink is caught here too.
    syms = find_symlinks(repo, folder_mode=folder_mode)
    if syms:
        if folder_mode:
            # A ZIP folder has no "reclone with core.symlinks=false" remedy.
            print(
                "error: real symlinks present in this folder — re-extract the "
                "archive without following/creating symlinks, or delete the "
                "offending links, before sanitizing. Offending:",
                file=sys.stderr,
            )
        else:
            print(
                "error: real symlinks present — this tree was NOT cloned with "
                "core.symlinks=false; reclone with "
                "`git clone -c core.symlinks=false ...` (coldclone fetch does "
                "this) so symlinks become inert plain files. Offending:",
                file=sys.stderr,
            )
        for s in syms[:20]:
            print(f"  {s.relative_to(repo)} -> {os.readlink(s)}", file=sys.stderr)
        if len(syms) > 20:
            print(f"  ... and {len(syms) - 20} more", file=sys.stderr)
        return 2

    # FAIL CLOSED on forbidden filename codepoints (control / bidi / zero-width) —
    # pure review-evasion with no honest use; refuse BEFORE any rename and before
    # the sentinel write, same posture as symlinks. The WARN-only results
    # (non-ASCII / case-collision) are collected here and folded into the manifest
    # below. NUL cannot occur in a POSIX filename, so no NUL-specific handling.
    fatal, filename_warns = scan_filenames(repo, folder_mode=folder_mode)
    if fatal:
        print("error: forbidden filename codepoints (control/bidi/zero-width — "
              "review-evasion); refusing to sanitize. Offending:", file=sys.stderr)
        for p, lab in fatal[:20]:
            print(f"  {lab}: {p.relative_to(repo)!r}", file=sys.stderr)
        if len(fatal) > 20:
            print(f"  ... and {len(fatal) - 20} more", file=sys.stderr)
        return 2

    # GIT MODE: Layer C eligibility + Layer A hygiene gate — BEFORE the
    # sentinel_path() call below (which consumes gitlink bytes) and BEFORE writing
    # any sentinel/record. A tree that fails is REFUSED (not sanitized, not
    # minted), closing the minting hole (a forged-`.git` tree must not get
    # provenance). Folder mode quarantines a repo-shipped `.git/` wholesale, so
    # this gate is git-mode only. find_symlinks/scan_filenames above are safe in
    # git mode (they prune `.git`).
    if not folder_mode:
        # Layer C: require a DIRECTORY `.git` root; refuse a gitlink-FILE root.
        gd = repo / ".git"
        if not gd.is_dir() or gd.is_symlink():
            print("error: worktree/gitlink `.git` not supported — re-fetch as a "
                  "standalone clone, or `sanitize-folder`. sanitize/check/push "
                  "require a .git DIRECTORY at the repo root.", file=sys.stderr)
            return 1
        # Layer A: hygiene gate (mode-aware remediation).
        hyg = run_git_hygiene(repo)
        if hyg is not None:
            print(f"error: .git hygiene gate refused this tree — {hyg}. "
                  f"{_GIT_HYGIENE_REMEDIATION}", file=sys.stderr)
            return 1

    # Have we sanitized this clone before? Tracked by the in-tree git sentinel
    # (a non-authoritative fast-path idempotency hint) — NOT by the worktree
    # manifest, which the repo could forge to masquerade a repo-shipped
    # `.quarantine/` as ours.
    #
    # FOLDER MODE skips the sentinel codepath ENTIRELY — no sentinel_path() call
    # (it would resolve attacker `gitdir:` bytes on a repo-shipped gitlink FILE),
    # no read, no write. `already_ran` is pinned FALSE, so every pre-existing
    # `.quarantine/` is treated as foreign and stashed (folder mode is one-shot
    # by design; see the rerun WARN below).
    if folder_mode:
        sentinel = None
        already_ran = False
    else:
        sentinel = sentinel_path(repo)
        if sentinel is None:
            print("warning: cannot locate git dir sentinel path (gitlink resolution failed); "
                  "idempotency may be degraded — treating as first run", file=sys.stderr)
        already_ran = sentinel is not None and sentinel.exists()

    # Enumerate normal targets FIRST — the walk skips the root `.quarantine/`,
    # so a foreign quarantine is not descended into here. Do this before any
    # rename so we never queue children of the stash (which would collide with
    # the whole-stash move below). In folder mode this ALSO emits any
    # repo-shipped `.git` (dir or gitlink file, any depth) as a target.
    targets = find_targets(repo, folder_mode=folder_mode)

    # --- TIER 2: prompt-injection HALT/WARN — seam pinned BEFORE any filesystem
    # mutation (after find_targets + already_ran; BEFORE the preseeded rename at
    # the block below). The preseeded block RENAMES a repo-shipped `.quarantine/`
    # to a stash, which would move the highest-signal STRICT targets off their
    # live paths — so the scan MUST run first. STRICT-target input includes the
    # repo-shipped `.quarantine/` body when present (walked as a DIR target in
    # pass 1) so a CLAUDE.md hidden inside it still HALTs.
    qroot_pre = repo / QUARANTINE_DIR
    strict_scan_targets = list(targets)
    if qroot_pre.exists() and not qroot_pre.is_symlink() and not already_ran:
        strict_scan_targets.append(qroot_pre)
    inj_warns, inj_halts = scan_injection(repo, targets=strict_scan_targets)
    if inj_halts and not acked:
        _print_injection_alert_safe(inj_halts)
        if args.json:
            try:
                print(json.dumps({
                    "repo": str(repo),
                    "mode": "folder" if folder_mode else "git",
                    "trusted_sentinel": False,  # in-tree sentinel is a NON-authoritative hint now (Layer B host record is the authority); check_push_supported is the real signal
                    "check_push_supported": not folder_mode,
                    "injection_halted": True,
                    "halt_count": len(inj_halts),
                    "halts": [{"rel": h[0], "line": h[1], "category": h[2],
                               "rule_id": h[3], "snippet": h[4], "mode": h[5]}
                              for h in inj_halts],
                    "ack_required": True,
                    "quarantined_count": None,
                    "items": None,
                    "warnings": None,
                }, indent=2))
            except Exception:
                pass
        else:
            print("refusing to sanitize: high-confidence prompt-injection — review "
                  "the above, then re-run with --ack-injection (or "
                  "COLDCLONE_ACK_INJECTION=1) once you have confirmed it is benign.",
                  file=sys.stderr)
        return EXIT_INJECTION_HALT
    # acked OR no halts -> continue (preseeded rename + quarantine + sentinel run).

    # A worktree `.quarantine/` is foreign UNLESS we've run before. On a fresh
    # clone we never wrote one, so any pre-existing `.quarantine/` is
    # repo-supplied (possibly with a forged owner-marker manifest) — move it
    # aside as a SINGLE target so its contents get suffixed and recorded,
    # never mistaken for sanitizer output. On a rerun (sentinel present) the
    # `.quarantine/` is ours; leave it.
    preseeded = False
    qroot = repo / QUARANTINE_DIR
    if qroot.exists() and not qroot.is_symlink() and not already_ran:
        preseeded = True
        # A hostile repo can also pre-create REPO-SUPPLIED-quarantine; pick
        # a free name so the rename can't collide.
        stash = repo / "REPO-SUPPLIED-quarantine"
        n = 0
        while stash.exists():
            n += 1
            stash = repo / f"REPO-SUPPLIED-quarantine-{n}"
        if not args.dry_run:
            qroot.rename(stash)
            targets.append(stash)
        else:
            targets.append(qroot)

    lines = quarantine(repo, targets, args.dry_run)
    if preseeded:
        lines.insert(0, f"WARNING: repo shipped its own .quarantine/ — quarantined as "
                        f"{stash.name}/ (treat with suspicion)")
        if folder_mode:
            # Folder mode has no sentinel, so EVERY run re-stashes a pre-existing
            # `.quarantine/` as foreign — including our OWN output from a prior
            # folder-mode run. Folder mode is one-shot by design; prefer
            # sanitizing a fresh extraction over re-sanitizing in place.
            lines.insert(1, "WARNING: folder mode is one-shot (no idempotency sentinel) — "
                            "a pre-existing .quarantine/ is re-stashed as foreign on every "
                            "run; sanitize a FRESH extraction rather than re-running here.")

    # Sweep any live (non-suffixed, non-MANIFEST) file that ended up inside our
    # own root `.quarantine/` — e.g. dropped there after a prior sanitize. This
    # makes a re-run actually clear what `--check` flags (same files-only
    # predicate), so the freshness gate's "re-run sanitize" remediation
    # converges. No-op on a clean tree.
    lines += _sweep_intruders(repo, args.dry_run)

    # Informational WARN lines: filename non-ASCII / case-collision (computed
    # above) + fail-open content WARNs over LEFT-LIVE files (foundry.toml ffi,
    # Anchor.toml [scripts], .gitmodules transports, …). These are NOT moves and
    # NOT gate failures; they ride the per-run manifest block as append-only
    # audit history.
    warn_lines = filename_warns + scan_content_warn(repo)

    if not args.dry_run:
        # Always write the manifest — step 5's skim reads it unconditionally,
        # so a clean repo must produce an explicit zero-items record rather
        # than a missing file. Consumer-safety (CRASH != DETECTION): the whole
        # manifest write is wrapped so an append failure DEGRADES to a warning,
        # never raises out of main() (else set -e in coldclone.sh would abort).
        try:
            qroot.mkdir(exist_ok=True)
            manifest = qroot / MANIFEST
            fresh = not manifest.exists()
            with manifest.open("a") as fh:
                if fresh:
                    fh.write(OWNER_MARKER + "\n")
                    if folder_mode:
                        # Provenance honesty: a folder-mode manifest is NOT an
                        # unforgeable sanitization proof (no host-controlled
                        # sentinel backs it — the worktree manifest is repo-
                        # writable). check/push are unsupported on this tree.
                        fh.write("# FOLDER MODE (--allow-no-git): this manifest is NOT an "
                                 "unforgeable sanitization proof — no git-dir sentinel "
                                 "backs it; coldclone check/push are unsupported here.\n")
                fh.write(f"RUN: mode={'folder' if folder_mode else 'git'}, "
                         f"trusted_sentinel=false, "  # non-authoritative in BOTH modes now; check_push_supported is the real signal
                         f"check_push_supported={'false' if folder_mode else 'true'}\n")
                fh.write(f"RUN: quarantined {len(lines)} item(s), "
                         f"{len(warn_lines)} warning(s)\n")
                if lines:
                    fh.write("\n".join(lines) + "\n")
                if warn_lines:
                    fh.write("\n".join(warn_lines) + "\n")
                # ACKED-INJECTION provenance (append-only audit record, NOT an ack
                # control): a tier-2 halt that the operator ack'd this run.
                if inj_halts and acked:
                    for h in inj_halts:
                        fh.write(f"ACKED-INJECTION {h[2]} {h[0]}:{h[1]}\n")
                if inj_warns:
                    fh.write("\n".join(inj_warns) + "\n")
        except Exception as e:
            print(f"warning: could not write manifest ({type(e).__name__}); "
                  "continuing", file=sys.stderr)
        # Layer B: mint the out-of-tree provenance record (git mode only — a
        # hygiene-passing git sanitize is the ONLY mint trigger). Record-FIRST,
        # then the in-tree sentinel. A state-dir anomaly fails CLOSED (exit 2):
        # we refuse to claim provenance we cannot safely record. This is inside
        # the `if not args.dry_run:` guard, so --dry-run never mints.
        if not folder_mode:
            try:
                _state_mint(repo)
            except StateError as e:
                print(f"error: host state dir failed validation — {e}", file=sys.stderr)
                return EXIT_STRUCTURAL
            except OSError as e:
                print(f"error: could not mint provenance record — {e}", file=sys.stderr)
                return EXIT_STRUCTURAL
        # Drop the in-tree sentinel (non-authoritative fast-path idempotency hint).
        if sentinel is not None:
            try:
                sentinel.write_text(OWNER_MARKER + "\n")
            except OSError as e:
                print(f"warning: could not write sentinel {sentinel}: {e}", file=sys.stderr)

    # When --json is set, route ALL human summary/item/warn/manifest/reminder
    # output to STDERR so STDOUT carries EXACTLY one JSON object — else
    # json.loads(stdout) breaks. (Parity with the halt path, which already keeps
    # stdout JSON-only.)
    hstream = sys.stderr if args.json else sys.stdout
    verb = "would quarantine" if args.dry_run else "quarantined"
    print(f"sanitize_repo: {verb} {len(lines)} item(s), {len(warn_lines)} warning(s) in {repo}",
          file=hstream)
    # --quiet suppresses per-quarantine-item lines; WARNs are always shown.
    if not args.quiet:
        for line in lines:
            print(f"  {line}", file=hstream)
    for w in warn_lines:
        print(f"  {w}", file=hstream)
    if (lines or warn_lines) and not args.dry_run:
        print(f"  manifest: {QUARANTINE_DIR}/{MANIFEST}", file=hstream)

    print(
        "reminder: deliberately LEFT LIVE (needed to read scope; fire only on a"
        " build/test tool that read-only review avoids): package.json scripts, Makefiles,"
        " foundry.toml (ffi), Anchor.toml, Cargo.toml, pyproject.toml, pom.xml,"
        " nx.json/turbo.json, slither.config.json, and .gitmodules (workflow-needed"
        " — submodule assembly reads it; content-WARN'd above, not quarantined)."
        " .gitattributes IS quarantined (no post-checkout reader).",
        file=hstream,
    )

    # TIER-2 advisory block: PROMINENT, distinct from the quiet structured WARNs.
    # When --json is set, ALL human alert/advisory text goes to STDERR so STDOUT
    # carries EXACTLY the final JSON object (attacker-controlled snippets may carry
    # `{`/`}`/quotes — they must not appear on the stdout a --json consumer parses).
    # An ack'd halt also prints its alert here so the operator sees what they ack'd.
    inj_stream = sys.stderr if args.json else sys.stdout
    if inj_halts and acked:
        _print_injection_alert_safe(inj_halts)
        print("(ACKED — proceeding past the above tier-2 prompt-injection HALT; "
              "recorded in the manifest.)", file=inj_stream)
    if inj_warns:
        print("POTENTIAL PROMPT-INJECTION (advisory — review before pointing an "
              "LLM here):", file=inj_stream)
        for w in inj_warns:
            print(f"  {w}", file=inj_stream)

    # Emit the machine-readable block LAST so a `--json` consumer can read the
    # final JSON object off stdout without the trailing reminder confusing a parser.
    if args.json:
        doc = {
            "repo": str(repo),
            "mode": "folder" if folder_mode else "git",
            "trusted_sentinel": False,  # in-tree sentinel is a NON-authoritative hint now (Layer B host record is the authority); check_push_supported is the real signal
            "check_push_supported": not folder_mode,
            "dry_run": args.dry_run,
            "quarantined_count": len(lines),
            "warning_count": len(warn_lines),
            "items": lines,
            "warnings": warn_lines,
            "injection_halted": bool(inj_halts) and not acked,
            "halt_count": len(inj_halts),
            "halts": [{"rel": h[0], "line": h[1], "category": h[2],
                       "rule_id": h[3], "snippet": h[4], "mode": h[5]}
                      for h in inj_halts],
            "ack_required": bool(inj_halts) and not acked,
            "injection_warnings": inj_warns,
        }
        # Consumer-safety (H2 / parity with the halt-path emit): a raise in the
        # final emit must not propagate out of main() -> traceback -> nonzero exit
        # -> coldclone.sh `set -e` aborts. Degrade, never raise.
        try:
            print(json.dumps(doc, indent=2))
        except Exception:
            pass
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
