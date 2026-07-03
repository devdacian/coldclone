#!/usr/bin/env python3
"""ioc_scan.py — known-malicious-dependency tripwire for an untrusted repo.

Greps every discoverable lockfile in a freshly cloned untrusted repo for any
package name on the bundled IoC list (`ioc-list.txt` next to this script). A hit
means the repo declares a CONFIRMED-malicious dependency (typosquat, supply-chain
compromise, Lazarus/infostealer drop) — a strong signal the repo is hostile.

This runs FIRST in the coldclone flow, on the HOST, right after the hardened
clone and BEFORE sanitize + moving the tree into an isolation environment:

  - It only READS lockfiles (no install, no build, no code execution), so it is
    safe to run on an untrusted tree.
  - A hit HALTs prep (exit 2) so the repo is caught up front — the human decides
    whether to treat the repo as hostile or to examine it deliberately inside
    their isolation environment.

This is a NAME-exact denylist (high precision via exact identity matching; it
catches only KNOWN drops, and its few residual false positives fail SAFE — see
the accepted limitation below). It complements — never replaces — the
auto-execution sanitizer (`sanitize_repo.py`) and the isolation boundary.

Exit codes: 0 clean, 1 IoC-list stale (>7 days) but no hit, 2 IoC hit (HALT),
3 config error — the gate could not actually run, so FAIL CLOSED and HALT:
IoC list missing / unreadable / EMPTY, a discovered lockfile that could not be
scanned (unreadable, or a symlink we refuse to follow), or a bad repo path. Only
0 and 1 mean "no malicious dependency found — proceed" (1 also flags a stale or
header-less list). A repo with simply no lockfiles is legitimately clean -> 0.

Usage: python3 ioc_scan.py <repo-dir> [--ioc-list <path>]

Known limitation (accepted): the IoC list is not tagged by ecosystem, so a
slash-delimited path component (e.g. a go.sum module owner `github.com/<org>/...`)
is matched against the whole cross-ecosystem list. A benign module whose owner
equals an npm/PyPI IoC name can therefore false-HALT. This fails SAFE (a HALT
sends it to human review, never a miss) and the alternative — matching only the
last path component — would instead MISS go modules whose package is not the last
component (e.g. a `/v2` major-version suffix), which is worse for a tripwire. A
future per-entry ecosystem tag would let the match be scoped precisely.

Bundled with the open-source coldclone tool; self-contained (no external deps).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import date
from pathlib import Path

# Default: the bundled list shipped next to this script.
_DEFAULT_IOC_LIST = Path(__file__).resolve().parent / "ioc-list.txt"

# Lockfiles grepped, by ecosystem. Reading these is execution-free.
_LOCKFILE_NAMES = frozenset({
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "uv.lock",
    "requirements.txt",
    "Pipfile.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
})

# Python lockfiles. PyPI normalizes distribution names (PEP 503): case-insensitive
# and any run of `-`, `_`, `.` collapses to a single `-`. So `mnemonic_to_address`,
# `mnemonic-to-address`, and `Mnemonic.To.Address` are the SAME package. We apply
# that normalization ONLY when scanning these files — npm and cargo treat `_` vs
# `-` as DISTINCT packages, so normalizing there would create false matches.
_PYPI_LOCKFILES = frozenset({"requirements.txt", "poetry.lock", "Pipfile.lock",
                             "uv.lock"})


def _pep503(name: str) -> str:
    """PEP 503 normalized PyPI distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()

# Directories never traversed — installed artifacts / build outputs. Matching an
# IoC inside a vendored/installed tree is meaningless (you would not install an
# untrusted repo) and node_modules is huge. NOTE: we deliberately DO descend
# into `lib/` — vendored or submodule source (e.g. the assembled Foundry
# SUBMODULE SOURCE a repo ships under `lib/`) can commit a real malicious
# lockfile, and that is a signal worth catching.
_SKIP_DIRS = frozenset({
    "node_modules", "target", "dist", "build", "out", "cache", "artifacts",
    "typechain", "typechain-types", "vendor", "venv", ".venv", "__pycache__",
    ".git",
})

_STALE_DAYS = 7


def load_ioc_list(path: Path) -> tuple[frozenset[str], int | None]:
    """Parse the IoC list. Returns (ioc_set, stale_days_or_none).

    `stale_days` is days since the `LAST_REFRESHED: YYYY-MM-DD` header, or None
    if absent/malformed. Comment (`#`) and blank lines are skipped.
    """
    if not path.is_file():
        raise FileNotFoundError(f"IoC list not found at {path}")
    iocs: set[str] = set()
    last_refreshed: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("LAST_REFRESHED:"):
            last_refreshed = stripped.split(":", 1)[1].strip()
            continue
        if not stripped or stripped.startswith("#"):
            continue
        iocs.add(stripped)
    stale_days: int | None = None
    if last_refreshed:
        try:
            y, m, d = (int(x) for x in last_refreshed.split("-"))
            stale_days = (date.today() - date(y, m, d)).days
        except (ValueError, IndexError):
            stale_days = None
    return frozenset(iocs), stale_days


def discover_lockfiles(root: Path) -> tuple[list[Path], list[Path]]:
    """Discover lockfiles under `root`, skipping installed-artifact dirs and not
    following symlinks (os.walk does not follow symlinked dirs by default).
    Returns (regular, symlinked): a lockfile that is itself a SYMLINK is NOT read
    (following it could be unsafe/exfil) but is also NOT silently dropped — it is
    returned in `symlinked` so the caller can FAIL CLOSED, since a symlinked
    lockfile is an unscanned discovered lockfile. (In the hardened prep flow the
    clone uses core.symlinks=false, so lockfiles are plain files and this list is
    empty; the fail-close matters for the standalone `ioc <dir>` path.)"""
    found: list[Path] = []
    symlinked: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name in _LOCKFILE_NAMES:
                p = Path(dirpath) / name
                (symlinked if p.is_symlink() else found).append(p)
    return sorted(found), sorted(symlinked)


# A package-identifier-shaped run of characters (scope, name, path separators,
# version separator). We extract these tokens per line, then DERIVE candidate
# package identities from each and exact-match them against the IoC set — exact
# membership, not a boundary regex, so there is no substring false-positive tail.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_./@-]+")
_NM_MARKER = "node_modules/"


def _candidates(token: str):
    """Yield candidate package identities from one lockfile token.

    Handles the real lockfile encodings across every ecosystem we scan:
      - bare `name`, `name@version`                         (yarn/pnpm/requirements)
      - `@scope/name`, `@scope/name@version`                (scoped npm)
      - npm package-lock v3 keys `node_modules/<name>` and nested
        `.../node_modules/@scope/name`                      (the DEFAULT npm format)
      - pnpm `/<name>@ver` keys                             (leading slash)
      - slash-delimited paths, e.g. go.sum `host/owner/<name>`

    Scope safety: a scoped `@scope/name` yields ONLY `@scope/name`, never the bare
    `name`, so an unscoped IoC cannot false-match a differently-scoped package
    (`@other/node-loggers` does NOT trip IoC `node-loggers`). A non-scoped path
    DOES split into components, so `node_modules/node-loggers` and
    `github.com/x/formstash` resolve to `node-loggers` / `formstash`.
    """
    t = token.strip().strip("\"'")
    if not t:
        return
    # Strip a trailing @version. A version `@` is preceded by a NAME char; a SCOPE
    # `@` is at index 0 or preceded by `/` (`@scope/n`, `node_modules/@scope/n`),
    # so it must NOT be stripped. Find the last `@` whose previous char is not `/`.
    for i in range(len(t) - 1, 0, -1):
        if t[i] == "@" and t[i - 1] != "/":
            t = t[:i]
            break
    idx = t.rfind(_NM_MARKER)  # npm nesting: keep only the part after the LAST node_modules/
    if idx != -1:
        t = t[idx + len(_NM_MARKER):]
    t = t.strip("/")
    if not t:
        return
    yield t  # full identity: bare `name` OR `@scope/name`
    if not t.startswith("@"):
        # Path-y token (go module path, or a registry tarball URL like
        # `//registry.npmjs.org/@other/name/-/name-1.0.0.tgz`): each component is
        # its own identity, BUT keep an `@scope/name` pair together so an unscoped
        # IoC cannot false-match a scoped package's name embedded in a URL/path
        # (`@other/node-loggers` must NOT yield bare `node-loggers`).
        comps = [c for c in t.split("/") if c]
        i = 0
        while i < len(comps):
            if comps[i].startswith("@") and i + 1 < len(comps):
                yield f"{comps[i]}/{comps[i + 1]}"
                i += 2
            else:
                yield comps[i]
                i += 1


def ioc_grep(
    lockfiles: list[Path], iocs: frozenset[str]
) -> tuple[list[tuple[Path, str, int]], list[Path]]:
    """Scan each lockfile line-by-line. Returns (hits, unreadable) where hits are
    (lockfile, ioc, line_no) and `unreadable` lists any discovered lockfile that
    could not be read — the caller FAILS CLOSED on those (a discovered-but-
    unscanned lockfile means we cannot certify the repo clean)."""
    # Normalized view of the IoC set for PyPI matching (built once).
    iocs_pep503 = {_pep503(i): i for i in iocs}
    hits: list[tuple[Path, str, int]] = []
    unreadable: list[Path] = []
    for lf in lockfiles:
        try:
            text = lf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable.append(lf)
            continue
        is_pypi = lf.name in _PYPI_LOCKFILES
        for line_no, line in enumerate(text.splitlines(), start=1):
            seen: set[str] = set()  # dedupe repeats within one line
            for tok in _TOKEN_RE.findall(line):
                for cand in _candidates(tok):
                    matched = None
                    if cand in iocs:
                        matched = cand
                    elif is_pypi:  # PEP 503: hyphen/underscore/dot + case insensitive
                        matched = iocs_pep503.get(_pep503(cand))
                    if matched and matched not in seen:
                        hits.append((lf, matched, line_no))
                        seen.add(matched)
    return hits, unreadable


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", type=Path, help="path to the cloned repo to scan")
    ap.add_argument("--ioc-list", type=Path, default=_DEFAULT_IOC_LIST,
                    help=f"IoC list file (default: {_DEFAULT_IOC_LIST})")
    args = ap.parse_args()

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"error: not a directory: {repo}", file=sys.stderr)
        return 3  # config error -> FAIL CLOSED (the caller must HALT, not proceed)

    try:
        iocs, stale_days = load_ioc_list(args.ioc_list)
    except (OSError, FileNotFoundError) as e:
        print(f"error: cannot read IoC list: {e}", file=sys.stderr)
        return 3  # the gate cannot run without its denylist -> FAIL CLOSED, never
                  # exit 1 (which the caller treats as "proceed"): a missing/
                  # unreadable list must HALT, not silently disable the gate.

    # An empty (truncated/corrupt) denylist cannot check anything -> FAIL CLOSED,
    # never report clean. A repo with no lockfiles, by contrast, is legitimately
    # clean (nothing to scan) and proceeds.
    if not iocs:
        print(f"error: IoC list {args.ioc_list} is empty — the gate cannot run; "
              f"refusing to certify clean", file=sys.stderr)
        return 3

    lockfiles, symlinked = discover_lockfiles(repo)
    hits, unreadable = ioc_grep(lockfiles, iocs)

    # A definitive HIT is the most informative outcome — report it first (still a
    # HALT). Both exit 2 (hit) and exit 3 (couldn't fully scan) stop prep.
    if hits:
        print("=" * 72, file=sys.stderr)
        print("MALICIOUS DEPENDENCY DETECTED — DO NOT PROCEED", file=sys.stderr)
        print("This repo declares a known-malicious package in a lockfile.",
              file=sys.stderr)
        print("Treat the repo as hostile; do not open it before going on.",
              file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        for lf, ioc, line_no in hits:
            print(f"  HIT: {ioc}  in  {lf.relative_to(repo)}:{line_no}",
                  file=sys.stderr)
        return 2

    # Discovered lockfiles we could not actually scan (unreadable, or a symlink we
    # refuse to follow) were NOT scanned -> FAIL CLOSED.
    unscanned = unreadable + symlinked
    if unscanned:
        print(f"error: {len(unscanned)} discovered lockfile(s) could not be scanned "
              f"(unreadable or a symlink) — cannot certify clean; failing closed:",
              file=sys.stderr)
        for lf in unscanned:
            kind = "symlink" if lf in symlinked else "unreadable"
            print(f"  {kind}: {lf.relative_to(repo)}", file=sys.stderr)
        return 3

    if stale_days is None or stale_days < 0:
        # Missing/malformed LAST_REFRESHED (None) OR a future date (negative delta,
        # e.g. a typo'd year): the denylist still works, but freshness — load-bearing
        # for this drift-prone bundled copy — cannot be trusted. Warn and proceed
        # (exit 1); never silently certify fresh-clean off an invalid header.
        reason = ("no valid LAST_REFRESHED header" if stale_days is None
                  else "a future-dated LAST_REFRESHED header")
        print(f"ioc_scan: clean ({len(lockfiles)} lockfile(s) scanned), but the IoC "
              f"list {args.ioc_list} has {reason} — freshness could not be "
              f"established; refresh/repair it", file=sys.stderr)
        return 1
    if stale_days > _STALE_DAYS:
        print(f"ioc_scan: clean ({len(lockfiles)} lockfile(s) scanned), but the "
              f"IoC list is {stale_days} days stale (>{_STALE_DAYS}d) — refresh it",
              file=sys.stderr)
        return 1

    print(f"ioc_scan: clean — no malicious dependencies in {len(lockfiles)} "
          f"lockfile(s) under {repo}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
