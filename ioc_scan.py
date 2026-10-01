#!/usr/bin/env python3
"""ioc_scan.py — known-malicious-dependency tripwire for an untrusted repo.

Greps every discoverable lockfile in a freshly cloned untrusted repo for any
package identity on the bundled IoC list (`ioc-list.txt` next to this script).
Plain entries are package-wide triggers for identities whose entire release
family is malicious (for example, typosquats). Structured VERSION records turn
an identity into an exact malicious-version denylist: a trusted exact version
not in that denylist is locally safe. When enabled, an exact OSV query can add a
malicious version that has not yet reached the bundled list. Unparseable or
structurally ambiguous version evidence cannot establish a safe version and
still halts.

This runs FIRST in the coldclone flow, on the HOST, right after the hardened
clone and BEFORE sanitize + moving the tree into an isolation environment:

  - It only READS lockfiles (no install, no build, no code execution), so it is
    safe to run on an untrusted tree.
  - A hit HALTs prep (exit 2) so the repo is caught up front — the human decides
    whether to treat the repo as hostile or to examine it deliberately inside
    their isolation environment.

This is an identity-and-version-exact denylist (high precision via exact
matching; it catches only KNOWN drops, and its few residual false positives fail
SAFE — see the accepted limitation below). Trusted exact-version evidence is
extracted locally from npm-family (package-lock, Yarn, pnpm, Bun text and
binary) and Cargo lockfiles. By default the scanner
also makes opportunistic exact-version OSV API queries for version-scoped
packages; `--offline` disables those queries. It complements — never replaces —
the auto-execution sanitizer
(`sanitize_repo.py`) and the isolation boundary.

Exit codes: 0 clean, 1 IoC-list stale (>7 days) but no hit, 2 IoC hit (HALT),
3 config error — the gate could not actually run, so FAIL CLOSED and HALT:
IoC list missing / unreadable / EMPTY / invalid, a discovered lockfile that
could not be scanned (unreadable, oversized, malformed structured data, or a
symlink we refuse to follow), or a bad repo path. Only 0 and 1 mean "no malicious dependency found — proceed" (1 also
flags a stale or header-less list). A repo with simply no lockfiles is
legitimately clean -> 0.

Usage: python3 ioc_scan.py <repo-dir> [--ioc-list <path>] [--offline]

Known limitation (accepted): plain package entries are not tagged by ecosystem,
so a slash-delimited path component (e.g. a go.sum module owner
`github.com/<org>/...`) is matched against the whole cross-ecosystem plain-name
list. A benign module whose owner equals an npm/PyPI IoC name can therefore
false-HALT. This fails SAFE (a HALT sends it to human review, never a miss) and
the alternative — matching only the last path component — would instead MISS go
modules whose package is not the last component (e.g. a `/v2` major-version
suffix), which is worse for a tripwire. Structured ecosystem tags scope exact
version evidence. A trusted exact version outside the recorded malicious set is
safe; legacy AFFECTED_SET_COMPLETE records are accepted as provenance but are
not needed to make that decision.

Bundled with the open-source coldclone tool; self-contained (no external deps).
"""

from __future__ import annotations

import argparse
import io
import itertools
import posixpath
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Callable, Mapping

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
    "bun.lock",
    "bun.lockb",
})

# Python lockfiles. PyPI normalizes distribution names (PEP 503): case-insensitive
# and any run of `-`, `_`, `.` collapses to a single `-`. So `mnemonic_to_address`,
# `mnemonic-to-address`, and `Mnemonic.To.Address` are the SAME package. We apply
# that normalization ONLY when scanning these files — npm and cargo treat `_` vs
# `-` as DISTINCT packages, so normalizing there would create false matches.
_PYPI_LOCKFILES = frozenset({"requirements.txt", "poetry.lock", "Pipfile.lock",
                             "uv.lock"})

_LOCKFILE_POLICY_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "bun.lockb": "npm",
    "Cargo.lock": "crates.io",
}


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
_OSV_API = "https://api.osv.dev/v1/query"
_OSV_TIMEOUT_SECONDS = 5
_OSV_RESPONSE_LIMIT = 4 * 1024 * 1024
_OSV_QUERY_LIMIT = 10
_LOCKFILE_SIZE_LIMIT = 8 * 1024 * 1024
_LOCKFILE_TOTAL_SIZE_LIMIT = 64 * 1024 * 1024
_LOCKFILE_COUNT_LIMIT = 1024
_DISCOVERY_ENTRY_LIMIT = 100_000
_VERSION_EXTRACTION_LIMIT_PER_LOCKFILE = 16
_YARN_BERRY_METADATA_VERSIONS = frozenset({"6", "8", "9"})
_OSV_MARKER_NODE_LIMIT = 100_000
_JSON_LOCKFILES = frozenset({
    "package-lock.json", "Pipfile.lock", "composer.lock",
})
_YAML_LOCKFILES = frozenset({"yarn.lock", "pnpm-lock.yaml"})
# Public registries a fresh npm/Yarn/pnpm/Bun install uses by default. Fetch
# URLs on any other host are surfaced as a non-gating advisory.
_DEFAULT_NPM_REGISTRY_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
_URL_SCHEME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-"
)
_URL_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
_URL_AUTHORITY_END_RE = re.compile(r"[/?#\\\s\"'<>{},]")
_YARN_BERRY_METADATA_RE = re.compile(
    r"^(?:__metadata|\"__metadata\"|'__metadata')\s*:", re.MULTILINE
)
_HOST_RE = re.compile(r"\[[0-9A-Fa-f:.]+\]|[^\s\"'<>{},:/?#\\\[\]]*")
_REMOTE_SOURCE_DISPLAY_LIMIT = 20
# Bun's text lockfile is JSON with comments and trailing commas (JSONC).
_JSONC_LOCKFILES = frozenset({"bun.lock"})
_BUN_LOCK_VERSIONS = frozenset({0, 1, 2})
_JSONC_LINE_COMMENT_END_RE = re.compile("[\n\r\u2028\u2029]")
_JSONC_WHITESPACE_RE = re.compile(r"\s+")
_URL_PATH_SPLIT_RE = re.compile(r"[/?#&=;:]")
_JSONC_PLAIN_RE = re.compile(r'[^\s"/,\[\]{}]+')
# Bun's binary lockfile (bun.lockb, Bun < 1.2 default). Layout per format:
# semver.Version is 48 bytes in format 2 (u32 major/minor/patch) and 56 bytes in
# format 3 (u64), which sizes the Resolution column of the package table.
_BUN_LOCKB_HEADER = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n"
_BUN_LOCKB_VERSION_SIZES = {2: 48, 3: 56}
# Package table columns, in serialized order: name String (8), name_hash u64
# (8), Resolution (16 + Version), dependencies slice (8), resolutions slice (8),
# Meta (88), Bin (20), Scripts (49).
_BUN_LOCKB_TAIL_COLUMN_SIZES = (8, 8, 88, 20, 49)
# Buffers after the package table: trees, hoisted deps, resolutions,
# dependencies, extern strings, string bytes (element sizes).
_BUN_LOCKB_BUFFER_SIZES = (20, 4, 4, 26, 16, 1)
_BUN_LOCKB_ANNOTATION_RE = re.compile(
    rb"\n<[^>\n]{1,200}> ([0-9]{1,4}) sizeof, ([0-9]{1,2}) alignof\n"
)
_BUN_LOCKB_DECODE_FACTOR = 4
_BUN_LOCKB_DECODE_FLOOR = 1024 * 1024
_BUN_RESOLUTION_NPM = 2
_BUN_RESOLUTION_ROOT = 1
# root, folder, symlink, workspace: local sources that never fetch a release.
_BUN_LOCAL_RESOLUTIONS = frozenset({1, 4, 64, 72})
_BUN_DEPENDENCY_PEER = 1 << 4
_YAML_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
_CARGO_PACKAGE_HEADER_RE = re.compile(
    r"^[ \t]*\[\[[ \t]*package[ \t]*\]\][ \t]*(?:#.*)?$"
)
_CARGO_TABLE_HEADER_RE = re.compile(
    r"^[ \t]*(?:"
    r"\[[ \t]*[A-Za-z0-9_-]+(?:[ \t]*\.[ \t]*[A-Za-z0-9_-]+)*[ \t]*\]"
    r"|\[\[[ \t]*[A-Za-z0-9_-]+(?:[ \t]*\.[ \t]*[A-Za-z0-9_-]+)*[ \t]*\]\]"
    r")[ \t]*(?:#.*)?$"
)
_CARGO_IDENTITY_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(name|version)[ \t]*=[ \t]*(?:\"([^\"\\]*)\"|'([^']*)')"
    r"[ \t]*(?:#.*)?$"
)
_CARGO_QUOTED_KEY_RE = re.compile(
    r'''^(?:"[^"\n]*"|'[^'\n]*')[ \t]*='''
)
_CARGO_IDENTITY_LIKE_RE = re.compile(
    r"^\s*(?:name|version)(?=\s|=)"
)
_CARGO_INVALID_LINE_BREAK_RE = re.compile(
    r"[\v\f\x1c-\x1e\x85\u2028\u2029]|\r(?!\n)"
)
_SEMVER_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_EXACT_SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    rf"(?:-{_SEMVER_IDENTIFIER}(?:\.{_SEMVER_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


@dataclass
class IocEntry:
    name: str
    line_no: int
    version_evidence: dict[str, tuple[tuple[str, int], ...]] = field(
        default_factory=dict
    )
    affected_set_complete: dict[str, int] = field(default_factory=dict)


@dataclass
class IocHit:
    lockfile: Path
    ioc: str
    lockfile_line_no: int  # 1-based; 0 means whole-file aggregate evidence
    ioc_line_no: int
    versions: tuple[str, ...] = ()
    ecosystem: str | None = None
    verification: str = "name-only"
    version_evidence: dict[str, tuple[tuple[str, int], ...]] = field(
        default_factory=dict
    )
    whole_file_kind: str | None = None
    affected_set_complete: dict[str, int] = field(default_factory=dict)
    lockfile_text: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class LockfilePackageVersions:
    versions: tuple[str, ...] = ()
    mixed_or_untrusted: bool = False


@dataclass
class OsvApiClassification:
    status: str  # success | failed
    vulns: list[dict] = field(default_factory=list)
    diagnostic: str = ""


class IocListError(ValueError):
    """The shipped IoC policy could not be read or parsed safely."""


def load_ioc_list(path: Path) -> tuple[dict[str, IocEntry], int | None]:
    """Parse the IoC policy. Returns (ioc_map, stale_days_or_none).

    `stale_days` is days since the `LAST_REFRESHED: YYYY-MM-DD` header, or None
    if absent/malformed. VERSION records form an exact malicious-release set;
    every one must have a corresponding plain package entry. Legacy
    AFFECTED_SET_COMPLETE records are validated and retained as provenance but
    do not affect classification.
    """
    if not path.is_file():
        raise IocListError(f"IoC list not found at {path}")
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise IocListError(f"cannot read IoC list {path}: {exc}") from exc

    iocs: dict[str, IocEntry] = {}
    policy_records: list[tuple[int, str, str, str, str | None]] = []
    last_refreshed: str | None = None
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("LAST_REFRESHED:"):
            last_refreshed = stripped.split(":", 1)[1].strip()
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("VERSION:"):
            fields = [
                part.strip()
                for part in stripped[len("VERSION:"):].split("|")
            ]
            if len(fields) != 3 or any(not field for field in fields):
                raise IocListError(f"line {line_no}: malformed VERSION record")
            ecosystem, package, version = fields
            if ecosystem not in _IOC_VERSION_ECOSYSTEMS:
                raise IocListError(
                    f"line {line_no}: VERSION ecosystem {ecosystem!r} "
                    "has no trusted exact extractor"
                )
            if (
                not _is_policy_package_identity(package)
                or not _is_exact_registry_version(version, ecosystem)
            ):
                raise IocListError(
                    f"line {line_no}: invalid VERSION package/version"
                )
            policy_records.append(
                (line_no, "version", ecosystem, package, version)
            )
            continue
        if re.match(r"^VERSION(?:\s|$)", stripped):
            raise IocListError(
                f"line {line_no}: malformed reserved VERSION record"
            )
        if stripped.startswith("AFFECTED_SET_COMPLETE:"):
            fields = [
                part.strip()
                for part in stripped[len("AFFECTED_SET_COMPLETE:"):].split("|")
            ]
            if len(fields) != 2 or any(not field for field in fields):
                raise IocListError(
                    f"line {line_no}: malformed AFFECTED_SET_COMPLETE record"
                )
            ecosystem, package = fields
            if ecosystem not in _IOC_VERSION_ECOSYSTEMS:
                raise IocListError(
                    f"line {line_no}: AFFECTED_SET_COMPLETE ecosystem "
                    f"{ecosystem!r} has no trusted exact extractor"
                )
            if not _is_policy_package_identity(package):
                raise IocListError(
                    f"line {line_no}: invalid AFFECTED_SET_COMPLETE package"
                )
            policy_records.append(
                (line_no, "complete", ecosystem, package, None)
            )
            continue
        if re.match(r"^AFFECTED_SET_COMPLETE(?:\s|$)", stripped):
            raise IocListError(
                f"line {line_no}: malformed reserved "
                "AFFECTED_SET_COMPLETE record"
            )
        if "|" in stripped:
            raise IocListError(
                f"line {line_no}: unexpected pipe in IoC policy record"
            )
        if not _is_plain_policy_identity(stripped):
            raise IocListError(
                f"line {line_no}: invalid plain package identity"
            )
        iocs.setdefault(stripped, IocEntry(name=stripped, line_no=line_no))

    by_package: dict[str, dict[str, dict[str, int]]] = {}
    active_complete: dict[tuple[str, str], int] = {}
    for line_no, kind, ecosystem, package, version in policy_records:
        if package not in iocs:
            raise IocListError(
                f"line {line_no}: {kind.upper()} record for {package!r} has "
                "no plain package entry"
            )
        versions = by_package.setdefault(package, {}).setdefault(ecosystem, {})
        key = (package, ecosystem)
        if kind == "version":
            assert version is not None
            if version not in versions:
                versions[version] = line_no
                active_complete.pop(key, None)
            continue
        if not versions:
            raise IocListError(
                f"line {line_no}: AFFECTED_SET_COMPLETE for {package!r} "
                "has no earlier distinct VERSION record"
            )
        active_complete[key] = line_no
    for package, ecosystems in by_package.items():
        iocs[package].version_evidence = {
            ecosystem: tuple(sorted(versions.items(), key=lambda item: item[1]))
            for ecosystem, versions in ecosystems.items()
        }
    for (package, ecosystem), line_no in active_complete.items():
        iocs[package].affected_set_complete[ecosystem] = line_no

    stale_days: int | None = None
    if last_refreshed:
        try:
            y, m, d = (int(x) for x in last_refreshed.split("-"))
            stale_days = (date.today() - date(y, m, d)).days
        except (ValueError, IndexError):
            stale_days = None
    return iocs, stale_days


def discover_lockfiles(root: Path) -> tuple[list[Path], list[Path], list[Path]]:
    """Discover lockfiles under `root`, skipping installed-artifact dirs and not
    following symlinks. Entries are consumed lazily so a single hostile giant
    directory cannot be materialized before the global discovery bound applies.
    Returns (regular, symlinked, traversal_errors): a lockfile that is itself a
    SYMLINK is NOT read (following it could be unsafe/exfil) but is also NOT
    silently dropped. Directory traversal errors are likewise retained so the
    caller cannot certify an incompletely walked tree clean. (In the hardened
    prep flow the clone uses core.symlinks=false; these fail-closed paths also
    protect standalone `ioc <dir>` use.)"""
    found: list[Path] = []
    symlinked: list[Path] = []
    traversal_errors: list[Path] = []
    entries_seen = 0

    def limit_error(kind: str) -> Path:
        return root / f".coldclone-{kind}-limit-exceeded"

    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            iterator_context = os.scandir(directory)
            with iterator_context as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen >= _DISCOVERY_ENTRY_LIMIT:
                        traversal_errors.append(limit_error("entry"))
                        return sorted(found), sorted(symlinked), sorted(
                            set(traversal_errors)
                        )
                    path = Path(entry.path)
                    try:
                        is_symlink = entry.is_symlink()
                        if is_symlink:
                            is_directory = entry.is_dir(follow_symlinks=True)
                            if is_directory and entry.name in _SKIP_DIRS:
                                continue
                            if is_directory or entry.name in _LOCKFILE_NAMES:
                                if len(found) + len(symlinked) >= _LOCKFILE_COUNT_LIMIT:
                                    traversal_errors.append(limit_error("lockfile"))
                                    return sorted(found), sorted(symlinked), sorted(
                                        set(traversal_errors)
                                    )
                                symlinked.append(path)
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in _SKIP_DIRS:
                                pending.append(path)
                            continue
                        if entry.name not in _LOCKFILE_NAMES:
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            traversal_errors.append(path)
                            continue
                        if len(found) + len(symlinked) >= _LOCKFILE_COUNT_LIMIT:
                            traversal_errors.append(limit_error("lockfile"))
                            return sorted(found), sorted(symlinked), sorted(
                                set(traversal_errors)
                            )
                        found.append(path)
                    except OSError:
                        traversal_errors.append(path)
        except OSError as exc:
            traversal_errors.append(
                Path(exc.filename) if exc.filename else directory
            )
    return sorted(found), sorted(symlinked), sorted(set(traversal_errors))


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


def _is_exact_registry_version(
    version: str, ecosystem: str | None = None
) -> bool:
    """Return true only for a canonical exact SemVer registry release.

    npm and crates.io both use SemVer release identities. Requiring the full
    three-part form prevents a malformed policy typo from silently turning an
    identity into a version-scoped allow-by-default rule.
    """
    if ecosystem not in (None, "npm", "crates.io"):
        return False
    if not version or len(version) > 128:
        return False
    return _EXACT_SEMVER_RE.fullmatch(version) is not None


def _is_policy_package_identity(package: str) -> bool:
    """Validate npm/crates.io identity shapes accepted by VERSION records."""
    return re.fullmatch(
        r"(?:@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)", package
    ) is not None


def _is_plain_policy_identity(package: str) -> bool:
    """Validate bounded cross-ecosystem identities accepted as plain records."""
    if not package or len(package) > 256:
        return False
    return re.fullmatch(
        r"(?:"
        r"@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
        r"|[A-Za-z0-9][A-Za-z0-9_.-]*"
        r"|[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9][A-Za-z0-9_.@+-]*)+"
        r")",
        package,
    ) is not None


def _npm_alias_target(value: object) -> tuple[str, str | None] | None:
    """Return (target, exact-version-or-None) for an npm alias specifier."""
    if not isinstance(value, str) or not value.startswith("npm:"):
        return None
    target_with_range = value[len("npm:"):]
    split_at = target_with_range.rfind("@")
    if split_at <= 0:
        return None
    target = target_with_range[:split_at]
    version = target_with_range[split_at + 1:]
    if not _is_policy_package_identity(target) or not version:
        return None
    return target, version if _is_exact_registry_version(version) else None


def _extract_package_lock_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    duplicate_key = False

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal duplicate_key
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                duplicate_key = True
            result[key] = value
        return result

    try:
        if text is None:
            text = lockfile.read_text(encoding="utf-8", errors="strict")
        data = json.loads(
            text,
            object_pairs_hook=object_pairs,
        )
    except (OSError, UnicodeError, ValueError, RecursionError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    versions: set[str] = set()
    untrusted = duplicate_key
    alias_referenced = False
    alias_resolved = False

    def consider(
        value: object, *, alias_version: str | None = None, alias: bool = False
    ) -> None:
        nonlocal untrusted, alias_resolved
        if not isinstance(value, dict):
            untrusted = True
            return
        version = alias_version if alias_version is not None else value.get("version")
        if isinstance(version, str) and _is_exact_registry_version(version):
            versions.add(version)
            if alias or alias_version is not None:
                alias_resolved = True
            for field_name in ("resolved", "_resolved"):
                resolved = value.get(field_name)
                if resolved is not None and not (
                    isinstance(resolved, str)
                    and _tarball_url_matches(resolved, package, version)
                ):
                    # npm downloads `resolved` (or, without it, `_resolved`)
                    # verbatim, and the attacker also writes `integrity`: it
                    # must be exactly this release's tarball.
                    untrusted = True
            source = value.get("from")
            if source is not None and (
                not isinstance(source, str) or _has_fetch_marker(source)
                or source.startswith("file:")
            ):
                # Legacy `from` is fetched when `resolved` is absent.
                untrusted = True
        else:
            untrusted = True

    def check_foreign(value: object) -> None:
        """A record installing another identity must not fetch the package."""
        nonlocal untrusted
        if not isinstance(value, dict) or value.get("link") is True:
            return
        for field_name in ("resolved", "_resolved", "from", "version"):
            spec = value.get(field_name)
            if (
                isinstance(spec, str)
                and not _is_local_directory_resolution(spec)
                and _mentions_package(spec, package)
            ):
                untrusted = True

    def alias_for(value: object) -> str | None:
        nonlocal alias_referenced
        parsed = _npm_alias_target(value)
        if parsed is None or parsed[0] != package:
            return None
        alias_referenced = True
        return parsed[1]

    def scan_packages(packages: object) -> None:
        nonlocal untrusted, alias_referenced, alias_resolved
        if not isinstance(packages, dict):
            untrusted = True
            return
        for key, value in packages.items():
            normalized = str(key).replace("\\", "/")
            if normalized and posixpath.normpath(normalized) != normalized:
                # npm resolves `node_modules/./keyv` or `a/../keyv` to the
                # installed location; npm never writes such keys.
                untrusted = True
            if normalized == f"node_modules/{package}" or normalized.endswith(
                f"/node_modules/{package}"
            ):
                installed = value.get("name") if isinstance(value, dict) else None
                if isinstance(installed, str) and installed != package:
                    # An alias location: it installs `name`, not `package`.
                    check_foreign(value)
                    continue
                consider(value)
                continue
            if not isinstance(value, dict) or _NM_MARKER not in normalized:
                check_foreign(value)
                continue
            # npm aliases are installed under the alias location, while either
            # the record's `name` or its `npm:<target>@<version>` value carries
            # the actual registry identity.
            owned = False
            if value.get("name") == package:
                alias_referenced = True
                owned = True
                consider(value, alias=True)
            alias_version = alias_for(value.get("version"))
            if alias_version is not None:
                owned = True
                consider(value, alias_version=alias_version)
            if not owned:
                check_foreign(value)

    def scan_dependencies(dependencies: object) -> None:
        nonlocal untrusted
        if not isinstance(dependencies, dict):
            untrusted = True
            return
        stack = [dependencies]
        while stack:
            deps = stack.pop()
            if package in deps:
                local = deps.get(package)
                target = (
                    _npm_alias_target(local.get("version"))
                    if isinstance(local, dict) else None
                )
                if target is not None and target[0] != package:
                    # An alias local name: it installs `target`, not `package`.
                    check_foreign(local)
                else:
                    consider(local)
            for name, value in deps.items():
                if isinstance(value, dict):
                    alias_version = alias_for(value.get("version"))
                    if alias_version is not None:
                        consider(value, alias_version=alias_version)
                    elif name != package:
                        check_foreign(value)
                if isinstance(value, dict) and isinstance(
                    value.get("dependencies"), dict
                ):
                    stack.append(value["dependencies"])

    def scan_alias_references(root: object) -> None:
        """Notice alias declarations even when their install record is absent."""
        stack = [root]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                stack.extend(value.keys())
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
            else:
                alias_for(value)

    if not isinstance(data, dict):
        untrusted = True
    else:
        scan_alias_references(data)
        lockfile_version = data.get("lockfileVersion")
        if type(lockfile_version) is not int or lockfile_version not in (1, 2, 3):
            untrusted = True
        elif lockfile_version == 1:
            scan_dependencies(data.get("dependencies"))
            if "packages" in data:
                untrusted = True
        elif lockfile_version == 2:
            scan_packages(data.get("packages"))
            scan_dependencies(data.get("dependencies"))
        else:  # lockfileVersion == 3
            scan_packages(data.get("packages"))
            if "dependencies" in data:
                untrusted = True
    if alias_referenced and not alias_resolved:
        untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


def _yarn_descriptor_name(descriptor: str) -> str:
    descriptor = descriptor.strip().strip("\"'")
    if descriptor.startswith("@"):
        idx = descriptor.find("@", 1)
        return descriptor if idx == -1 else descriptor[:idx]
    return descriptor.split("@", 1)[0]


def _yarn_alias_target(descriptor: str) -> str | None:
    """Return the package targeted by an exact Yarn npm-alias descriptor."""
    value = descriptor.strip().strip("\"'")
    alias = _yarn_descriptor_name(value)
    marker = value[len(alias):]
    if not marker.startswith("@npm:"):
        return None
    target_with_range = marker[len("@npm:"):]
    target = _yarn_descriptor_name(target_with_range)
    range_part = target_with_range[len(target):]
    if not target or not range_part.startswith("@") or len(range_part) == 1:
        return None
    return target


_YARN_CLASSIC_SHA1_FRAGMENT_RE = re.compile(r"[0-9a-f]{40}")


def _yarn_classic_resolved_matches(url: str, name: str, version: str) -> bool:
    """Yarn Classic appends `#<sha1>` to the registry tarball URL it fetches."""
    base, separator, fragment = url.partition("#")
    if separator and _YARN_CLASSIC_SHA1_FRAGMENT_RE.fullmatch(fragment) is None:
        return False
    return _tarball_url_matches(base, name, version)


_FETCH_MARKER_RE = re.compile(
    # Remote and VCS sources a package manager fetches as-is (a semver range
    # or `npm:` locator never contains one of these). scp-style `git@host:` only where a source starts, so a package named
    # `@changesets/git@^3` is not mistaken for one.
    r"://|github:|gitlab:|bitbucket:|git\+|(?:^|[@\s\"':])git@"
    # a local archive (directories are exempt: they are not releases)
    r"|file:[^\s\"']*\.(?:tgz|tar\.gz|tar)(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def _has_fetch_marker(text: str) -> bool:
    """A remote/VCS/archive source marker, as a URL parser sees the text."""
    return _FETCH_MARKER_RE.search(_canonical_url_text(text)) is not None


def _yarn_fetches_package(
    header: str, body: list[str], package: str
) -> bool:
    """True if a remote/VCS source in another identity's block names `package`.

    Whole lines are checked (not just the `resolved`/`resolution` field) so a
    quoted or otherwise unusual key spelling cannot hide the fetched source.
    """
    return any(
        _has_fetch_marker(line) and _mentions_package(line, package)
        for line in (header, *body)
    )


def _extract_yarn_classic_version_info(
    lines: list[str], package: str
) -> LockfilePackageVersions:
    versions: set[str] = set()
    untrusted = False
    for header, body in _yarn_top_level_blocks(lines):
        descriptors = header.split(",")
        # An alias descriptor (`local@npm:target@range`) installs `target`;
        # its local name is not an install of a package by that name.
        alias_targets = {_yarn_alias_target(part) for part in descriptors}
        names = {
            _yarn_descriptor_name(part)
            for part in descriptors
            if _yarn_alias_target(part) is None
        }
        if package not in names and package not in alias_targets:
            # Yarn fetches `resolved` verbatim: another identity whose tarball
            # names the package is a renamed install, not unrelated metadata.
            if _yarn_fetches_package(header, body, package):
                untrusted = True
            continue

        populated = [line for line in body if line.strip()]
        if not populated:
            untrusted = True
            continue
        direct_indent = min(
            len(line) - len(line.lstrip(" ")) for line in populated
        )
        prefix = re.escape(" " * direct_indent)
        version_re = re.compile(prefix + r'version\s+"([^"]+)"\s*$')
        version_values = [
            match.group(1) for line in body if (match := version_re.fullmatch(line))
        ]
        # Yarn's parser also accepts a quoted key and `key: value`.
        resolved_values = [
            _strip_balanced_yaml_scalar(value)
            for line in body
            if line.startswith(" " * direct_indent)
            and not line[direct_indent:direct_indent + 1].isspace()
            and (value := _yarn_field_value(line.strip(), "resolved")) is not None
        ]
        if sum(
            _has_fetch_marker(line)
            for line in body
            if line.startswith(" " * direct_indent)
            and not line[direct_indent:direct_indent + 1].isspace()
        ) > len(resolved_values):
            # A remote source in a field of this block other than the one
            # recognized `resolved` (nested dependency specs may be git URLs).
            untrusted = True
        if len(version_values) != 1:
            untrusted = True
            for version in version_values:
                if _is_exact_registry_version(version):
                    versions.add(version)
            continue
        version = version_values[0]
        if any(
            _has_fetch_marker(part) or "@file:" in part
            for part in descriptors
        ) or not resolved_values:
            # Without `resolved`, Yarn re-resolves the descriptor (fetching a
            # URL descriptor verbatim), so `version` proves nothing.
            untrusted = True
        if _is_exact_registry_version(version):
            versions.add(version)
            if len(resolved_values) > 1 or (
                resolved_values
                and (
                    resolved_values[0] is None
                    or not _yarn_classic_resolved_matches(
                        resolved_values[0], package, version
                    )
                )
            ):
                untrusted = True
        else:
            untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


def _strip_balanced_yaml_scalar(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value[0] in "\"'" or value[-1:] in "\"'":
        if len(value) < 2 or value[0] != value[-1] or value[0] not in "\"'":
            return None
        value = value[1:-1]
    return value


def _yarn_field_value(content: str, key: str) -> str | None:
    """Raw value of a stripped Yarn line that is the field `key`, else None.

    Accepts Classic `key value`, YAML `key: value`, and a quoted key, by plain
    string checks (no backtracking regex over hostile whitespace).
    """
    for spelled in (key, f'"{key}"', f"'{key}'"):
        if not content.startswith(spelled):
            continue
        rest = content[len(spelled):]
        if rest[:1] == ":":
            rest = rest[1:]
        elif not rest[:1].isspace():
            continue
        rest = rest.strip()
        return rest or None
    return None


def _yarn_has_unrecognized_top_level(lines: list[str]) -> bool:
    """A top-level line that is not a `header:` (e.g. `key: # comment`).

    `_yarn_top_level_blocks` would drop it or fold its body into the previous
    block, while Yarn parses it as an ordinary entry.
    """
    return any(
        line
        and not line[0].isspace()
        and not line.startswith("#")
        and not line.rstrip().endswith(":")
        for line in lines
    )


def _yarn_top_level_blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    header: str | None = None
    body: list[str] = []
    for line in lines:
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            if header is not None:
                blocks.append((header, body))
            header = line.rstrip()[:-1]
            body = []
        elif header is not None:
            body.append(line)
    if header is not None:
        blocks.append((header, body))
    return blocks


def _yaml_field_pattern(indent: int, key: str) -> re.Pattern[str]:
    """`key:` at exactly `indent`, plain or quoted, optionally spaced (`key :`)."""
    escaped = re.escape(key)
    return re.compile(
        "^" + " " * indent + f"""(?:{escaped}|"{escaped}"|'{escaped}')[ \t]*:(.*)$"""
    )


def _yarn_direct_scalars(body: list[str], key: str) -> list[str | None]:
    populated = [line for line in body if line.strip()]
    if not populated:
        return []
    direct_indent = min(len(line) - len(line.lstrip(" ")) for line in populated)
    pattern = _yaml_field_pattern(direct_indent, key)
    return [
        _strip_balanced_yaml_scalar(match.group(1).strip())
        for line in body
        if (match := pattern.match(line))
    ]


def _yarn_direct_raw_scalars(body: list[str], key: str) -> list[str]:
    populated = [line for line in body if line.strip()]
    if not populated:
        return []
    direct_indent = min(len(line) - len(line.lstrip(" ")) for line in populated)
    pattern = _yaml_field_pattern(direct_indent, key)
    return [
        match.group(1).strip()
        for line in body
        if (match := pattern.match(line))
    ]


def _yarn_npm_locator(value: str | None) -> tuple[str, str] | None:
    if value is None or "@npm:" not in value:
        return None
    package, version = value.rsplit("@npm:", 1)
    if not package or not _is_exact_registry_version(version):
        return None
    return package, version


def _yarn_range_selects_version(range_spec: str, version: str) -> bool:
    """Evaluate the closed exact/^/~ range forms used by compat patches."""
    match = re.fullmatch(
        r"(?P<operator>[~^]?)(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)",
        range_spec,
    )
    selected = re.fullmatch(
        r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)", version
    )
    if match is None or selected is None:
        return False
    base = tuple(int(match.group(name)) for name in ("major", "minor", "patch"))
    current = tuple(
        int(selected.group(name)) for name in ("major", "minor", "patch")
    )
    operator = match.group("operator")
    if operator == "":
        return current == base
    if current < base:
        return False
    if operator == "~":
        return current[:2] == base[:2]
    if base[0] != 0:
        return current[0] == base[0]
    if base[1] != 0:
        return current[:2] == base[:2]
    return current == base


def _is_yarn_builtin_compat_patch(
    header: str, resolution: str, package: str, version: str
) -> bool:
    escaped_package = re.escape(package)
    escaped_version = re.escape(version)
    resolution_match = re.fullmatch(
        escaped_package
        + r"@patch:"
        + escaped_package
        + r"@npm%3A"
        + escaped_version
        + r"#(?P<variant>optional!|~)builtin<compat/"
        + escaped_package
        + r">::version="
        + escaped_version
        + r"&hash=(?P<hash>[A-Za-z0-9]+)",
        resolution,
    )
    if resolution_match is None:
        return False
    if resolution_match.group("variant") == "optional!":
        descriptor_re = re.compile(
            r"^"
            + escaped_package
            + r"@patch:"
            + escaped_package
            + r"@npm%3A(?P<range>[^#]+)#optional!builtin<compat/"
            + escaped_package
            + r">$"
        )
    else:
        descriptor_re = re.compile(
            r"^"
            + escaped_package
            + r"@patch:"
            + escaped_package
            + r"@(?P<range>[^#]+)#~builtin<compat/"
            + escaped_package
            + r">$"
        )
    descriptors = [part.strip().strip("\"'") for part in header.split(",")]
    matches = [descriptor_re.fullmatch(part) for part in descriptors]
    return bool(matches) and all(
        match is not None
        and _yarn_range_selects_version(match.group("range"), version)
        for match in matches
    )


def _extract_yarn_berry_version_info(
    blocks: list[tuple[str, list[str]]], package: str
) -> LockfilePackageVersions:
    versions: set[str] = set()
    untrusted = False
    relevant: list[tuple[str, list[str | None], list[str | None]]] = []
    direct_candidates: set[str] = set()

    for header, body in blocks:
        if header.strip().strip("\"'") == "__metadata":
            continue
        resolutions = _yarn_direct_scalars(body, "resolution")
        descriptors = header.split(",")
        header_match = (
            package in {_yarn_descriptor_name(part) for part in descriptors}
            or package in {_yarn_alias_target(part) for part in descriptors}
        )
        resolution_match = any(
            (locator := _yarn_npm_locator(value)) is not None
            and locator[0] == package
            for value in resolutions
        )
        resolution_name_match = any(
            value is not None and value.startswith(f"{package}@")
            for value in resolutions
        )
        if not (header_match or resolution_match or resolution_name_match):
            # Another identity whose resolution fetches the package (a URL or
            # git source) is a renamed install, not unrelated metadata.
            if _yarn_fetches_package(header, body, package):
                untrusted = True
            continue
        version_values = _yarn_direct_scalars(body, "version")
        relevant.append((header, version_values, resolutions))
        if len(version_values) == 1 and len(resolutions) == 1:
            version = version_values[0]
            locator = _yarn_npm_locator(resolutions[0])
            if (
                version is not None
                and _is_exact_registry_version(version)
                and locator == (package, version)
            ):
                direct_candidates.add(version)

    for header, version_values, resolutions in relevant:
        for version in version_values:
            if version is not None and _is_exact_registry_version(version):
                versions.add(version)
        if len(version_values) != 1 or len(resolutions) != 1:
            untrusted = True
            continue
        version = version_values[0]
        resolution = resolutions[0]
        if version is None or not _is_exact_registry_version(version) or resolution is None:
            untrusted = True
            continue
        locator = _yarn_npm_locator(resolution)
        if locator == (package, version):
            continue
        if version in direct_candidates and _is_yarn_builtin_compat_patch(
            header, resolution, package, version
        ):
            continue
        untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


def _extract_yarn_lock_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    try:
        if text is None:
            text = lockfile.read_text(encoding="utf-8", errors="strict")
        lines = text.splitlines()
    except (OSError, UnicodeError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    if _yarn_has_unrecognized_top_level(lines):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    metadata_key_re = re.compile(
        r"^(?:__metadata|\"__metadata\"|'__metadata')\s*:"
    )
    metadata_present = any(metadata_key_re.match(line) for line in lines)
    if not metadata_present:
        return _extract_yarn_classic_version_info(lines, package)
    blocks = _yarn_top_level_blocks(lines)
    metadata = [
        (header, body)
        for header, body in blocks
        if header.strip().strip("\"'") == "__metadata"
    ]
    if len(metadata) != 1:
        return LockfilePackageVersions(mixed_or_untrusted=True)
    metadata_versions = _yarn_direct_raw_scalars(metadata[0][1], "version")
    if (
        len(metadata_versions) != 1
        or metadata_versions[0] not in _YARN_BERRY_METADATA_VERSIONS
    ):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    # Berry's exact `package@npm:version` locator is the dependency identity we
    # compare with registry-version advisories. The parser above rejects
    # duplicate, malformed, ambiguous, and incompatible patch records before a
    # locator can be treated as exact.
    return _extract_yarn_berry_version_info(blocks, package)


@dataclass(frozen=True)
class _YamlMappingNode:
    key: str
    value: str
    indent: int
    parent: int | None


@dataclass(frozen=True)
class _YamlMappingIndex:
    nodes: tuple[_YamlMappingNode, ...]
    roots: tuple[int, ...]
    children: Mapping[int, tuple[int, ...]]
    unsupported_structure: bool = False


def _join_flow_lines(lines: list[str]) -> list[str]:
    """Fold Prettier's `key:` + `{` ... `}` lines back onto the key line.

    The subset gate only admits a multi-line flow collection in that shape;
    joining it gives the index the one-line `key: {...}` pnpm itself writes.
    """
    joined: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if (
            line.strip()[:1] in ("{", "[")
            and joined
            and joined[-1].rstrip().endswith(":")
            and len(line) - len(line.lstrip()) > len(joined[-1]) - len(joined[-1].lstrip())
        ):
            parts = [joined[-1].rstrip(), line.strip()]
            depth = 0
            quote = None
            while True:
                text = parts[-1]
                position = 0
                while position < len(text):
                    char = text[position]
                    if quote == '"' and char == "\\":
                        position += 2  # `\\` or `\"`, the only escapes admitted
                        continue
                    if quote:
                        if char == quote:
                            quote = None
                    elif char == "#" and (position == 0 or text[position - 1] in " \t"):
                        # A comment: drop it so its brackets are not counted.
                        parts[-1] = text[:position].rstrip()
                        break
                    elif char in "\"'":
                        quote = char
                    elif char in "[{":
                        depth += 1
                    elif char in "]}":
                        depth -= 1
                    position += 1
                if depth <= 0 or index + 1 >= len(lines):
                    break
                index += 1
                parts.append(lines[index].strip())
            joined[-1] = " ".join(parts)
        else:
            joined.append(line)
        index += 1
    return joined


def _yaml_mapping_index(lines: list[str]) -> _YamlMappingIndex:
    """Index the mapping-only pnpm subset once, in linear time."""
    lines = _join_flow_lines(lines)
    nodes: list[_YamlMappingNode] = []
    roots: list[int] = []
    mutable_children: dict[int, list[int]] = {}
    stack: list[int] = []
    unsupported_structure = False

    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line[:len(line) - len(line.lstrip())]:
            unsupported_structure = True
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:].rstrip()
        while stack and nodes[stack[-1]].indent >= indent:
            stack.pop()
        parent = stack[-1] if stack else None
        structural_parents = {
            "packages", "snapshots", "importers", "dependencies",
            "devDependencies", "optionalDependencies",
        }
        if content.startswith("- "):
            if parent is None or nodes[parent].key in structural_parents:
                unsupported_structure = True
            continue
        if content[:1] in {"'", '"'}:
            quote = content[0]
            closing = content.find(quote, 1)
            if closing < 0 or not content[closing + 1:].lstrip().startswith(":"):
                unsupported_structure = True
                continue
            key = content[1:closing]
            value = content[closing + 1:].lstrip()[1:].strip()
        else:
            if ":" not in content:
                if parent is None or nodes[parent].key in structural_parents:
                    unsupported_structure = True
                continue
            key, value = (part.strip() for part in content.split(":", 1))
        if not key:
            unsupported_structure = True
            continue
        idx = len(nodes)
        nodes.append(_YamlMappingNode(key, value, indent, parent))
        if parent is None:
            roots.append(idx)
        else:
            mutable_children.setdefault(parent, []).append(idx)
        stack.append(idx)

    return _YamlMappingIndex(
        nodes=tuple(nodes),
        roots=tuple(roots),
        children={key: tuple(value) for key, value in mutable_children.items()},
        unsupported_structure=unsupported_structure,
    )


def _yaml_child_values(
    index: _YamlMappingIndex, parent: int, key: str
) -> list[tuple[int, str]]:
    return [
        (child, index.nodes[child].value)
        for child in index.children.get(parent, ())
        if index.nodes[child].key == key
    ]


def _yaml_has_duplicate_child_keys(index: _YamlMappingIndex, parent: int) -> bool:
    keys = [index.nodes[child].key for child in index.children.get(parent, ())]
    return len(keys) != len(set(keys))


def _pnpm_specifier_is_registry_like(specifier: str | None) -> bool:
    if specifier is None:
        return False
    lowered = specifier.strip().lower().strip("'\"")
    if not lowered:
        return False
    return not lowered.startswith(
        ("file:", "git", "http:", "https:", "link:", "workspace:")
    )


def _parse_yaml_flow_mapping(value: str) -> dict[str, str] | None:
    """Parse pnpm's one-line `{key: value, ...}`; None when ambiguous."""
    value = value.strip()
    if not (value.startswith("{") and value.endswith("}")):
        return None
    inner = value[1:-1].strip()
    fields: dict[str, str] = {}
    if not inner:
        return fields
    items = inner.split(",")
    if len(items) > 1 and not items[-1].strip():
        items.pop()  # a trailing comma (Prettier)
    for item in items:
        key, separator, raw = item.partition(":")
        key = _strip_balanced_yaml_scalar(key) or ""  # `"tarball": ...`
        scalar = _strip_balanced_yaml_scalar(raw)
        if (
            not separator
            or not key
            or key in fields
            or scalar is None
            or any(char in scalar for char in "{}[]")
        ):
            return None
        fields[key] = scalar
    return fields


def _pnpm_resolution(
    index: _YamlMappingIndex, package_node: int
) -> tuple[list[str], dict[str, str] | None]:
    """(every raw value, parsed fields or None) of a package's `resolution`."""
    entries = _yaml_child_values(index, package_node, "resolution")
    if not entries:
        return [], {}
    raw: list[str] = []
    stack = [node for node, _ in entries]
    while stack:
        node = stack.pop()
        raw.append(index.nodes[node].value)
        stack.extend(index.children.get(node, ()))
    if len(entries) != 1:
        return raw, None
    node, value = entries[0]
    children = index.children.get(node, ())
    if value:
        return raw, None if children else _parse_yaml_flow_mapping(value)
    fields: dict[str, str] = {}
    for child in children:
        key = index.nodes[child].key
        scalar = _strip_balanced_yaml_scalar(index.nodes[child].value)
        if index.children.get(child) or key in fields or scalar is None:
            return raw, None
        fields[key] = scalar
    return raw, fields


def _extract_pnpm_lock_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    try:
        if text is None:
            text = lockfile.read_text(encoding="utf-8", errors="strict")
        lines = text.splitlines()
    except (OSError, UnicodeError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    index = _yaml_mapping_index(lines)
    nodes = index.nodes
    root_by_key: dict[str, list[int]] = {}
    for node_idx in index.roots:
        root_by_key.setdefault(nodes[node_idx].key, []).append(node_idx)

    generations = root_by_key.get("lockfileVersion", [])
    if len(generations) != 1:
        return LockfilePackageVersions(mixed_or_untrusted=True)
    generation = _strip_balanced_yaml_scalar(nodes[generations[0]].value)
    if generation not in {"5.4", "6.0", "9.0"}:
        return LockfilePackageVersions(mixed_or_untrusted=True)

    versions: set[str] = set()
    untrusted = (
        index.unsupported_structure
        or len(index.roots) != len(root_by_key)
    )
    escaped = re.escape(package)
    modern_package_key_re = re.compile(
        r"^/?" + escaped + r"@([^:(\"']+)(?:\(.*\))?$"
    )
    snapshot_key_re = re.compile(
        r"^" + escaped + r"@([^:(\"']+)(?:\(.*\))?$"
    )
    v6_package_key_re = re.compile(
        r"^/" + escaped + r"@([^:(\"']+)(?:\(.*\))?$"
    )
    legacy_package_key_re = re.compile(
        r"^/" + escaped + r"/([^:(\"']+)(?:\(.*\))?$"
    )
    allowed_package_key_re = {
        "5.4": legacy_package_key_re,
        "6.0": v6_package_key_re,
        "9.0": modern_package_key_re,
    }[generation]

    package_sections = root_by_key.get("packages", [])
    if len(package_sections) != 1:
        return LockfilePackageVersions(mixed_or_untrusted=True)
    package_section = package_sections[0]
    if nodes[package_section].value:
        untrusted = True
    if _yaml_has_duplicate_child_keys(index, package_section):
        untrusted = True
    direct_package_nodes = set(index.children.get(package_section, ()))
    snapshot_sections = root_by_key.get("snapshots", [])
    if len(snapshot_sections) > 1 or (snapshot_sections and generation != "9.0"):
        untrusted = True
    direct_snapshot_nodes: set[int] = set()
    if len(snapshot_sections) == 1 and generation == "9.0":
        snapshot_section = snapshot_sections[0]
        if nodes[snapshot_section].value:
            untrusted = True
        direct_snapshot_nodes.update(index.children.get(snapshot_section, ()))
        if _yaml_has_duplicate_child_keys(index, snapshot_section):
            untrusted = True
    snapshot_versions: set[str] = set()
    for idx, node in enumerate(nodes):
        match = modern_package_key_re.fullmatch(
            node.key
        ) or legacy_package_key_re.fullmatch(
            node.key
        )
        if match is None:
            continue
        if idx in direct_snapshot_nodes:
            snapshot_match = snapshot_key_re.fullmatch(node.key)
            if snapshot_match is None:
                untrusted = True
                continue
            version = snapshot_match.group(1)
            if _is_exact_registry_version(version):
                snapshot_versions.add(version)
            else:
                untrusted = True
            continue
        if idx not in direct_package_nodes:
            untrusted = True
            continue
        allowed_match = allowed_package_key_re.fullmatch(node.key)
        if allowed_match is None:
            untrusted = True
            continue
        version = allowed_match.group(1)
        if not _is_exact_registry_version(version):
            untrusted = True
            continue
        versions.add(version)
    if not snapshot_versions.issubset(versions):
        untrusted = True

    own_key_prefixes = (f"{package}@", f"/{package}@", f"/{package}/")
    for idx in sorted(direct_package_nodes | direct_snapshot_nodes):
        key = nodes[idx].key
        inline = nodes[idx].value
        if inline.endswith(":") and ": " not in inline:
            # The line index splits an unquoted key containing `:` (pnpm's
            # `dep@https://...:` tarball keys) at its first colon; rejoin it.
            key, inline = f"{key}:{inline[:-1]}", ""
        is_package_node = idx in direct_package_nodes
        own_match = (
            allowed_package_key_re if is_package_node else snapshot_key_re
        ).fullmatch(key)
        if inline not in ("", "{}"):
            # An inline mapping (`key: {resolution: ...}`) hides its fields
            # from the line index; pnpm writes records in block style.
            if (
                own_match is not None
                or key.startswith(own_key_prefixes)
                or _mentions_package(inline, package)
            ):
                untrusted = True
            continue
        if own_match is None:
            if key.startswith(own_key_prefixes):
                # The package from a tarball/git/file source: no registry
                # version to compare with the denylist.
                untrusted = True
                continue
            # pnpm merges a snapshot over its package record, so a snapshot's
            # `resolution` is a fetch source too.
            raw, fields = _pnpm_resolution(index, idx)
            if (
                fields is not None
                and fields.get("type") == "directory"
                and set(fields) <= {"directory", "type"}
            ):
                continue  # a local directory, never a fetched release
            sources = list(fields.values()) if fields is not None else raw
            source_key = key.split("(", 1)[0]
            if _has_fetch_marker(source_key):
                # A tarball/git key; peer suffixes (`(...)`, 5.4's `_a+b`)
                # legitimately name other packages and are not sources.
                sources.append(source_key)
            if any(_mentions_package(source, package) for source in sources):
                # Another identity whose key or fetched source names the
                # package is a renamed install, not unrelated metadata.
                untrusted = True
            continue
        _, fields = _pnpm_resolution(index, idx)
        version = own_match.group(1)
        if fields is None or not set(fields) <= {"integrity", "tarball"} or (
            "tarball" in fields
            and not _tarball_url_matches(fields["tarball"], package, version)
        ):
            # pnpm fetches `resolution.tarball` verbatim (the attacker also
            # writes `integrity`), so it must be exactly this release's tarball.
            untrusted = True

    allowed_maps = {"dependencies", "devDependencies", "optionalDependencies"}
    importer_sections = root_by_key.get("importers", [])
    if len(importer_sections) > 1:
        untrusted = True
    dependency_maps: list[int] = []
    if len(importer_sections) == 1:
        importer_section = importer_sections[0]
        if nodes[importer_section].value:
            untrusted = True
        if _yaml_has_duplicate_child_keys(index, importer_section):
            untrusted = True
        for importer in index.children.get(importer_section, ()):
            if _yaml_has_duplicate_child_keys(index, importer):
                untrusted = True
            # A flow value here (`.: {...}`, `dependencies: {...}`) stands in
            # for the block mapping the index reads.
            if nodes[importer].value not in ("", "{}"):
                untrusted = True
            for child in index.children.get(importer, ()):
                if nodes[child].key in allowed_maps:
                    dependency_maps.append(child)
                    if nodes[child].value not in ("", "{}"):
                        untrusted = True
    direct_dependency_nodes = {
        child
        for dependency_map in dependency_maps
        for child in index.children.get(dependency_map, ())
    }
    for dependency_map in dependency_maps:
        if _yaml_has_duplicate_child_keys(index, dependency_map):
            untrusted = True
        stack = list(index.children.get(dependency_map, ()))
        while stack:
            idx = stack.pop()
            node = nodes[idx]
            if node.key == package:
                if idx not in direct_dependency_nodes:
                    untrusted = True
                elif node.value:
                    specifier = _strip_balanced_yaml_scalar(node.value)
                    if not (
                        specifier is not None
                        and _is_exact_registry_version(specifier)
                        and specifier in versions
                    ):
                        untrusted = True
                else:
                    version_fields = _yaml_child_values(index, idx, "version")
                    specifier_fields = _yaml_child_values(index, idx, "specifier")
                    version = (
                        _strip_balanced_yaml_scalar(version_fields[0][1])
                        if len(version_fields) == 1
                        else None
                    )
                    specifier = (
                        _strip_balanced_yaml_scalar(specifier_fields[0][1])
                        if len(specifier_fields) == 1
                        else None
                    )
                    if (
                        version is None
                        or not _is_exact_registry_version(version)
                        or version not in versions
                        or not _pnpm_specifier_is_registry_like(specifier)
                    ):
                        untrusted = True
            stack.extend(index.children.get(idx, ()))
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


def _extract_cargo_lock_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    try:
        if text is None:
            text = lockfile.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    if _CARGO_INVALID_LINE_BREAK_RE.search(text):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    lines = text.replace("\r\n", "\n").split("\n")
    versions: set[str] = set()
    untrusted = False
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if _CARGO_PACKAGE_HEADER_RE.fullmatch(line):
            if current is not None:
                blocks.append(current)
            current = []
            continue
        if _CARGO_TABLE_HEADER_RE.fullmatch(line):
            if current is not None:
                blocks.append(current)
                current = None
            continue
        if current is not None:
            current.append(line)
    if current is not None:
        blocks.append(current)

    for block in blocks:
        names: list[str] = []
        version_values: list[str] = []
        invalid_identity = False
        for line in block:
            if re.match(r"^[ \t]*(?:name|version)[ \t]*=", line) is None:
                continue
            match = _CARGO_IDENTITY_ASSIGNMENT_RE.fullmatch(line)
            if match is None:
                invalid_identity = True
                continue
            key, double, single = match.groups()
            value = double if double is not None else single
            assert value is not None
            (names if key == "name" else version_values).append(value)
        if package not in names:
            continue
        for version in version_values:
            if _is_exact_registry_version(version, "crates.io"):
                versions.add(version)
        if (
            invalid_identity
            or len(names) != 1
            or len(version_values) != 1
            or not _is_exact_registry_version(version_values[0], "crates.io")
        ):
            untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


def _jsonc_to_json(text: str) -> str:
    """Strip JSONC comments and trailing commas outside strings (bun.lock).

    Anything else non-standard is left for the strict JSON parser to reject, so
    input Bun might accept but we cannot read fails closed rather than open.
    Output is streamed in spans with O(1) bookkeeping, so memory stays a small
    multiple of the input even for hostile token-dense files.
    """
    out = io.StringIO()
    previous = ""            # last significant character written
    pending_comma = False    # a comma not yet known to be trailing
    before_comma = ""        # significant character preceding that comma
    i = 0
    length = len(text)

    def emit(chunk: str) -> None:
        nonlocal previous, pending_comma
        if pending_comma:
            # Only a comma that follows a value is a trailing comma; `[,]`
            # and `{,}` keep theirs so the strict parser rejects them.
            if not (chunk[0] in "}]" and before_comma not in ("", "[", "{", ",")):
                out.write(",")
            pending_comma = False
        out.write(chunk)
        previous = chunk[-1]

    while i < length:
        char = text[i]
        if char == '"':
            j = i + 1
            while True:
                close = text.find('"', j)
                if close == -1:
                    raise ValueError("unterminated string")
                k = close - 1
                while k > i and text[k] == "\\":
                    k -= 1
                if (close - 1 - k) % 2 == 0:
                    break
                j = close + 1
            emit(text[i:close + 1])
            i = close + 1
        elif text.startswith("//", i):
            # Bun ends a line comment at any of these; ending only at "\n"
            # would let a crafted lockfile show us a different document.
            match = _JSONC_LINE_COMMENT_END_RE.search(text, i)
            i = length if match is None else match.start()
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            if close == -1:
                raise ValueError("unterminated comment")
            out.write(" ")
            i = close + 2
        elif char == ",":
            if pending_comma:
                out.write(",")
                previous = ","
            before_comma = previous
            pending_comma = True
            i += 1
        elif char in "[]{}":
            emit(char)
            i += 1
        elif char.isspace():
            match = _JSONC_WHITESPACE_RE.match(text, i)
            assert match is not None
            out.write(match.group())
            i = match.end()
        else:
            match = _JSONC_PLAIN_RE.match(text, i)
            stop = match.end() if match is not None else i + 1
            emit(text[i:stop])
            i = stop
    if pending_comma:
        out.write(",")
    return out.getvalue()


def _load_jsonc(text: str) -> tuple[object, bool]:
    """Parse JSONC strictly. Returns (data, duplicate_key_seen)."""
    duplicate_key = False

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal duplicate_key
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                duplicate_key = True
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    data = json.loads(
        _jsonc_to_json(text),
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )
    return data, duplicate_key


def _tarball_url_matches(url: str, name: str, version: str) -> bool:
    """True only for a plain registry tarball URL of exactly name@version.

    Bun downloads a recorded tarball URL verbatim, so a URL that disagrees with
    the parsed identity (or hides a different file behind a query, fragment,
    credentials, encoding, or dot segments) cannot vouch for that version.
    """
    if "?" in url or "#" in url or "%" in url or "\\" in url:
        return False
    if any(char <= " " or char == "\x7f" for char in url):
        return False  # URL parsers drop or trim these: not a plain URL
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if (
        parts.scheme not in ("http", "https")
        or not parts.netloc
        or "@" in parts.netloc
    ):
        return False
    if any(segment in (".", "..") for segment in parts.path.split("/")):
        return False
    basename = name.rsplit("/", 1)[-1]
    return parts.path.endswith(f"/{name}/-/{basename}-{version}.tgz")


_URL_IGNORED_CHARS_RE = re.compile("[\t\n\r]")
# WHATWG accepts special schemes with any run of `/` or `\` (even none):
# `https:/u@host/x`, `https:host/x`, and `https:\\host/x` all fetch host/x.
_SPECIAL_SCHEME_SLASHES_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])(https?|wss?|ftp):[/\\]*", re.IGNORECASE
)


def _canonical_url_text(value: str) -> str:
    """`value` as a WHATWG parser reads its URLs: tab/CR/LF dropped and each
    special scheme followed by exactly `//`."""
    return _SPECIAL_SCHEME_SLASHES_RE.sub(
        lambda match: match.group(1) + "://", _URL_IGNORED_CHARS_RE.sub("", value)
    )


def _percent_decodings(value: str) -> list[str]:
    """`value` plus the forms a URL parser and registry may see in it.

    WHATWG URL parsing drops tab/CR/LF anywhere (`ke\tyv` -> `keyv`) and
    accepts `https:/x` or `https:x` for `https://x`, and registries
    percent-decode paths (`%6beyv` -> `keyv`).
    """
    bases = [value]
    canonical = _canonical_url_text(value)
    if canonical != value:
        bases.append(canonical)
    forms: list[str] = []
    for base in bases:
        forms.append(base)
        for _ in range(3):
            if "%" not in forms[-1]:
                break
            decoded = urllib.parse.unquote(forms[-1])
            if decoded == forms[-1]:
                break
            forms.append(decoded)
    return forms


def _url_path_identities(value: str) -> set[str]:
    """Package identities named by the path/query/fragment of any URL in value.

    The generic tokenizer reads an `@` as a version separator, so URL
    credentials (`https://user@host/keyv/-/...`) would truncate the path away.
    Here everything after the authority is split on URL delimiters instead,
    keeping `@scope/name` pairs together.
    """
    identities: set[str] = set()
    for form in _percent_decodings(value):
        scheme_end = form.find("://")
        while scheme_end != -1:
            # Each URL spans only up to the next `://`, which is handled on its
            # own, so a run of URLs costs linear rather than quadratic work.
            next_scheme = form.find("://", scheme_end + 3)
            rest = form[scheme_end + 3:next_scheme if next_scheme != -1 else None]
            slash = rest.find("/")
            if slash != -1:
                parts = [part for part in _URL_PATH_SPLIT_RE.split(rest[slash:]) if part]
                index = 0
                while index < len(parts):
                    part = parts[index]
                    if part.startswith("@") and index + 1 < len(parts):
                        # Keep `@scope/name` whole: `@types/keyv` must not
                        # read as `keyv` (same scope rule as `_candidates`).
                        scoped = parts[index + 1]
                        identities.add(f"{part}/{scoped}")
                        if "@" in scoped:
                            identities.add(f"{part}/{scoped.split('@', 1)[0]}")
                        index += 2
                        continue
                    identities.add(part)
                    if "@" in part[1:]:
                        identities.update(piece for piece in part.split("@") if piece)
                    index += 1
            scheme_end = next_scheme
    return identities


def _mentions_package(value: str, package: str) -> bool:
    """True if the name gate would derive `package` from `value`, from its
    percent-decoded form, or from any URL path inside it."""
    return package in _url_path_identities(value) or any(
        candidate == package
        for form in _percent_decodings(value)
        for token in _TOKEN_RE.findall(form)
        for candidate in _candidates(token)
    )


def _is_local_directory_resolution(resolution: str) -> bool:
    """workspace:/link:/directory file: resolutions never fetch a release."""
    if resolution.startswith(("workspace:", "link:")):
        return True
    # npm classifies archives case-insensitively (`payload.TGZ` is a file).
    return resolution.startswith("file:") and not resolution.lower().endswith(
        (".tgz", ".tar.gz", ".tar")
    )


def _bun_identity(identity: str) -> tuple[str, str] | None:
    """Split a bun.lock `name@resolution` identity; None if malformed."""
    split_at = identity.find("@", 1 if identity.startswith("@") else 0)
    if split_at <= 0 or split_at == len(identity) - 1:
        return None
    return identity[:split_at], identity[split_at + 1:]


def _bun_lock_key_package(key: str) -> str:
    """Return the installed package name at the end of a bun.lock path key."""
    parts = key.split("/")
    if len(parts) >= 2 and parts[-2].startswith("@"):
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1]


def _bun_lock_declares(
    dependencies: object, package: str, *, untrusted_on_malformed: bool = True
) -> bool | None:
    """True if a dependency map installs `package` (by name or npm alias).

    Returns None for a malformed map so the caller can refuse to clear.
    """
    if dependencies is None:
        return False
    if not isinstance(dependencies, dict):
        return None if untrusted_on_malformed else False
    for name, spec in dependencies.items():
        if name == package:
            return True
        parsed = _npm_alias_target(spec)
        if parsed is not None and parsed[0] == package:
            return True
    return False


def _extract_bun_lock_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    try:
        if text is None:
            # Decode bytes ourselves: text-mode reads translate a bare "\r",
            # which would make us parse a different document than ioc_grep.
            with lockfile.open("rb") as stream:
                raw = stream.read(_LOCKFILE_SIZE_LIMIT + 1)
            if len(raw) > _LOCKFILE_SIZE_LIMIT:
                return LockfilePackageVersions(mixed_or_untrusted=True)
            text = raw.decode("utf-8", errors="strict")
        data, duplicate_key = _load_jsonc(text)
    except (OSError, UnicodeError, ValueError, RecursionError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    if duplicate_key or not isinstance(data, dict):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    lockfile_version = data.get("lockfileVersion")
    packages = data.get("packages")
    if (
        type(lockfile_version) is not int
        or lockfile_version not in _BUN_LOCK_VERSIONS
        or not isinstance(packages, dict)
    ):
        return LockfilePackageVersions(mixed_or_untrusted=True)

    versions: set[str] = set()
    untrusted = False
    declared = False
    for key, value in packages.items():
        key_package = _bun_lock_key_package(key)
        identity = None
        if isinstance(value, list) and value and isinstance(value[0], str):
            identity = _bun_identity(value[0])
        if identity is None:
            if key_package == package:
                untrusted = True
            continue
        name, resolution = identity
        tarball = value[1] if len(value) >= 2 and isinstance(value[1], str) else ""
        if name != package:
            fetches = not _is_local_directory_resolution(resolution)
            if key_package == package or (fetches and (
                _mentions_package(tarball, package)
                or _mentions_package(resolution, package)
            )):
                # The key or the fetched tarball names the package while the
                # record installs another identity: never let an alias or a
                # renamed tarball stand in for the real release.
                untrusted = True
            continue
        # npm records are [identity, registry/tarball URL, metadata, integrity];
        # Bun writes "" for the default registry and downloads any other value
        # verbatim, so it must be this exact release's tarball. Any other
        # resolution (workspace:, link:, file:, git, tarball URL) has no
        # registry version to compare with the denylist.
        if (
            _is_exact_registry_version(resolution)
            and len(value) >= 2
            and isinstance(value[1], str)
            and (not tarball or _tarball_url_matches(tarball, package, resolution))
        ):
            versions.add(resolution)
        else:
            untrusted = True
    workspaces = data.get("workspaces", {})
    if not isinstance(workspaces, dict):
        untrusted = True
    else:
        for workspace in workspaces.values():
            if not isinstance(workspace, dict):
                untrusted = True
                continue
            for field_name in (
                "dependencies", "devDependencies", "optionalDependencies"
            ):
                result = _bun_lock_declares(workspace.get(field_name), package)
                if result is None:
                    untrusted = True
                elif result:
                    declared = True
    for value in packages.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for field_name in ("dependencies", "optionalDependencies"):
                        if _bun_lock_declares(
                            item.get(field_name), package,
                            untrusted_on_malformed=False,
                        ):
                            declared = True
    if declared and not versions:
        # A dependency is declared but no install record establishes which
        # release Bun would fetch; that cannot be certified as a safe version.
        untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


@dataclass(frozen=True)
class _BunLockbPackage:
    name: str
    resolution_tag: int
    version: str | None  # exact registry version, npm resolutions only
    url: str


@dataclass(frozen=True)
class _BunLockbDependency:
    name: str
    behavior: int
    literal: str


@dataclass(frozen=True)
class _BunLockb:
    packages: tuple[_BunLockbPackage, ...]
    dependencies: tuple[_BunLockbDependency, ...]


def _parse_bun_lockb(data: bytes) -> _BunLockb | None:
    """Parse the package and dependency tables of a binary bun.lockb.

    Every offset, length, column size, and buffer annotation is validated; any
    deviation returns None so the caller fails closed instead of guessing.
    """
    header_len = len(_BUN_LOCKB_HEADER)
    if not data.startswith(_BUN_LOCKB_HEADER) or len(data) < header_len + 84:
        return None
    (format_version,) = struct.unpack_from("<I", data, header_len)
    version_size = _BUN_LOCKB_VERSION_SIZES.get(format_version)
    if version_size is None:
        return None
    pos = header_len + 4 + 32  # format + meta hash
    (total_end,) = struct.unpack_from("<Q", data, pos)
    pos += 8
    if total_end > len(data):
        return None
    count, alignment, field_count, begin, end = struct.unpack_from(
        "<QQQQQ", data, pos
    )
    pos += 40
    resolution_size = 16 + version_size
    package_size = 8 + 8 + resolution_size + sum(_BUN_LOCKB_TAIL_COLUMN_SIZES)
    if (
        alignment != 8
        or field_count != 8
        or count == 0
        or begin != (pos + 7) // 8 * 8
        or end != begin + count * package_size
        or end > total_end
    ):
        return None

    buffers: list[bytes] = []
    pos = end
    for element_size in _BUN_LOCKB_BUFFER_SIZES:
        if pos + 16 > total_end:
            return None
        start, stop = struct.unpack_from("<QQ", data, pos)
        annotation = _BUN_LOCKB_ANNOTATION_RE.match(data, pos + 16)
        if annotation is None or int(annotation.group(1)) != element_size:
            return None
        annotation_end = annotation.end()
        if not (
            annotation_end <= start <= stop <= total_end
            and start - annotation_end < 16
            and (stop - start) % element_size == 0
        ):
            return None
        buffers.append(data[start:stop])
        pos = stop
    dependency_bytes, string_bytes = buffers[3], buffers[5]

    # Pointers may repeat or overlap, so a small file could otherwise decode
    # into an enormous volume of strings. Real lockfiles decode to well under
    # their own size; anything far beyond that fails closed.
    decode_budget = max(
        _BUN_LOCKB_DECODE_FACTOR * len(data), _BUN_LOCKB_DECODE_FLOOR
    )
    decoded: dict[bytes, str] = {}

    def string_at(raw: bytes) -> str:
        nonlocal decode_budget
        cached = decoded.get(raw)
        if cached is not None:
            return cached
        if raw[7] & 0x80 == 0:
            value = raw.split(b"\0", 1)[0]
        else:
            offset, size = struct.unpack("<II", raw)
            size &= 0x7FFFFFFF
            if offset + size > len(string_bytes):
                raise ValueError("string out of bounds")
            decode_budget -= size
            if decode_budget < 0:
                raise ValueError("string decode budget exceeded")
            value = string_bytes[offset:offset + size]
        text = value.decode("utf-8", errors="strict")
        decoded[raw] = text
        return text

    names_at = begin
    resolutions_at = begin + 16 * count
    packages: list[_BunLockbPackage] = []
    dependencies: list[_BunLockbDependency] = []
    try:
        for index in range(count):
            name = string_at(data[names_at + 8 * index:names_at + 8 * index + 8])
            record = resolutions_at + resolution_size * index
            tag = data[record]
            url = string_at(data[record + 8:record + 16])
            version: str | None = None
            if tag == _BUN_RESOLUTION_NPM:
                at = record + 16
                if format_version == 3:
                    major, minor, patch = struct.unpack_from("<QQQ", data, at)
                    tag_at = at + 24
                else:
                    major, minor, patch = struct.unpack_from("<III", data, at)
                    tag_at = at + 16
                pre = string_at(data[tag_at:tag_at + 8])
                build = string_at(data[tag_at + 16:tag_at + 24])
                candidate = f"{major}.{minor}.{patch}"
                if pre:
                    candidate += f"-{pre}"
                if build:
                    candidate += f"+{build}"
                if _is_exact_registry_version(candidate):
                    version = candidate
            if index == 0 and tag != _BUN_RESOLUTION_ROOT:
                return None
            packages.append(_BunLockbPackage(name, tag, version, url))
        for offset in range(0, len(dependency_bytes), 26):
            raw = dependency_bytes[offset:offset + 26]
            dependencies.append(_BunLockbDependency(
                name=string_at(raw[0:8]),
                behavior=raw[16],
                literal=string_at(raw[18:26]),
            ))
    except (ValueError, UnicodeError, struct.error):
        return None
    return _BunLockb(tuple(packages), tuple(dependencies))


def _bun_lockb_registry_version(package: _BunLockbPackage) -> str | None:
    """Exact registry version of an npm resolution, cross-checked with its URL."""
    if package.resolution_tag != _BUN_RESOLUTION_NPM or package.version is None:
        return None
    if package.url and not _tarball_url_matches(
        package.url, package.name, package.version
    ):
        return None
    return package.version


def _bun_lockb_lines(parsed: _BunLockb) -> list[str]:
    """Distinct identity-bearing strings of a parsed bun.lockb (name gate)."""
    lines: dict[str, None] = {}
    for package in parsed.packages:
        lines[package.name] = None
        if package.url:
            lines[package.url] = None
    for dependency in parsed.dependencies:
        lines[dependency.name] = None
        lines[dependency.literal] = None
    return list(lines)


def _extract_bun_lockb_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    try:
        if text is not None:
            data = text.encode("latin-1")  # ioc_grep decodes bun.lockb losslessly
        else:
            with lockfile.open("rb") as stream:
                data = stream.read(_LOCKFILE_SIZE_LIMIT + 1)
            if len(data) > _LOCKFILE_SIZE_LIMIT:
                return LockfilePackageVersions(mixed_or_untrusted=True)
    except (OSError, UnicodeError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    parsed = _parse_bun_lockb(data)
    if parsed is None:
        return LockfilePackageVersions(mixed_or_untrusted=True)
    versions: set[str] = set()
    untrusted = False
    checked_urls: set[str] = set()
    for record in parsed.packages:
        if record.name != package:
            if (
                record.resolution_tag not in _BUN_LOCAL_RESOLUTIONS
                and record.url not in checked_urls
            ):
                # Rows may share one (possibly huge) URL string: inspect each
                # distinct URL once so shared pointers cannot amplify work.
                checked_urls.add(record.url)
                if _mentions_package(record.url, package):
                    # Another identity whose fetched tarball/source names the
                    # package: a renamed install cannot clear the name hit.
                    untrusted = True
            continue
        version = _bun_lockb_registry_version(record)
        if version is None:
            untrusted = True
        else:
            versions.add(version)
    declared = any(
        (dependency.name == package and not dependency.behavior & _BUN_DEPENDENCY_PEER)
        or (
            (alias := _npm_alias_target(dependency.literal)) is not None
            and alias[0] == package
        )
        for dependency in parsed.dependencies
    )
    if declared and not versions:
        untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


_LOCKFILE_VERSION_EXTRACTORS: dict[
    str, Callable[[Path, str, str | None], LockfilePackageVersions]
] = {
    "package-lock.json": _extract_package_lock_version_info,
    "yarn.lock": _extract_yarn_lock_version_info,
    "pnpm-lock.yaml": _extract_pnpm_lock_version_info,
    "bun.lock": _extract_bun_lock_version_info,
    "bun.lockb": _extract_bun_lockb_version_info,
    "Cargo.lock": _extract_cargo_lock_version_info,
}
assert set(_LOCKFILE_VERSION_EXTRACTORS) == set(_LOCKFILE_POLICY_ECOSYSTEMS)
_IOC_VERSION_ECOSYSTEMS = frozenset(_LOCKFILE_POLICY_ECOSYSTEMS.values())


def _extract_lockfile_version_info(
    lockfile: Path, package: str, text: str | None = None
) -> LockfilePackageVersions:
    extractor = _LOCKFILE_VERSION_EXTRACTORS.get(lockfile.name)
    if extractor is None:
        return LockfilePackageVersions(mixed_or_untrusted=True)
    return extractor(lockfile, package, text)


def _has_malicious_osv_family(vulns: list[dict]) -> bool:
    """Return true when OSV identifies malicious code in the package/version."""
    malicious_markers = {"malicious-code", "malicious code"}

    for vuln in vulns:
        identifiers = [vuln.get("id")]
        aliases = vuln.get("aliases")
        if isinstance(aliases, list):
            identifiers.extend(aliases)
        if any(
            isinstance(identifier, str) and identifier.startswith("MAL-")
            for identifier in identifiers
        ):
            return True
        for field_name in ("database_specific", "ecosystem_specific"):
            stack = [vuln.get(field_name)]
            seen_containers: set[int] = set()
            visited = 0
            while stack and visited < _OSV_MARKER_NODE_LIMIT:
                value = stack.pop()
                visited += 1
                if isinstance(value, str):
                    normalized = value.strip().lower().replace("_", "-")
                    if normalized in malicious_markers:
                        return True
                elif isinstance(value, (list, dict)):
                    identity = id(value)
                    if identity in seen_containers:
                        continue
                    seen_containers.add(identity)
                    stack.extend(value if isinstance(value, list) else value.values())
    return False


def _is_bounded_osv_marker_tree(value: object) -> bool:
    """Return false if a consumed advisory subtree exceeds its work budget."""
    stack = [value]
    seen_containers: set[int] = set()
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > _OSV_MARKER_NODE_LIMIT:
            return False
        if isinstance(node, (list, dict)):
            identity = id(node)
            if identity in seen_containers:
                continue
            seen_containers.add(identity)
            stack.extend(node if isinstance(node, list) else node.values())
    return True


def _is_schema_valid_osv_vuln(vuln: dict[object, object]) -> bool:
    """Validate every OSV field consumed by malicious-package classification."""
    vuln_id = vuln.get("id")
    if not isinstance(vuln_id, str) or not vuln_id or len(vuln_id) > 512:
        return False
    aliases = vuln.get("aliases", [])
    if not isinstance(aliases, list) or any(
        not isinstance(alias, str) or not alias or len(alias) > 512
        for alias in aliases
    ):
        return False
    for field_name in ("database_specific", "ecosystem_specific"):
        value = vuln.get(field_name, {})
        if not isinstance(value, dict) or not _is_bounded_osv_marker_tree(value):
            return False
    return True


def query_osv_api(
    package: str,
    version: str | None = None,
    *,
    ecosystem: str,
) -> OsvApiClassification:
    """Query OSV for an exact version; failure means fallback is unavailable."""
    payload: dict[str, object] = {
        "package": {"name": package, "ecosystem": ecosystem}
    }
    if version is not None:
        payload["version"] = version
    try:
        request = urllib.request.Request(
            _OSV_API,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "coldclone-ioc-scan",
            },
        )
        with urllib.request.urlopen(
            request, timeout=_OSV_TIMEOUT_SECONDS
        ) as response:
            raw = response.read(_OSV_RESPONSE_LIMIT + 1)
        if len(raw) > _OSV_RESPONSE_LIMIT:
            return OsvApiClassification(
                status="failed", diagnostic="response-too-large"
            )
        duplicate_key = False

        def object_pairs(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            nonlocal duplicate_key
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    duplicate_key = True
                result[key] = value
            return result

        def reject_constant(value: str) -> object:
            raise ValueError(f"non-standard JSON constant: {value}")

        data = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
        if duplicate_key:
            return OsvApiClassification(
                status="failed", diagnostic="duplicate-response-key"
            )
        if not isinstance(data, dict):
            return OsvApiClassification(
                status="failed", diagnostic="malformed-response"
            )
        vulns = data.get("vulns", [])
        if not isinstance(vulns, list) or any(
            not isinstance(vuln, dict) or not _is_schema_valid_osv_vuln(vuln)
            for vuln in vulns
        ):
            return OsvApiClassification(
                status="failed", diagnostic="malformed-vulns"
            )
        return OsvApiClassification(status="success", vulns=vulns)
    except urllib.error.URLError as exc:
        return OsvApiClassification(
            status="failed", diagnostic=f"urlerror:{exc.reason}"
        )
    except (
        OSError, UnicodeError, ValueError, RecursionError,
    ) as exc:
        return OsvApiClassification(
            status="failed", diagnostic=f"{type(exc).__name__}:{exc}"
        )


def _yaml_has_unsupported_quoting(text: str, *, yarn_classic: bool) -> bool:
    """True when yarn/pnpm text leaves the plain subset lockfile writers emit.

    Rejected: a quoted scalar with an escape (other than `\\\\`/`\\"`) or one
    spanning lines; a tag `!`, anchor `&`, alias `*`, block scalar `|`/`>`,
    explicit key `?`, or merge key `<<`; an unbalanced flow collection; and
    any line outside a flow collection that is not a comment, a `- item`, or a
    `key:`/`key: value` entry (Yarn Classic: or `key value`), i.e. a continued
    plain scalar. (Flow collections may span lines: Prettier formats pnpm
    lockfiles that way.)
    Each can spell, move, or hide an identity or URL (`ke\\u0079v`, a folded
    or literal line break, `!!str "..."`, `*payload`) where the line-based gate
    and extractors cannot see it. A quote or indicator counts only where YAML
    starts a node (line start, after `:`/`-`/`?` plus whitespace, inside a flow
    collection, or right after a quoted key's colon; Yarn Classic quotes also
    after whitespace), so `don't` or `workspace:*` in plain text are fine.
    One linear pass per line.
    """
    flow_depth = 0
    flow_key_indent = 0  # indent of the line whose value is the open flow
    last_content = None  # previous non-blank, non-comment line content
    last_indent = 0
    for line in _YAML_LINE_BREAK_RE.split(text):
        quote = None
        previous = ""  # last non-space character outside quotes
        in_flow = flow_depth > 0
        content_end = len(line)
        stripped = line.strip()
        if last_content is None and stripped and not stripped.startswith("#"):
            if line[:1].isspace():
                return True  # an indented root mapping
        if (
            in_flow
            and stripped
            and not stripped.startswith("#")
            and len(line) - len(line.lstrip()) <= flow_key_indent
        ):
            return True  # a flow continuation line dedented out of its key
        index = 0
        while index < len(line):
            char = line[index]
            if quote == '"':
                if char == "\\":
                    if line[index + 1:index + 2] not in ("\\", '"'):
                        return True
                    index += 2
                    continue
                if char == '"':
                    quote = None
                    previous = '"'
                index += 1
                continue
            if quote == "'":
                if char == "'":
                    if line[index + 1:index + 2] == "'":
                        index += 2
                        continue
                    quote = None
                    previous = "'"
                index += 1
                continue
            if char == "#" and (index == 0 or line[index - 1] in " \t"):
                content_end = index
                break  # comment
            at_node_start = (
                index == 0
                or (
                    previous in ("", "[", "{", ",", ":", "-", "?")
                    and line[index - 1] in " \t"
                )
                or (previous in ("[", "{", ",") and line[index - 1] == previous)
                or (line[index - 1] == ":" and line[index - 2:index - 1] in ("'", '"'))
            )
            if at_node_start and (
                char in "!&*|>"
                or (char == "?" and line[index + 1:index + 2] in ("", " ", "\t"))
                or (char == "<" and line.startswith("<<", index))
            ):
                return True
            if char in "\"'" and (
                previous in ("", ":", "-", "[", "{", ",")
                or (yarn_classic and line[index - 1] in " \t")
            ):
                quote = char
            elif char in "[{" and (flow_depth or at_node_start):
                if not flow_depth and not (
                    previous in (":", "-")  # an inline value: `key: {...}`
                    or (
                        # Prettier: `key:` then the flow value on the next,
                        # more indented line.
                        previous == ""
                        and last_content is not None
                        and last_content.endswith(":")
                        and len(line) - len(line.lstrip()) > last_indent
                    )
                ):
                    return True  # a flow collection standing in for keys
                if not flow_depth:
                    flow_key_indent = (
                        len(line) - len(line.lstrip())
                        if previous in (":", "-")
                        else last_indent
                    )
                flow_depth += 1
                in_flow = True
            elif char in "]}" and flow_depth:
                flow_depth -= 1
            if char not in " \t":
                previous = char
            index += 1
        if quote is not None:
            return True
        content = line[:content_end].strip()
        if content and not in_flow:
            last_content = content
            last_indent = len(line) - len(line.lstrip())
        elif content:
            last_content = content
        if content and not in_flow and not (
            content == "-"
            or content.startswith("- ")
            or content.endswith(":")
            or ": " in content
            or ":\t" in content
            # Yarn Classic writes `key value` pairs.
            or (yarn_classic and len(content.split(None, 1)) == 2)
        ):
            return True  # a continued plain scalar or other construct
    return flow_depth > 0


def _has_unsupported_identity_encoding(lockfile_name: str, text: str) -> bool:
    """Reject encodings our bounded exact extractors cannot safely interpret."""
    if lockfile_name in _YAML_LOCKFILES:
        return _yaml_has_unsupported_quoting(
            text,
            yarn_classic=lockfile_name == "yarn.lock"
            and _YARN_BERRY_METADATA_RE.search(text) is None,
        )
    if lockfile_name != "Cargo.lock":
        return False
    if _CARGO_INVALID_LINE_BREAK_RE.search(text):
        return True
    in_package = False
    for line in text.replace("\r\n", "\n").split("\n"):
        if _CARGO_PACKAGE_HEADER_RE.fullmatch(line):
            in_package = True
            continue
        loose = line.strip()
        if loose.startswith("[") and _CARGO_TABLE_HEADER_RE.fullmatch(line) is None:
            # Only ASCII space/tab are TOML structural whitespace. A malformed
            # boundary must not terminate a package block and hide identities.
            return True
        if loose.startswith("[[") and "package" in loose:
            # A package-table-like header outside the supported TOML grammar
            # can otherwise make following identity fields look like metadata.
            return True
        if _CARGO_TABLE_HEADER_RE.fullmatch(line):
            in_package = False
            continue
        if (
            in_package
            and (
                _CARGO_QUOTED_KEY_RE.match(line.lstrip()) is not None
                or (
                    _CARGO_IDENTITY_LIKE_RE.match(line)
                    and _CARGO_IDENTITY_ASSIGNMENT_RE.fullmatch(line) is None
                )
            )
        ):
            return True
    return False


def _display_safe(text: str) -> str:
    """Escape control and non-ASCII characters before printing hostile text,
    so escape sequences, lookalikes, or bidi characters cannot rewrite or
    disguise what the operator sees."""
    return "".join(
        char if " " <= char < "\x7f" and char != "\\"
        else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def _yaml_scalar_text(value: str) -> str:
    """A one-line YAML value without quotes or a trailing ` #` comment."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        return _strip_balanced_yaml_scalar(value) or ""
    comment = value.find(" #")
    return value if comment == -1 else value[:comment].rstrip()


def _remote_fetch_source(value: str) -> tuple[str, str] | None:
    """(host label, url) when a fetch field's URL is outside the default
    registries.

    `value` is one fetch field (a `resolved`/`tarball`/`repo`/... value), so
    it holds one URL: everything after its first `://` is that URL, and a
    URL-shaped query value is never read as another source. After dropping
    tab/CR/LF (as URL parsers do), the host is shown only when the authority
    ends at `/`, `?`, `#` or `\\`, and only the part after its last `@`:
    userinfo may hold a token and is never echoed, and an authority cut short
    (a comma, quote, or space) could still be userinfo.
    """
    value = _canonical_url_text(value)
    marker = value.find("://")
    if marker == -1:
        return None
    scheme_start = marker
    while scheme_start > 0 and value[scheme_start - 1] in _URL_SCHEME_CHARS:
        scheme_start -= 1
    while scheme_start < marker and not value[scheme_start].isalpha():
        scheme_start += 1
    if scheme_start == marker:
        return None
    scheme = value[scheme_start:marker].lower()
    after = marker + 3
    authority_end = _URL_AUTHORITY_END_RE.search(value, after)
    stop = authority_end.start() if authority_end else len(value)
    # `\\` ends the authority only for WHATWG special schemes; elsewhere
    # (`git+ssh`) it can sit inside userinfo, so the host is withheld.
    terminated = authority_end is not None and (
        value[stop] in "/?#"
        or (value[stop] == "\\" and scheme in _URL_SPECIAL_SCHEMES)
    )
    host = _HOST_RE.match(value[after:stop].rsplit("@", 1)[-1]).group().lower()
    if terminated and scheme == "https" and host in _DEFAULT_NPM_REGISTRY_HOSTS:
        return None
    label = (_display_safe(host) or "(no host)") if terminated else "(host not shown)"
    if scheme != "https":
        label = f"{_display_safe(scheme)}://{label}"
    return label, value[scheme_start:]


def ioc_grep(
    lockfiles: list[Path],
    iocs: Mapping[str, IocEntry],
    remote_sources: dict[str, dict[Path, set[str]]] | None = None,
) -> tuple[list[IocHit], list[Path]]:
    """Scan each lockfile line-by-line and return (IocHit records, unreadable).

    Hits carry the matched identity, lockfile/policy lines, and structured
    version evidence for later conservative classification. `unreadable` lists
    discovered lockfiles that could not be read; the caller FAILS CLOSED on
    those because an unscanned lockfile prevents certifying the repo clean.
    When `remote_sources` is given, it is filled with the npm-family fetch
    URLs on non-default hosts ({host label: {lockfile: {url}}}) for the
    non-gating registry-host advisory.
    """
    # Normalized view of the IoC set for PyPI matching (built once).
    iocs_pep503 = {_pep503(i): i for i in iocs}
    hits: list[IocHit] = []
    unreadable: list[Path] = []
    total_bytes = 0
    aggregate_limit_reached = False
    for lf in lockfiles:
        if aggregate_limit_reached:
            unreadable.append(lf)
            continue
        try:
            remaining_bytes = _LOCKFILE_TOTAL_SIZE_LIMIT - total_bytes
            read_limit = min(_LOCKFILE_SIZE_LIMIT + 1, remaining_bytes + 1)
            with lf.open("rb") as stream:
                raw = stream.read(read_limit)
            total_bytes += len(raw)
            if total_bytes > _LOCKFILE_TOTAL_SIZE_LIMIT:
                aggregate_limit_reached = True
                unreadable.append(lf)
                continue
            if len(raw) > _LOCKFILE_SIZE_LIMIT:
                unreadable.append(lf)
                continue
            if lf.name == "bun.lockb":
                # Binary: latin-1 is a lossless bytes<->str mapping, so the
                # exact extractor can recover the original bytes later.
                text = raw.decode("latin-1")
            else:
                strict = lf.name in _JSON_LOCKFILES or lf.name in _JSONC_LOCKFILES
                text = raw.decode("utf-8", errors="strict" if strict else "replace")
        except (OSError, UnicodeError):
            unreadable.append(lf)
            continue
        is_pypi = lf.name in _PYPI_LOCKFILES
        is_npm = _LOCKFILE_POLICY_ECOSYSTEMS.get(lf.name) == "npm"
        recorded_in_file: set[str] = set()

        def note_sources(value: str) -> None:
            """Record one fetch field's URL for the registry-host advisory."""
            if (
                remote_sources is None
                or not is_npm
                or "://" not in _canonical_url_text(value)
            ):
                return
            source = _remote_fetch_source(value)
            if source is not None:
                label, url = source
                remote_sources.setdefault(label, {}).setdefault(lf, set()).add(url)

        def record_candidates(value: str, line_no: int) -> None:
            # npm-family managers download recorded tarball URLs verbatim and
            # registries percent-decode paths, so `%6beyv` must still surface
            # `keyv`, and URL credentials must not hide the path.
            forms = _percent_decodings(value) if is_npm else (value,)
            candidates = (
                cand
                for form in forms
                for tok in _TOKEN_RE.findall(form)
                for cand in _candidates(tok)
            )
            if is_npm and ":" in value:
                # `_url_path_identities` checks each normalized form (a tab
                # inside `https:\t//` is dropped by URL parsers).
                candidates = itertools.chain(
                    candidates, sorted(_url_path_identities(value))
                )
            for cand in candidates:
                matched = None
                if cand in iocs:
                    matched = cand
                elif is_pypi:
                    matched = iocs_pep503.get(_pep503(cand))
                if matched and matched not in recorded_in_file:
                    entry = iocs[matched]
                    hits.append(IocHit(
                        lockfile=lf,
                        ioc=entry.name,
                        lockfile_line_no=line_no,
                        ioc_line_no=entry.line_no,
                        version_evidence=entry.version_evidence,
                        affected_set_complete=entry.affected_set_complete,
                        lockfile_text=text,
                    ))
                    recorded_in_file.add(matched)

        if lf.name == "bun.lockb":
            parsed = _parse_bun_lockb(raw)
            if parsed is None:
                # Surface any raw identity first, but an unparsed binary
                # lockfile cannot be certified clean.
                for line in text.splitlines():
                    record_candidates(line, 0)
                unreadable.append(lf)
                continue
            # Tokenize parsed identities, not raw bytes: the string buffer is
            # unseparated, so raw runs can merge adjacent names.
            for line in _bun_lockb_lines(parsed):
                record_candidates(line, 0)
            # Rows may share one URL string: inspect each distinct URL once.
            for url in dict.fromkeys(
                package.url
                for package in parsed.packages
                if package.resolution_tag not in _BUN_LOCAL_RESOLUTIONS
            ):
                note_sources(url)
            continue

        unsupported_encoding = _has_unsupported_identity_encoding(lf.name, text)
        for line_no, line in enumerate(text.splitlines(), start=1):
            record_candidates(line, line_no)
            if (
                lf.name == "yarn.lock"
                and not unsupported_encoding
                and ":" in line
                and line[:1].isspace()
            ):
                # Only a fetch field, read as one URL; comments and other
                # text are never fetch sources.
                content = line.strip()
                for key in ("resolved", "resolution"):
                    value = _yarn_field_value(content, key)
                    if value is not None:
                        note_sources(_yaml_scalar_text(value))
        if lf.name == "pnpm-lock.yaml" and not unsupported_encoding:
            for node in _yaml_mapping_index(text.splitlines()).nodes:
                if "://" not in _canonical_url_text(node.value):
                    continue
                # A flow mapping spread over lines leaves `{ tarball` keys
                # and `url,` values in the line index.
                key = node.key.lstrip("{[, \t")
                if key in ("tarball", "repo"):
                    note_sources(_yaml_scalar_text(node.value.rstrip(",]} \t")))
                elif key == "resolution":
                    fields = _parse_yaml_flow_mapping(node.value)
                    for field_name in ("tarball", "repo"):
                        if fields is not None and field_name in fields:
                            note_sources(fields[field_name])
                    if fields is None and remote_sources is not None:
                        # A remote resolution we cannot split into fields:
                        # flag it without echoing any of its text.
                        remote_sources.setdefault(
                            "(unparsed resolution)", {}
                        ).setdefault(lf, set()).add(node.value)

        if unsupported_encoding:
            # Raw matches still surface first, but an encoded identity invisible
            # to the textual gate cannot be certified clean by a partial parser.
            unreadable.append(lf)
            continue

        if lf.name in _JSON_LOCKFILES or lf.name in _JSONC_LOCKFILES:
            duplicate_key = False

            def object_pairs(
                pairs: list[tuple[str, object]],
            ) -> dict[str, object]:
                nonlocal duplicate_key
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        duplicate_key = True
                    result[key] = value
                return result

            try:
                if lf.name in _JSONC_LOCKFILES:
                    decoded, duplicate_key = _load_jsonc(text)
                else:
                    decoded = json.loads(text, object_pairs_hook=object_pairs)
            except (ValueError, RecursionError):
                # Raw scanning still gets to surface a definitive hit first, but
                # malformed structured input cannot be certified clean: escaped
                # JSON identifiers may otherwise be invisible in serialized text.
                unreadable.append(lf)
                continue
            if duplicate_key:
                unreadable.append(lf)
                continue
            stack = [decoded]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    stack.extend(value.values())
                    strings = value.keys()
                    if lf.name not in _JSONC_LOCKFILES:
                        # package-lock: only fetch fields, not funding/repo
                        # metadata URLs.
                        for field_name in ("resolved", "version"):
                            field = value.get(field_name)
                            if isinstance(field, str):
                                note_sources(field)
                elif isinstance(value, list):
                    stack.extend(value)
                    continue
                elif isinstance(value, str):
                    strings = (value,)
                    if lf.name in _JSONC_LOCKFILES:
                        note_sources(value)
                else:
                    continue
                for string in strings:
                    # Decoded JSON may reveal `ke\u0079v` as `keyv`. Only add
                    # aggregate evidence for identities raw text did not expose.
                    record_candidates(string, 0)
    return hits, unreadable


def classify_ioc_hits(
    hits: list[IocHit], *, use_osv: bool = False
) -> list[IocHit]:
    """Apply package-wide or exact-version malicious-package policy.

    A plain-only entry blocks every version. Once VERSION records exist for an
    ecosystem, only trusted exact intersections block locally. OSV is an
    opportunistic supplement: an exact malicious-code advisory adds a hit, but
    a clean response or unavailable API leaves the locally disjoint version
    safe. Structurally ambiguous version evidence remains a hit because no safe
    exact version was established; integrity metadata is not part of the
    package-version identity, and the extractors only trust a recorded
    tarball URL that is exactly that release's.
    """
    classified: list[IocHit] = []
    processed_version_aware: set[tuple[Path, str, str]] = set()
    extraction_counts: dict[Path, int] = {}
    osv_cache: dict[tuple[str, str, str], OsvApiClassification] = {}
    osv_query_count = 0

    def query(package: str, ecosystem: str, version: str) -> OsvApiClassification:
        nonlocal osv_query_count
        key = (ecosystem, package, version)
        if key not in osv_cache:
            if osv_query_count >= _OSV_QUERY_LIMIT:
                osv_cache[key] = OsvApiClassification(
                    status="failed", diagnostic="per-scan-query-budget-exhausted"
                )
            else:
                osv_query_count += 1
                osv_cache[key] = query_osv_api(
                    package, version, ecosystem=ecosystem
                )
        return osv_cache[key]

    for hit in hits:
        ecosystem = _LOCKFILE_POLICY_ECOSYSTEMS.get(hit.lockfile.name)
        evidence = hit.version_evidence.get(ecosystem or "", ())
        if not evidence:
            classified.append(hit)
            continue

        aggregate_key = (hit.lockfile, hit.ioc, ecosystem or "")
        if aggregate_key in processed_version_aware:
            continue
        processed_version_aware.add(aggregate_key)

        extraction_count = extraction_counts.get(hit.lockfile, 0) + 1
        extraction_counts[hit.lockfile] = extraction_count
        if extraction_count > _VERSION_EXTRACTION_LIMIT_PER_LOCKFILE:
            # Refuse rather than perform attacker-amplified reparsing or clear a
            # candidate whose exact version was not established within budget.
            classified.append(hit)
            continue

        version_info = _extract_lockfile_version_info(
            hit.lockfile, hit.ioc, hit.lockfile_text
        )
        if version_info.mixed_or_untrusted:
            classified.append(hit)
            continue
        if not version_info.versions:
            # The exact extractor found no installed package record. The grep
            # match came from non-install metadata such as a peer-dependency
            # key, so there is no release to compare with the denylist.
            continue

        matched = [
            (version, line_no)
            for version, line_no in evidence
            if version in version_info.versions
        ]
        if matched:
            for version, line_no in matched:
                classified.append(replace(
                    hit,
                    lockfile_line_no=0,
                    ioc_line_no=line_no,
                    versions=(version,),
                    ecosystem=ecosystem,
                    verification="ioc-list-version-match",
                    whole_file_kind="curated-version-pair",
                ))
            continue

        if use_osv:
            for version in version_info.versions:
                result = query(hit.ioc, ecosystem or "", version)
                if result.status == "success" and _has_malicious_osv_family(
                    result.vulns
                ):
                    classified.append(replace(
                        hit,
                        lockfile_line_no=0,
                        versions=(version,),
                        ecosystem=ecosystem,
                        verification="osv-malicious-version-match",
                        whole_file_kind="osv-version-pair",
                    ))
    return classified


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", type=Path, help="path to the cloned repo to scan")
    ap.add_argument("--ioc-list", type=Path, default=_DEFAULT_IOC_LIST,
                    help=f"IoC list file (default: {_DEFAULT_IOC_LIST})")
    ap.add_argument(
        "--offline",
        action="store_true",
        help=(
            "disable opportunistic exact-version OSV malicious-package lookups"
        ),
    )
    args = ap.parse_args()

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"error: not a directory: {repo}", file=sys.stderr)
        return 3  # config error -> FAIL CLOSED (the caller must HALT, not proceed)

    try:
        iocs, stale_days = load_ioc_list(args.ioc_list)
    except IocListError as e:
        print(f"error: invalid IoC list: {e}", file=sys.stderr)
        return 3  # the gate cannot run without its denylist -> FAIL CLOSED, never
                  # exit 1 (which the caller treats as "proceed"): a missing/
                  # unreadable/invalid list must HALT, not disable the gate.

    # An empty (truncated/corrupt) denylist cannot check anything -> FAIL CLOSED,
    # never report clean. A repo with no lockfiles, by contrast, is legitimately
    # clean (nothing to scan) and proceeds.
    if not iocs:
        print(f"error: IoC list {args.ioc_list} is empty — the gate cannot run; "
              f"refusing to certify clean", file=sys.stderr)
        return 3

    try:
        lockfiles, symlinked, traversal_errors = discover_lockfiles(repo)
        remote_sources: dict[str, dict[Path, set[str]]] = {}
        name_hits, unreadable = ioc_grep(lockfiles, iocs, remote_sources)
        hits = classify_ioc_hits(name_hits, use_osv=not args.offline)
    except Exception as exc:
        print(
            f"error: IoC scan failed unexpectedly ({type(exc).__name__}: {exc}) "
            "— cannot certify clean; failing closed",
            file=sys.stderr,
        )
        return 3

    if remote_sources:
        # Non-gating: a denylist cannot judge what an arbitrary host serves.
        print(
            "ioc_scan: NOTE (non-gating) — npm-family lockfiles fetch packages "
            "from outside the default registries. The IoC list cannot vouch "
            "for what these hosts serve, and a hand-edited lockfile can point "
            "any package at them; confirm each host is expected before "
            "installing:",
            file=sys.stderr,
        )
        ranked = sorted(
            remote_sources.items(),
            key=lambda item: (-sum(len(urls) for urls in item[1].values()), item[0]),
        )
        for label, by_lockfile in ranked[:_REMOTE_SOURCE_DISPLAY_LIMIT]:
            count = sum(len(urls) for urls in by_lockfile.values())
            files = sorted(
                _display_safe(str(lf.relative_to(repo))) for lf in by_lockfile
            )
            shown = ", ".join(files[:3]) + (
                f", +{len(files) - 3} more" if len(files) > 3 else ""
            )
            print(f"  {label}: {count} URL(s) in {shown}", file=sys.stderr)
        if len(ranked) > _REMOTE_SOURCE_DISPLAY_LIMIT:
            print(
                f"  … and {len(ranked) - _REMOTE_SOURCE_DISPLAY_LIMIT} more host(s)",
                file=sys.stderr,
            )

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
        for hit in hits:
            rel = hit.lockfile.relative_to(repo)
            if hit.whole_file_kind == "curated-version-pair":
                version = hit.versions[0]
                print(
                    f"  HIT: {hit.ioc}@{version}  in  {rel}:whole-file "
                    "(curated exact-version match)",
                    file=sys.stderr,
                )
                print(
                    f"       policy: {args.ioc_list}:{hit.ioc_line_no}  "
                    f"ecosystem: {hit.ecosystem}  verification: "
                    f"{hit.verification}",
                    file=sys.stderr,
                )
            elif hit.whole_file_kind == "osv-version-pair":
                version = hit.versions[0]
                print(
                    f"  HIT: {hit.ioc}@{version}  in  {rel}:whole-file "
                    "(OSV malicious-version match)",
                    file=sys.stderr,
                )
                print(
                    f"       source: OSV API  ecosystem: {hit.ecosystem}  "
                    f"verification: {hit.verification}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"  HIT: {hit.ioc}  in  {rel}:{hit.lockfile_line_no}",
                    file=sys.stderr,
                )
                if hit.versions or hit.verification != "name-only":
                    versions = ", ".join(hit.versions) or "unparsed"
                    print(
                        f"       locked versions: {versions}  "
                        f"ecosystem: {hit.ecosystem or 'unknown'}  "
                        f"verification: {hit.verification}",
                        file=sys.stderr,
                    )
        return 2

    # Discovered lockfiles we could not actually scan (unreadable, or a symlink we
    # refuse to follow) were NOT scanned -> FAIL CLOSED.
    unscanned = unreadable + symlinked
    if unscanned or traversal_errors:
        print(
            "error: lockfile coverage was incomplete — cannot certify clean; "
            "failing closed:",
            file=sys.stderr,
        )
        for lf in unscanned:
            kind = "symlink" if lf in symlinked else "unreadable"
            print(f"  {kind}: {lf.relative_to(repo)}", file=sys.stderr)
        for path in traversal_errors:
            try:
                display = path.relative_to(repo)
            except ValueError:
                display = path
            print(f"  traversal-error: {display}", file=sys.stderr)
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
