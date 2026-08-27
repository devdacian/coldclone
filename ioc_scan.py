#!/usr/bin/env python3
"""ioc_scan.py — known-malicious-dependency tripwire for an untrusted repo.

Greps every discoverable lockfile in a freshly cloned untrusted repo for any
package identity on the bundled IoC list (`ioc-list.txt` next to this script).
Plain entries are conservative package-wide triggers. Structured VERSION records
add exact positive evidence for disclosed compromised releases; because those
records may be incomplete, an unlisted or unparseable version never clears a
plain-name hit.

This runs FIRST in the coldclone flow, on the HOST, right after the hardened
clone and BEFORE sanitize + moving the tree into an isolation environment:

  - It only READS lockfiles (no install, no build, no code execution), so it is
    safe to run on an untrusted tree.
  - A hit HALTs prep (exit 2) so the repo is caught up front — the human decides
    whether to treat the repo as hostile or to examine it deliberately inside
    their isolation environment.

This is an identity-exact denylist (high precision via exact identity matching;
it catches only KNOWN drops, and its few residual false positives fail SAFE —
see the accepted limitation below). Trusted exact-version evidence is extracted
locally from npm-family and Cargo lockfiles without OSV or network access. It
complements — never replaces — the auto-execution sanitizer
(`sanitize_repo.py`) and the isolation boundary.

Exit codes: 0 clean, 1 IoC-list stale (>7 days) but no hit, 2 IoC hit (HALT),
3 config error — the gate could not actually run, so FAIL CLOSED and HALT:
IoC list missing / unreadable / EMPTY / invalid, a discovered lockfile that
could not be scanned (unreadable, or a symlink we refuse to follow), or a bad
repo path. Only 0 and 1 mean "no malicious dependency found — proceed" (1 also
flags a stale or header-less list). A repo with simply no lockfiles is
legitimately clean -> 0.

Usage: python3 ioc_scan.py <repo-dir> [--ioc-list <path>]

Known limitation (accepted): plain package entries are not tagged by ecosystem,
so a slash-delimited path component (e.g. a go.sum module owner
`github.com/<org>/...`) is matched against the whole cross-ecosystem plain-name
list. A benign module whose owner equals an npm/PyPI IoC name can therefore
false-HALT. This fails SAFE (a HALT sends it to human review, never a miss) and
the alternative — matching only the last path component — would instead MISS go
modules whose package is not the last component (e.g. a `/v2` major-version
suffix), which is worse for a tripwire. VERSION ecosystem tags scope only exact
positive evidence and diagnostics; they do not narrow this conservative
plain-name halt rule.

Bundled with the open-source coldclone tool; self-contained (no external deps).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
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


@dataclass
class IocEntry:
    name: str
    line_no: int
    version_evidence: dict[str, tuple[tuple[str, int], ...]] = field(
        default_factory=dict
    )


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


@dataclass(frozen=True)
class LockfilePackageVersions:
    versions: tuple[str, ...] = ()
    mixed_or_untrusted: bool = False


class IocListError(ValueError):
    """The shipped IoC policy could not be read or parsed safely."""


def load_ioc_list(path: Path) -> tuple[dict[str, IocEntry], int | None]:
    """Parse the IoC policy. Returns (ioc_map, stale_days_or_none).

    `stale_days` is days since the `LAST_REFRESHED: YYYY-MM-DD` header, or None
    if absent/malformed. VERSION records are additive exact positive evidence;
    every one must have a corresponding plain package entry.
    """
    if not path.is_file():
        raise IocListError(f"IoC list not found at {path}")
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise IocListError(f"cannot read IoC list {path}: {exc}") from exc

    iocs: dict[str, IocEntry] = {}
    version_records: list[tuple[int, str, str, str]] = []
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
                or not _is_exact_registry_version(version)
            ):
                raise IocListError(
                    f"line {line_no}: invalid VERSION package/version"
                )
            version_records.append((line_no, ecosystem, package, version))
            continue
        if re.match(r"^VERSION(?:\s|$)", stripped):
            raise IocListError(
                f"line {line_no}: malformed reserved VERSION record"
            )
        if "|" in stripped:
            raise IocListError(
                f"line {line_no}: unexpected pipe in IoC policy record"
            )
        iocs.setdefault(stripped, IocEntry(name=stripped, line_no=line_no))

    by_package: dict[str, dict[str, dict[str, int]]] = {}
    for line_no, ecosystem, package, version in version_records:
        if package not in iocs:
            raise IocListError(
                f"line {line_no}: VERSION record for {package!r} has no plain "
                "package entry"
            )
        by_package.setdefault(package, {}).setdefault(ecosystem, {}).setdefault(
            version, line_no
        )
    for package, ecosystems in by_package.items():
        iocs[package].version_evidence = {
            ecosystem: tuple(sorted(versions.items(), key=lambda item: item[1]))
            for ecosystem, versions in ecosystems.items()
        }

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
    following symlinks (os.walk does not follow symlinked dirs by default).
    Returns (regular, symlinked, traversal_errors): a lockfile that is itself a
    SYMLINK is NOT read (following it could be unsafe/exfil) but is also NOT
    silently dropped. Directory traversal errors are likewise retained so the
    caller cannot certify an incompletely walked tree clean. (In the hardened
    prep flow the clone uses core.symlinks=false; these fail-closed paths also
    protect standalone `ioc <dir>` use.)"""
    found: list[Path] = []
    symlinked: list[Path] = []
    traversal_errors: list[Path] = []

    def onerror(exc: OSError) -> None:
        traversal_errors.append(Path(exc.filename) if exc.filename else root)

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name in _LOCKFILE_NAMES:
                p = Path(dirpath) / name
                (symlinked if p.is_symlink() else found).append(p)
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


def _is_exact_registry_version(version: str) -> bool:
    """Return true for a bounded exact registry version, not a range/alias/URL."""
    if not version or len(version) > 128:
        return False
    lowered = version.lower()
    if any(token in lowered for token in (":", "/", "\\", " ", "*")):
        return False
    if lowered.startswith(
        ("^", "~", ">", "<", "=", "workspace", "file", "link", "git", "npm")
    ):
        return False
    return re.fullmatch(r"[0-9][0-9A-Za-z.+_-]*", version) is not None


def _is_policy_package_identity(package: str) -> bool:
    """Validate npm/crates.io identity shapes accepted by VERSION records."""
    return re.fullmatch(
        r"(?:@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)", package
    ) is not None


def _registry_url_package_matches(
    value: object, package: str, version: str, hosts: tuple[str, ...]
) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.netloc.lower() not in hosts:
        return False
    parts = [
        part for part in urllib.parse.unquote(parsed.path).split("/") if part
    ]
    if package.startswith("@"):
        if not (
            len(parts) >= 4
            and "/".join(parts[:2]) == package
            and parts[2] == "-"
        ):
            return False
        basename = parts[3]
        package_basename = package.split("/", 1)[1]
    else:
        if not (len(parts) >= 3 and parts[0] == package and parts[1] == "-"):
            return False
        basename = parts[2]
        package_basename = package
    return basename == f"{package_basename}-{version}.tgz"


def _is_npm_registry_resolved(value: object, package: str, version: str) -> bool:
    return _registry_url_package_matches(
        value, package, version, ("registry.npmjs.org",)
    )


def _has_integrity(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_cargo_registry_source(value: str | None) -> bool:
    return isinstance(value, str) and value in (
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    )


def _extract_package_lock_version_info(
    lockfile: Path, package: str
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
        data = json.loads(
            lockfile.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
        )
    except (OSError, UnicodeError, ValueError, RecursionError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    versions: set[str] = set()
    untrusted = duplicate_key

    def consider(value: object) -> None:
        nonlocal untrusted
        if not isinstance(value, dict):
            untrusted = True
            return
        version = value.get("version")
        if isinstance(version, str) and _is_exact_registry_version(version):
            versions.add(version)
            if not (
                _is_npm_registry_resolved(value.get("resolved"), package, version)
                and _has_integrity(value.get("integrity"))
            ):
                untrusted = True
        else:
            untrusted = True

    def scan_packages(packages: object) -> None:
        nonlocal untrusted
        if not isinstance(packages, dict):
            untrusted = True
            return
        for key, value in packages.items():
            normalized = str(key).replace("\\", "/")
            if normalized == f"node_modules/{package}" or normalized.endswith(
                f"/node_modules/{package}"
            ):
                consider(value)

    def scan_dependencies(dependencies: object) -> None:
        nonlocal untrusted
        if not isinstance(dependencies, dict):
            untrusted = True
            return
        stack = [dependencies]
        while stack:
            deps = stack.pop()
            if package in deps:
                consider(deps.get(package))
            for value in deps.values():
                if isinstance(value, dict) and isinstance(
                    value.get("dependencies"), dict
                ):
                    stack.append(value["dependencies"])

    if not isinstance(data, dict):
        untrusted = True
    else:
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


def _extract_yarn_classic_version_info(
    lines: list[str], package: str
) -> LockfilePackageVersions:
    versions: set[str] = set()
    untrusted = False
    for header, body in _yarn_top_level_blocks(lines):
        descriptors = header.split(",")
        names = {_yarn_descriptor_name(part) for part in descriptors}
        alias_targets = {_yarn_alias_target(part) for part in descriptors}
        if package not in names and package not in alias_targets:
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
        resolved_re = re.compile(prefix + r'resolved\s+"([^"]+)"\s*$')
        integrity_re = re.compile(prefix + r'integrity\s+(\S.*?)\s*$')
        version_values = [
            match.group(1) for line in body if (match := version_re.fullmatch(line))
        ]
        resolved_values = [
            match.group(1) for line in body if (match := resolved_re.fullmatch(line))
        ]
        integrity_values = [
            match.group(1) for line in body if (match := integrity_re.fullmatch(line))
        ]
        if (
            len(version_values) != 1
            or len(resolved_values) != 1
            or len(integrity_values) != 1
        ):
            untrusted = True
            for version in version_values:
                if _is_exact_registry_version(version):
                    versions.add(version)
            continue
        version = version_values[0]
        if _is_exact_registry_version(version):
            versions.add(version)
            if not _registry_url_package_matches(
                resolved_values[0],
                package,
                version,
                ("registry.npmjs.org", "registry.yarnpkg.com"),
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


def _yarn_direct_scalars(body: list[str], key: str) -> list[str | None]:
    populated = [line for line in body if line.strip()]
    if not populated:
        return []
    direct_indent = min(len(line) - len(line.lstrip(" ")) for line in populated)
    pattern = re.compile(
        r"^" + re.escape(" " * direct_indent + key) + r":\s*(.*?)\s*$"
    )
    return [
        _strip_balanced_yaml_scalar(match.group(1))
        for line in body
        if (match := pattern.match(line))
    ]


def _yarn_direct_raw_scalars(body: list[str], key: str) -> list[str]:
    populated = [line for line in body if line.strip()]
    if not populated:
        return []
    direct_indent = min(len(line) - len(line.lstrip(" ")) for line in populated)
    pattern = re.compile(
        r"^" + re.escape(" " * direct_indent + key) + r":\s*(.*?)\s*$"
    )
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
    lockfile: Path, package: str
) -> LockfilePackageVersions:
    try:
        lines = lockfile.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
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
    if len(metadata_versions) != 1 or metadata_versions[0] != "8":
        return LockfilePackageVersions(mixed_or_untrusted=True)
    # A Berry `package@npm:version` locator identifies the resolver protocol,
    # but not the configured registry host. Preserve the parsed versions for
    # diagnostics while refusing to call them authoritative exact evidence.
    return replace(
        _extract_yarn_berry_version_info(blocks, package),
        mixed_or_untrusted=True,
    )


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


def _yaml_mapping_index(lines: list[str]) -> _YamlMappingIndex:
    """Index the mapping-only pnpm subset once, in linear time."""
    nodes: list[_YamlMappingNode] = []
    roots: list[int] = []
    mutable_children: dict[int, list[int]] = {}
    stack: list[int] = []

    for line in lines:
        if not line.strip() or line.lstrip().startswith(("#", "- ")):
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:].rstrip()
        if content[:1] in {"'", '"'}:
            quote = content[0]
            closing = content.find(quote, 1)
            if closing < 0 or not content[closing + 1:].lstrip().startswith(":"):
                continue
            key = content[1:closing]
            value = content[closing + 1:].lstrip()[1:].strip()
        else:
            if ":" not in content:
                continue
            key, value = (part.strip() for part in content.split(":", 1))
        if not key:
            continue
        while stack and nodes[stack[-1]].indent >= indent:
            stack.pop()
        parent = stack[-1] if stack else None
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


def _pnpm_inline_map_values(raw: str, key: str) -> list[str]:
    if not (raw.startswith("{") and raw.endswith("}")):
        return []
    inner = raw[1:-1]
    pattern = re.compile(r"(?:^|,)\s*" + re.escape(key) + r":\s*([^,}]*)")
    return [match.group(1).strip().strip("'\"") for match in pattern.finditer(inner)]


def _pnpm_block_is_registry_backed(
    index: _YamlMappingIndex, start_idx: int, package: str, version: str
) -> bool:
    resolutions = _yaml_child_values(index, start_idx, "resolution")
    if len(resolutions) != 1:
        return False
    resolution_idx, raw = resolutions[0]
    if raw:
        integrities = _pnpm_inline_map_values(raw, "integrity")
        tarballs = _pnpm_inline_map_values(raw, "tarball")
    else:
        integrities = [
            value.strip().strip("'\"")
            for _idx, value in _yaml_child_values(index, resolution_idx, "integrity")
        ]
        tarballs = [
            value.strip().strip("'\"")
            for _idx, value in _yaml_child_values(index, resolution_idx, "tarball")
        ]
    if len(integrities) != 1 or not integrities[0]:
        return False
    if len(tarballs) != 1 or not tarballs[0]:
        return False
    return _registry_url_package_matches(
        tarballs[0], package, version, ("registry.npmjs.org",)
    )


def _pnpm_specifier_is_registry_like(specifier: str | None) -> bool:
    if specifier is None:
        return False
    lowered = specifier.strip().lower().strip("'\"")
    if not lowered:
        return False
    return not lowered.startswith(
        ("file:", "git", "http:", "https:", "link:", "workspace:")
    )


def _extract_pnpm_lock_version_info(
    lockfile: Path, package: str
) -> LockfilePackageVersions:
    try:
        lines = lockfile.read_text(encoding="utf-8", errors="strict").splitlines()
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
    untrusted = len(index.roots) != len(root_by_key)
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
    if _yaml_has_duplicate_child_keys(index, package_section):
        untrusted = True
    direct_package_nodes = set(index.children.get(package_section, ()))
    snapshot_sections = root_by_key.get("snapshots", [])
    if len(snapshot_sections) > 1 or (snapshot_sections and generation != "9.0"):
        untrusted = True
    direct_snapshot_nodes: set[int] = set()
    if len(snapshot_sections) == 1 and generation == "9.0":
        snapshot_section = snapshot_sections[0]
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
        if not _pnpm_block_is_registry_backed(index, idx, package, version):
            untrusted = True
    if not snapshot_versions.issubset(versions):
        untrusted = True

    allowed_maps = {"dependencies", "devDependencies", "optionalDependencies"}
    importer_sections = root_by_key.get("importers", [])
    if len(importer_sections) > 1:
        untrusted = True
    dependency_maps: list[int] = []
    if len(importer_sections) == 1:
        importer_section = importer_sections[0]
        if _yaml_has_duplicate_child_keys(index, importer_section):
            untrusted = True
        for importer in index.children.get(importer_section, ()):
            if _yaml_has_duplicate_child_keys(index, importer):
                untrusted = True
            dependency_maps.extend(
                child
                for child in index.children.get(importer, ())
                if nodes[child].key in allowed_maps
            )
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
    lockfile: Path, package: str
) -> LockfilePackageVersions:
    try:
        text = lockfile.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return LockfilePackageVersions(mixed_or_untrusted=True)
    versions: set[str] = set()
    untrusted = False
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text):
        names = re.findall(r'(?m)^name\s*=\s*"([^"]+)"\s*$', block)
        if package not in names:
            continue
        version_values = re.findall(
            r'(?m)^\s*version\s*=\s*"([^"]+)"\s*$', block
        )
        source_values = re.findall(
            r'(?m)^\s*source\s*=\s*"([^"]+)"\s*$', block
        )
        for version in version_values:
            if _is_exact_registry_version(version):
                versions.add(version)
        if (
            len(names) != 1
            or len(version_values) != 1
            or len(source_values) != 1
            or not _is_exact_registry_version(version_values[0])
            or not _is_cargo_registry_source(source_values[0])
        ):
            untrusted = True
    return LockfilePackageVersions(
        versions=tuple(sorted(versions)), mixed_or_untrusted=untrusted
    )


_LOCKFILE_VERSION_EXTRACTORS: dict[
    str, Callable[[Path, str], LockfilePackageVersions]
] = {
    "package-lock.json": _extract_package_lock_version_info,
    "yarn.lock": _extract_yarn_lock_version_info,
    "pnpm-lock.yaml": _extract_pnpm_lock_version_info,
    "Cargo.lock": _extract_cargo_lock_version_info,
}
assert set(_LOCKFILE_VERSION_EXTRACTORS) == set(_LOCKFILE_POLICY_ECOSYSTEMS)
_IOC_VERSION_ECOSYSTEMS = frozenset(_LOCKFILE_POLICY_ECOSYSTEMS.values())


def _extract_lockfile_version_info(
    lockfile: Path, package: str
) -> LockfilePackageVersions:
    extractor = _LOCKFILE_VERSION_EXTRACTORS.get(lockfile.name)
    if extractor is None:
        return LockfilePackageVersions(mixed_or_untrusted=True)
    return extractor(lockfile, package)


def ioc_grep(
    lockfiles: list[Path], iocs: Mapping[str, IocEntry]
) -> tuple[list[IocHit], list[Path]]:
    """Scan each lockfile line-by-line and return (IocHit records, unreadable).

    Hits carry the matched identity, lockfile/policy lines, and structured
    version evidence for later conservative classification. `unreadable` lists
    discovered lockfiles that could not be read; the caller FAILS CLOSED on
    those because an unscanned lockfile prevents certifying the repo clean.
    """
    # Normalized view of the IoC set for PyPI matching (built once).
    iocs_pep503 = {_pep503(i): i for i in iocs}
    hits: list[IocHit] = []
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
                        entry = iocs[matched]
                        hits.append(IocHit(
                            lockfile=lf,
                            ioc=entry.name,
                            lockfile_line_no=line_no,
                            ioc_line_no=entry.line_no,
                            version_evidence=entry.version_evidence,
                        ))
                        seen.add(matched)
    return hits, unreadable


def classify_ioc_hits(hits: list[IocHit]) -> list[IocHit]:
    """Enrich trusted curated intersections without ever clearing a name hit."""
    classified: list[IocHit] = []
    processed_version_aware: set[tuple[Path, str, str]] = set()
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

        version_info = _extract_lockfile_version_info(hit.lockfile, hit.ioc)
        if not version_info.mixed_or_untrusted:
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

        # VERSION records are incomplete positive evidence, never an allowlist.
        # Unsupported, untrusted, malformed, and disjoint extraction all retain
        # the original package-wide name hit and therefore the same hard halt.
        classified.append(hit)
    return classified


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
        name_hits, unreadable = ioc_grep(lockfiles, iocs)
        hits = classify_ioc_hits(name_hits)
    except Exception as exc:
        print(
            f"error: IoC scan failed unexpectedly ({type(exc).__name__}: {exc}) "
            "— cannot certify clean; failing closed",
            file=sys.stderr,
        )
        return 3

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
            else:
                print(
                    f"  HIT: {hit.ioc}  in  {rel}:{hit.lockfile_line_no}",
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
