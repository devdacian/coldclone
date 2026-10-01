"""Regression tests for the known-malicious dependency tripwire."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

import ioc_scan


def _policy(path: Path, *records: str) -> Path:
    path.write_text(
        f"LAST_REFRESHED: {date.today().isoformat()}\n" + "\n".join(records) + "\n",
        encoding="utf-8",
    )
    return path


def _scan_hits(
    repo: Path, policy: Path, *, use_osv: bool = False
) -> list[ioc_scan.IocHit]:
    iocs, _ = ioc_scan.load_ioc_list(policy)
    lockfiles, symlinked, traversal_errors = ioc_scan.discover_lockfiles(repo)
    assert not symlinked
    assert not traversal_errors
    hits, unreadable = ioc_scan.ioc_grep(lockfiles, iocs)
    assert not unreadable
    return ioc_scan.classify_ioc_hits(hits, use_osv=use_osv)


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    repo: Path,
    policy: Path,
    *extra_args: str,
) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        ["ioc_scan.py", str(repo), "--ioc-list", str(policy), *extra_args],
    )
    return ioc_scan.main()


def test_version_policy_is_additive_order_independent_and_keeps_provenance(
    tmp_path: Path,
) -> None:
    policy = _policy(
        tmp_path / "ioc.txt",
        "VERSION: npm | keyv | 6.0.0",
        "keyv",
        "VERSION: npm | keyv | 6.0.0",
        "VERSION: npm | keyv | 6.1.0",
        "AFFECTED_SET_COMPLETE: npm | keyv",
        "VERSION: npm | keyv | 6.1.0",
    )
    iocs, stale = ioc_scan.load_ioc_list(policy)
    assert stale == 0
    assert iocs["keyv"].line_no == 3
    assert iocs["keyv"].version_evidence == {
        "npm": (("6.0.0", 2), ("6.1.0", 5))
    }
    assert iocs["keyv"].affected_set_complete == {"npm": 6}


def test_new_distinct_version_reopens_complete_set_until_refinalized(
    tmp_path: Path,
) -> None:
    reopened = _policy(
        tmp_path / "reopened.txt",
        "keyv",
        "VERSION: npm | keyv | 6.0.0",
        "AFFECTED_SET_COMPLETE: npm | keyv",
        "VERSION: npm | keyv | 6.1.0",
    )
    iocs, _ = ioc_scan.load_ioc_list(reopened)
    assert iocs["keyv"].affected_set_complete == {}
    assert tuple(
        version for version, _line in iocs["keyv"].version_evidence["npm"]
    ) == ("6.0.0", "6.1.0")

    reclosed = _policy(
        tmp_path / "reclosed.txt",
        "keyv",
        "VERSION: npm | keyv | 6.0.0",
        "AFFECTED_SET_COMPLETE: npm | keyv",
        "VERSION: npm | keyv | 6.1.0",
        "AFFECTED_SET_COMPLETE: npm | keyv",
    )
    iocs, _ = ioc_scan.load_ioc_list(reclosed)
    assert iocs["keyv"].affected_set_complete.keys() == {"npm"}


@pytest.mark.parametrize(
    "record, diagnostic",
    [
        ("VERSION npm | keyv | 6.0.0", "malformed reserved"),
        ("VERSION: npm | keyv", "malformed VERSION"),
        ("VERSION: npm | | 6.0.0", "malformed VERSION"),
        ("VERSION: pypi | keyv | 6.0.0", "no trusted exact extractor"),
        ("VERSION: npm | keyv | v6.0.0", "invalid VERSION"),
        ("VERSION: npm | keyv | ^6.0.0", "invalid VERSION"),
        ("VERSION: npm | keyv | 1!6.0.0", "invalid VERSION"),
        ("VERSION: npm | keyv | 6_0_0", "invalid VERSION"),
        ("VERSION: npm | keyv | 6..0", "invalid VERSION"),
        ("VERSION: npm | keyv | 6.0.", "invalid VERSION"),
        ("VERSION: npm | keyv | 01.2.3", "invalid VERSION"),
        ("VERSION: npm | keyv | 1.2.3-01", "invalid VERSION"),
        ("VERSION: npm | bad package | 6.0.0", "invalid VERSION"),
        ("VERSION: npm | a/b | 6.0.0", "invalid VERSION"),
        ("bad package", "invalid plain package identity"),
        ("@broken-scope", "invalid plain package identity"),
        ("github.com//broken", "invalid plain package identity"),
        (
            "AFFECTED_SET_COMPLETE npm | keyv",
            "malformed reserved AFFECTED_SET_COMPLETE",
        ),
        (
            "AFFECTED_SET_COMPLETE: pypi | keyv",
            "no trusted exact extractor",
        ),
        (
            "AFFECTED_SET_COMPLETE: npm | keyv | 6.0.0",
            "malformed AFFECTED_SET_COMPLETE",
        ),
        (
            "AFFECTED_SET_COMPLETE: npm | bad package",
            "invalid AFFECTED_SET_COMPLETE",
        ),
        (
            "AFFECTED_SET_COMPLETE: npm | keyv",
            "no earlier distinct VERSION",
        ),
        ("keyv | 6.0.0", "unexpected pipe"),
    ],
)
def test_malformed_version_policy_fails_closed(
    tmp_path: Path, record: str, diagnostic: str
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", record)
    with pytest.raises(ioc_scan.IocListError, match=diagnostic):
        ioc_scan.load_ioc_list(policy)


def test_version_policy_requires_plain_fallback_entry(tmp_path: Path) -> None:
    policy = _policy(tmp_path / "ioc.txt", "VERSION: npm | keyv | 6.0.0")
    with pytest.raises(ioc_scan.IocListError, match="no plain package entry"):
        ioc_scan.load_ioc_list(policy)


def test_plain_identity_starting_with_version_word_is_not_a_directive(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "VERSION-control")
    iocs, _ = ioc_scan.load_ioc_list(policy)
    assert set(iocs) == {"VERSION-control"}


def test_invalid_utf8_and_empty_policy_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    invalid = tmp_path / "invalid.txt"
    invalid.write_bytes(b"LAST_REFRESHED: 2026-08-25\nkeyv\n\xff")
    assert _run_main(monkeypatch, repo, invalid) == 3
    assert "invalid IoC list" in capsys.readouterr().err

    empty = tmp_path / "empty.txt"
    empty.write_text("# comments only\n", encoding="utf-8")
    assert _run_main(monkeypatch, repo, empty) == 3
    assert "is empty" in capsys.readouterr().err


def test_malformed_version_policy_cli_is_exit_3_not_exit_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | ^6")
    assert _run_main(monkeypatch, repo, policy) == 3
    assert "invalid IoC list" in capsys.readouterr().err


def test_canonical_policy_has_pinned_version_and_complete_set_shape() -> None:
    iocs, _ = ioc_scan.load_ioc_list(Path(__file__).with_name("ioc-list.txt"))
    actual = {
        (ecosystem, package, version)
        for package, entry in iocs.items()
        for ecosystem, versions in entry.version_evidence.items()
        for version, _line in versions
    }
    expected_sentinels = {
        ("npm", "keyv", "6.0.0"),
        ("npm", "flat-cache", "6.1.24"),
        ("npm", "file-entry-cache", "11.1.6"),
        ("npm", "cacheable-request", "13.0.20"),
        ("npm", "@cacheable/utils", "2.5.1"),
        ("npm", "cacheable", "2.5.1"),
        ("npm", "@cacheable/memory", "2.2.1"),
        ("npm", "cache-manager", "7.2.10"),
        ("npm", "@cacheable/node-cache", "3.1.2"),
        ("npm", "ecto", "5.0.1"),
        ("npm", "@cacheable/net", "2.1.1"),
        ("npm", "@tanstack/react-router", "1.169.8"),
        ("npm", "@injectivelabs/sdk-ts", "1.20.21"),
        ("npm", "jscrambler", "8.20.0"),
        ("npm", "@joyfill/layouts", "0.1.2-2773.beta.0"),
        ("npm", "@memtensor/memos-cloud-openclaw-plugin", "0.1.25"),
        ("npm", "@nubjs/types", "0.9.4"),
        ("crates.io", "arrayref", "0.3.10"),
        ("crates.io", "greentic-setup", "1.3.1-dev.34027618345"),
    }
    assert len(actual) == 2400
    assert expected_sentinels <= actual
    assert len(iocs) == 6471
    assert sum(bool(entry.version_evidence) for entry in iocs.values()) == 521

    complete = {
        (ecosystem, package)
        for package, entry in iocs.items()
        for ecosystem in entry.affected_set_complete
    }
    assert len(complete) == 63
    assert {
        ("npm", "@tanstack/react-router"),
        ("npm", "@injectivelabs/sdk-ts"),
        ("npm", "jscrambler"),
        ("npm", "@joyfill/layouts"),
    } <= complete


def test_policy_ecosystem_and_extractor_maps_have_bidirectional_parity() -> None:
    assert set(ioc_scan._LOCKFILE_VERSION_EXTRACTORS) == set(
        ioc_scan._LOCKFILE_POLICY_ECOSYSTEMS
    )
    assert ioc_scan._IOC_VERSION_ECOSYSTEMS == frozenset({"npm", "crates.io"})
    assert {
        ioc_scan._LOCKFILE_POLICY_ECOSYSTEMS[name]
        for name in ioc_scan._LOCKFILE_VERSION_EXTRACTORS
    } == ioc_scan._IOC_VERSION_ECOSYSTEMS


def test_trusted_package_lock_intersection_reports_exact_policy_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "6.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
                "integrity": "sha512-test",
            }
        },
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )

    hits = _scan_hits(repo, policy)
    assert [(h.ioc, h.versions, h.ioc_line_no, h.lockfile_line_no) for h in hits] == [
        ("keyv", ("6.0.0",), 3, 0)
    ]
    assert hits[0].verification == "ioc-list-version-match"
    assert _run_main(monkeypatch, repo, policy) == 2
    err = capsys.readouterr().err
    assert "keyv@6.0.0" in err
    assert "whole-file (curated exact-version match)" in err
    assert f"policy: {policy}:3" in err


def test_trusted_package_lock_disjoint_version_is_safe_without_finalizer(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz",
                "integrity": "sha512-ok",
            }
        }
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy) == []


@pytest.mark.parametrize(
    "resolved,integrity",
    [
        ("https://evil.invalid/keyv/-/keyv-5.0.0.tgz", "sha512-ok"),
        ("https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz", ""),
    ],
)
def test_package_lock_source_metadata_does_not_override_safe_disjoint_version(
    tmp_path: Path, resolved: str, integrity: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": resolved,
                "integrity": integrity,
            }
        }
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy) == []


def test_legacy_complete_marker_does_not_change_version_scoped_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(
        tmp_path / "ioc.txt",
        "keyv",
        "VERSION: npm | keyv | 6.0.0",
        "AFFECTED_SET_COMPLETE: npm | keyv",
    )

    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz",
                "integrity": "sha512-ok",
            }
        },
    }), encoding="utf-8")
    assert _scan_hits(trusted, policy) == []
    assert _run_main(monkeypatch, trusted, policy, "--offline") == 0

    untrusted = tmp_path / "untrusted"
    untrusted.mkdir()
    (untrusted / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": "https://evil.invalid/keyv/-/keyv-5.0.0.tgz",
                "integrity": "sha512-ok",
            }
        },
    }), encoding="utf-8")
    assert _scan_hits(untrusted, policy) == []


def test_package_lock_v1_walk_is_iterative_and_collects_nested_version(
    tmp_path: Path,
) -> None:
    nested: dict[str, object] = {
        "keyv": {
            "version": "6.0.0",
            "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
            "integrity": "sha512-test",
        }
    }
    for index in range(400):
        nested = {f"wrapper-{index}": {"dependencies": nested}}
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps({"lockfileVersion": 1, "dependencies": nested}),
        encoding="utf-8",
    )
    assert ioc_scan._extract_lockfile_version_info(
        lockfile, "keyv"
    ) == ioc_scan.LockfilePackageVersions(("6.0.0",), False)


def test_package_lock_v2_requires_coherent_legacy_and_packages_views(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    record = {
        "version": "6.0.0",
        "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
        "integrity": "sha512-test",
    }
    lockfile.write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/keyv": record},
        "dependencies": {"keyv": record},
    }), encoding="utf-8")
    assert ioc_scan._extract_lockfile_version_info(
        lockfile, "keyv"
    ) == ioc_scan.LockfilePackageVersions(("6.0.0",), False)


@pytest.mark.parametrize("generation", [None, 0, 4, 999, "3", True])
def test_package_lock_missing_or_unknown_generation_falls_back(
    tmp_path: Path, generation: object
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    data: dict[str, object] = {
        "packages": {
            "node_modules/keyv": {
                "version": "6.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
                "integrity": "sha512-test",
            }
        }
    }
    if generation is not None:
        data["lockfileVersion"] = generation
    (repo / "package-lock.json").write_text(json.dumps(data), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "name-only"


def test_package_lock_duplicate_json_key_falls_back(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/keyv":{'
        '"version":"6.0.0",'
        '"resolved":"https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",'
        '"resolved":"https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",'
        '"integrity":"sha512-test"}}}',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    iocs, _ = ioc_scan.load_ioc_list(policy)
    lockfiles, _, _ = ioc_scan.discover_lockfiles(repo)
    name_hits, unreadable = ioc_scan.ioc_grep(lockfiles, iocs)
    assert unreadable == [repo / "package-lock.json"]
    assert ioc_scan.classify_ioc_hits(name_hits)[0].verification == "name-only"


def test_huge_json_integer_falls_back_to_name_hit_and_wrapper_refuses(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0",'
        '"resolved":"https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",'
        '"integrity":"sha512-test","hostile":' + "9" * 10000 + "}}}",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    iocs, _ = ioc_scan.load_ioc_list(policy)
    lockfiles, _, _ = ioc_scan.discover_lockfiles(repo)
    name_hits, unreadable = ioc_scan.ioc_grep(lockfiles, iocs)
    assert unreadable == [repo / "package-lock.json"]
    hits = ioc_scan.classify_ioc_hits(name_hits)
    assert len(hits) == 1
    assert hits[0].ioc == "keyv"
    assert hits[0].verification == "name-only"

    cp = subprocess.run(
        [str(Path(__file__).with_name("coldclone.sh")), "scan", str(repo)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert cp.returncode == 1
    assert "KNOWN-MALICIOUS dependency" in cp.stderr


@pytest.mark.parametrize("plain_only", [False, True])
def test_json_escaped_package_identity_cannot_bypass_scan(
    tmp_path: Path, plain_only: bool
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/ke\\u0079v":'
        '{"version":"6.0.0"}}}',
        encoding="utf-8",
    )
    records = ["keyv"]
    if not plain_only:
        records.append("VERSION: npm | keyv | 6.0.0")
    hits = _scan_hits(repo, _policy(tmp_path / "ioc.txt", *records))
    assert len(hits) == 1
    assert hits[0].ioc == "keyv"
    if not plain_only:
        assert hits[0].versions == ("6.0.0",)


def test_duplicate_json_container_cannot_hide_escaped_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion":3,"pack\\u0061ges":{'
        '"node_modules/ke\\u0079v":{"version":"6.0.0"}},"packages":{}}',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 3


@pytest.mark.parametrize(
    "record",
    [
        {"name": "keyv", "version": "6.0.0"},
        {"version": "npm:keyv@6.0.0"},
    ],
)
def test_package_lock_npm_alias_target_uses_target_version(
    tmp_path: Path, record: dict[str, str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/friendly-alias": record},
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].versions == ("6.0.0",)


def test_unresolved_npm_alias_target_remains_blocking_name_hit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"friendly-alias": "npm:keyv@^6.0.0"}}
        },
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "name-only"


def test_unexpected_extractor_exception_is_fail_closed_exit_3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0"}}}',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )

    def explode(_lockfile: Path, _package: str) -> ioc_scan.LockfilePackageVersions:
        raise RuntimeError("extractor exploded")

    monkeypatch.setitem(
        ioc_scan._LOCKFILE_VERSION_EXTRACTORS, "package-lock.json", explode
    )
    assert _run_main(monkeypatch, repo, policy) == 3
    err = capsys.readouterr().err
    assert "failed unexpectedly" in err
    assert "cannot certify clean; failing closed" in err


def test_yarn_classic_and_structurally_valid_berry_locators_are_exact(
    tmp_path: Path,
) -> None:
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    classic = tmp_path / "classic"
    classic.mkdir()
    (classic / "yarn.lock").write_text(
        'keyv@^6.0.0:\n'
        '  version "6.0.0"\n'
        '  resolved "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"\n'
        '  integrity sha512-test\n',
        encoding="utf-8",
    )
    berry = tmp_path / "berry"
    berry.mkdir()
    (berry / "yarn.lock").write_text(
        "__metadata:\n  version: 8\n\n"
        '"keyv@npm:^6.0.0":\n'
        "  version: 6.0.0\n"
        '  resolution: "keyv@npm:6.0.0"\n'
        "  conditions: os=darwin\n",
        encoding="utf-8",
    )
    assert _scan_hits(classic, policy)[0].versions == ("6.0.0",)
    berry_hit = _scan_hits(berry, policy)[0]
    assert berry_hit.verification == "ioc-list-version-match"
    assert berry_hit.versions == ("6.0.0",)


def test_yarn_berry_trusted_disjoint_version_is_safe(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        "__metadata:\n  version: 8\n\n"
        '"@injectivelabs/sdk-ts@npm:^1.18.0":\n'
        "  version: 1.18.19\n"
        '  resolution: "@injectivelabs/sdk-ts@npm:1.18.19"\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "@injectivelabs/sdk-ts",
        "VERSION: npm | @injectivelabs/sdk-ts | 1.20.21",
    )
    assert _scan_hits(repo, policy) == []


def test_yarn_classic_version_identity_does_not_borrow_metadata_from_next_block(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        'keyv@^6.0.0:\n'
        '  version "6.0.0"\n'
        'other@^1.0.0:\n'
        '  version "1.0.0"\n'
        '  resolved "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"\n'
        '  integrity sha512-borrowed\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "ioc-list-version-match"


def test_yarn_classic_duplicate_nonidentity_metadata_does_not_hide_version(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        'keyv@^6.0.0:\n'
        '  version "6.0.0"\n'
        '  resolved "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"\n'
        '  resolved "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"\n'
        '  integrity sha512-test\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "ioc-list-version-match"


@pytest.mark.parametrize(
    "text",
    [
        "__metadata: malformed\nkeyv@^6.0.0:\n  version \"6.0.0\"\n",
        '"__metadata":\n  version: "8"\n\n'
        '"keyv@npm:^6.0.0":\n  version: 6.0.0\n'
        '  resolution: "keyv@npm:6.0.0"\n',
        "__metadata:\n  version: 8\n\n"
        '"keyv@workspace:.":\n  version: 6.0.0\n'
        '  resolution: "keyv@workspace:."\n',
    ],
)
def test_yarn_ambiguous_or_unsupported_shapes_fall_back(
    tmp_path: Path, text: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(text, encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert hits and all(hit.verification == "name-only" for hit in hits)


@pytest.mark.parametrize("generation", ["6", "8", "9"])
def test_yarn_berry_numeric_metadata_generations_are_supported(
    tmp_path: Path, generation: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        f"__metadata:\n  version: {generation}\n\n"
        '"keyv@npm:^6.0.0":\n'
        "  version: 6.0.0\n"
        '  resolution: "keyv@npm:6.0.0"\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "ioc-list-version-match"


def test_unknown_yarn_berry_metadata_generation_remains_name_hit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        "__metadata:\n  version: 999\n\n"
        '"keyv@npm:^5.0.0":\n'
        "  version: 5.0.0\n"
        '  resolution: "keyv@npm:5.0.0"\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "name-only"


def test_escaped_yarn_identity_fails_closed_instead_of_clearing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yarn.lock").write_text(
        "__metadata:\n  version: 8\n\n"
        '"ke\\u0079v@npm:^6.0.0":\n'
        "  version: 6.0.0\n"
        '  resolution: "ke\\u0079v@npm:6.0.0"\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 3


def test_pnpm_trusted_intersection_and_workspace_fallback(tmp_path: Path) -> None:
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv:\n"
        "        specifier: 6.0.0\n"
        "        version: 6.0.0\n"
        "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n"
        "snapshots:\n"
        "  keyv@6.0.0:\n"
        "    dependencies:\n"
        "      left-pad: 1.3.0\n",
        encoding="utf-8",
    )
    assert _scan_hits(trusted, policy)[0].versions == ("6.0.0",)

    untrusted = tmp_path / "untrusted"
    untrusted.mkdir()
    (untrusted / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv:\n"
        "        specifier: workspace:*\n"
        "        version: 6.0.0\n"
        "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
        encoding="utf-8",
    )
    hits = _scan_hits(untrusted, policy)
    assert hits[0].verification == "name-only"


def test_pnpm_metadata_only_name_match_with_no_package_record_is_safe(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  other@1.0.0:\n"
        "    peerDependencies:\n"
        "      keyv: ^6.0.0\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy) == []


def test_structurally_ambiguous_disjoint_version_stays_a_name_hit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  keyv@5.0.0:\n"
        "  keyv@5.0.0:\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "name-only"


@pytest.mark.parametrize(
    "resolution",
    [
        "    resolution: {integrity:}\n",
        "    resolution: {integrity: sha512-test}\n"
        "    resolution: {integrity: sha512-test}\n",
        "    resolution:\n      integrity:\n",
        "    resolution: {integrity: sha512-test, "
        "tarball: https://evil.invalid/keyv/-/keyv-6.0.0.tgz}\n",
    ],
)
def test_pnpm_resolution_metadata_does_not_hide_exact_version(
    tmp_path: Path, resolution: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv:\n"
        "        specifier: 6.0.0\n"
        "        version: 6.0.0\n"
        "packages:\n"
        "  keyv@6.0.0:\n"
        + resolution,
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].verification == "ioc-list-version-match"


def test_pnpm_importer_never_borrows_nested_version_or_specifier(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv:\n"
        "        nested:\n"
        "          specifier: 6.0.0\n"
        "          version: 6.0.0\n"
        "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-test}\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].verification == "name-only"


@pytest.mark.parametrize(
    "generation_line",
    [
        "",
        "lockfileVersion: '4.0'\n",
        "lockfileVersion: '99.0'\n",
        "lockfileVersion: 9\n",
        "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\n",
    ],
)
def test_pnpm_missing_malformed_duplicate_or_unknown_generation_falls_back(
    tmp_path: Path, generation_line: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        generation_line
        + "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].verification == "name-only"


@pytest.mark.parametrize(
    "body",
    [
        "packages:\n"
        "  wrapper:\n"
        "    keyv@6.0.0:\n"
        "      resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      wrapper:\n"
        "        keyv:\n"
        "          specifier: 6.0.0\n"
        "          version: 6.0.0\n"
        "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
    ],
)
def test_pnpm_nested_package_or_dependency_identity_is_not_trusted(
    tmp_path: Path, body: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n" + body, encoding="utf-8"
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].verification == "name-only"


def test_pnpm_sequence_under_packages_is_unsupported_and_remains_name_hit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  - keyv@5.0.0:\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "name-only"


def test_escaped_pnpm_identity_fails_closed_instead_of_clearing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        '  "ke\\u0079v@6.0.0":\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 3


def test_pnpm_hostile_nested_candidates_build_one_linear_structure_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    nested = ["lockfileVersion: '9.0'", "packages:"]
    for depth in range(300):
        nested.append("  " * (depth + 1) + "keyv@6.0.0:")
    nested.append(
        "  " * 301
        + "resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}"
    )
    (repo / "pnpm-lock.yaml").write_text("\n".join(nested) + "\n", encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    original = ioc_scan._yaml_mapping_index
    calls = 0

    def counted(lines: list[str]) -> ioc_scan._YamlMappingIndex:
        nonlocal calls
        calls += 1
        return original(lines)

    monkeypatch.setattr(ioc_scan, "_yaml_mapping_index", counted)
    assert _scan_hits(repo, policy)[0].verification == "name-only"
    assert calls == 1


@pytest.mark.parametrize(
    "ambiguous",
    [
        "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-one, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-two, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv: 6.0.0\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv: 6.0.0\n",
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv: 6.0.0\n"
        "    dependencies:\n"
        "      keyv: 6.0.0\n",
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv: 6.0.0\n"
        "      keyv: 6.0.0\n",
    ],
)
def test_pnpm_duplicate_semantic_mapping_keys_fall_back(
    tmp_path: Path, ambiguous: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    package_record = (
        "packages:\n"
        "  keyv@6.0.0:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n"
    )
    if ambiguous.startswith("packages:"):
        package_record = ""
    (repo / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n" + ambiguous + package_record,
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].verification == "name-only"


@pytest.mark.parametrize(
    "generation,package_key",
    [
        ("5.4", "/keyv/6.0.0"),
        ("6.0", "/keyv@6.0.0"),
        ("9.0", "keyv@6.0.0"),
        ("9.0", "/keyv@6.0.0"),
    ],
)
def test_pnpm_supported_generation_specific_layouts_are_trusted(
    tmp_path: Path, generation: str, package_key: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        f"lockfileVersion: '{generation}'\n"
        "packages:\n"
        f"  {package_key}:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].versions == ("6.0.0",)


@pytest.mark.parametrize(
    "generation,package_key",
    [
        ("5.4", "keyv@6.0.0"),
        ("5.4", "/keyv@6.0.0"),
        ("6.0", "/keyv/6.0.0"),
        ("6.0", "keyv@6.0.0"),
        ("9.0", "/keyv/6.0.0"),
    ],
)
def test_pnpm_cross_generation_package_key_layouts_fall_back(
    tmp_path: Path, generation: str, package_key: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pnpm-lock.yaml").write_text(
        f"lockfileVersion: '{generation}'\n"
        "packages:\n"
        f"  {package_key}:\n"
        "    resolution: {integrity: sha512-test, "
        "tarball: https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz}\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert _scan_hits(repo, policy)[0].verification == "name-only"


@pytest.mark.parametrize(
    "source",
    [
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
        "git+https://evil.invalid/logtrace",
        None,
    ],
)
def test_cargo_source_metadata_does_not_hide_exact_version(
    tmp_path: Path, source: str | None
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source_line = f'source = "{source}"\n' if source else ""
    (repo / "Cargo.lock").write_text(
        "[[package]]\n"
        'name = "logtrace"\n'
        'version = "1.2.3"\n'
        + source_line,
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].versions == ("1.2.3",)
    assert hits[0].verification == "ioc-list-version-match"


@pytest.mark.parametrize(
    "extra,verification",
    [
        ('version = "1.2.3"\n', "name-only"),
        (
            'source = "sparse+https://index.crates.io/"\n',
            "ioc-list-version-match",
        ),
        ('name = "logtrace"\n', "name-only"),
    ],
)
def test_cargo_duplicate_identity_is_ambiguous_but_source_is_metadata(
    tmp_path: Path, extra: str, verification: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_text(
        "[[package]]\n"
        'name = "logtrace"\n'
        'version = "1.2.3"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        + extra,
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    assert _scan_hits(repo, policy)[0].verification == verification


def test_cargo_literal_string_identity_supports_exact_version(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_text(
        "[[package]]\nname = 'logtrace'\nversion = '1.2.3'\n",
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].versions == ("1.2.3",)


def test_cargo_indentation_and_inline_comments_preserve_exact_identity(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_text(
        "  [[ package ]] # generated metadata\n"
        '  name = "logtrace" # package identity\n'
        '  version = "1.2.3" # exact release\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].versions == ("1.2.3",)


@pytest.mark.parametrize(
    "identity_lines",
    [
        '"name" = "logtrace"\n"version" = "1.2.3"\n',
        'name\u00a0=\u00a0"logtrace"\nversion = "1.2.3"\n',
    ],
)
def test_unsupported_cargo_key_or_whitespace_syntax_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity_lines: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_text(
        "[[package]]\n" + identity_lines,
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 3


@pytest.mark.parametrize(
    "boundary",
    [
        "\u00a0[metadata]",
        "[metadata\u00a0]",
        "[metadata]\v",
        "[metadata]\f",
        "[metadata]\x85",
        "[metadata]\u2028",
        "[metadata]\u2029",
    ],
)
def test_malformed_unicode_cargo_table_boundary_cannot_hide_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_text(
        '[[package]]\nname = "logtrace"\nversion = "1.0.0"\n'
        f'{boundary}\nname = "logtrace"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 2


def test_bare_cr_cargo_boundary_cannot_hide_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_bytes(
        b'[[package]]\nname = "logtrace"\nversion = "1.0.0"\n'
        b'[metadata]\rname = "logtrace"\nversion = "1.2.3"\n'
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 2


def test_escaped_cargo_identity_fails_closed_instead_of_clearing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.lock").write_text(
        '[[package]]\nname = "log\\u0074race"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt",
        "logtrace",
        "VERSION: crates.io | logtrace | 1.2.3",
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 3


def test_pep503_matching_and_scoped_npm_nonmatch_regressions(tmp_path: Path) -> None:
    pypi = tmp_path / "pypi"
    pypi.mkdir()
    (pypi / "requirements.txt").write_text(
        "Mnemonic.To.Address==1.0\n", encoding="utf-8"
    )
    pypi_policy = _policy(tmp_path / "pypi-ioc.txt", "mnemonic_to_address")
    assert _scan_hits(pypi, pypi_policy)[0].ioc == "mnemonic_to_address"

    npm = tmp_path / "npm"
    npm.mkdir()
    (npm / "package-lock.json").write_text(
        '{"packages":{"node_modules/@other/node-loggers":{"version":"1.0.0"}}}',
        encoding="utf-8",
    )
    npm_policy = _policy(tmp_path / "npm-ioc.txt", "node-loggers")
    assert _scan_hits(npm, npm_policy) == []


def test_version_aware_repeated_tokens_dedupe_to_one_aggregate_hit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "6.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
                "integrity": "sha512-a",
            },
            "node_modules/wrapper/node_modules/keyv": {
                "version": "6.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
                "integrity": "sha512-b",
            },
        }
    }, indent=2), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].versions == ("6.0.0",)


def test_exact_extraction_budget_fails_safe_as_name_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {"version": "5.0.0"},
            "node_modules/flat-cache": {"version": "5.0.0"},
        },
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt",
        "keyv",
        "VERSION: npm | keyv | 6.0.0",
        "flat-cache",
        "VERSION: npm | flat-cache | 6.0.0",
    )
    monkeypatch.setattr(ioc_scan, "_VERSION_EXTRACTION_LIMIT_PER_LOCKFILE", 1)

    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].verification == "name-only"
    assert hits[0].ioc in {"keyv", "flat-cache"}


def test_repeated_plain_identity_is_one_bounded_hit_per_lockfile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "node-loggers==1.0.0\n" * 10_000, encoding="utf-8"
    )
    policy = _policy(tmp_path / "ioc.txt", "node-loggers")
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].lockfile_line_no == 1


def test_hit_precedes_unrelated_symlinked_lockfile_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"dependencies":{"node-loggers":{"version":"1.0.0"}}}',
        encoding="utf-8",
    )
    (repo / "requirements.txt").symlink_to(tmp_path / "outside.txt")
    policy = _policy(tmp_path / "ioc.txt", "node-loggers")
    assert _run_main(monkeypatch, repo, policy) == 2


def test_symlinked_directory_is_fail_closed_coverage_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package-lock.json").write_text("{}", encoding="utf-8")
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    policy = _policy(tmp_path / "ioc.txt", "keyv")

    assert _run_main(monkeypatch, repo, policy) == 3
    assert "symlink: linked" in capsys.readouterr().err


def test_oversized_lockfile_fails_closed_without_reading_past_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text("{}" + " " * 32, encoding="utf-8")
    policy = _policy(tmp_path / "ioc.txt", "keyv")
    monkeypatch.setattr(ioc_scan, "_LOCKFILE_SIZE_LIMIT", 8)

    assert _run_main(monkeypatch, repo, policy) == 3
    assert "unreadable: package-lock.json" in capsys.readouterr().err


def test_aggregate_lockfile_bytes_are_bounded_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for index in range(2):
        nested = repo / str(index)
        nested.mkdir()
        (nested / "package-lock.json").write_text("{}", encoding="utf-8")
    policy = _policy(tmp_path / "ioc.txt", "keyv")
    monkeypatch.setattr(ioc_scan, "_LOCKFILE_TOTAL_SIZE_LIMIT", 2)

    assert _run_main(monkeypatch, repo, policy) == 3
    assert "unreadable:" in capsys.readouterr().err


def test_version_classification_reuses_budgeted_lockfile_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    lockfile = repo / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":'
        '{"node_modules/keyv":{"version":"6.0.0"}}}',
        encoding="utf-8",
    )
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    iocs, _stale = ioc_scan.load_ioc_list(policy)
    name_hits, unreadable = ioc_scan.ioc_grep([lockfile], iocs)
    assert not unreadable

    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("version extraction reread a lockfile")
        ),
    )
    hits = ioc_scan.classify_ioc_hits(name_hits)
    assert len(hits) == 1
    assert hits[0].versions == ("6.0.0",)


def test_discovery_entry_and_lockfile_counts_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_repo = tmp_path / "entries"
    entry_repo.mkdir()
    (entry_repo / "a").mkdir()
    (entry_repo / "b").mkdir()
    monkeypatch.setattr(ioc_scan, "_DISCOVERY_ENTRY_LIMIT", 1)
    _found, _symlinked, errors = ioc_scan.discover_lockfiles(entry_repo)
    assert any(path.name == ".coldclone-entry-limit-exceeded" for path in errors)

    lock_repo = tmp_path / "locks"
    lock_repo.mkdir()
    for index in range(2):
        nested = lock_repo / str(index)
        nested.mkdir()
        (nested / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(ioc_scan, "_DISCOVERY_ENTRY_LIMIT", 100)
    monkeypatch.setattr(ioc_scan, "_LOCKFILE_COUNT_LIMIT", 1)
    found, _symlinked, errors = ioc_scan.discover_lockfiles(lock_repo)
    assert len(found) == 1
    assert any(path.name == ".coldclone-lockfile-limit-exceeded" for path in errors)


def test_discovery_entry_budget_stops_lazy_iterator_without_overconsumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    requested = 0

    class Entry:
        def __init__(self, index: int) -> None:
            self.name = f"ordinary-{index}"
            self.path = str(repo / self.name)

        def is_symlink(self) -> bool:
            return False

        def is_dir(self, *, follow_symlinks: bool) -> bool:
            return False

        def is_file(self, *, follow_symlinks: bool) -> bool:
            return True

    class LazyScan:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self):
            return self

        def __next__(self) -> Entry:
            nonlocal requested
            requested += 1
            if requested > 2:
                raise AssertionError("entry iterator consumed past its budget")
            return Entry(requested)

    monkeypatch.setattr(ioc_scan, "_DISCOVERY_ENTRY_LIMIT", 2)
    monkeypatch.setattr(ioc_scan.os, "scandir", lambda _path: LazyScan())
    _found, _symlinked, errors = ioc_scan.discover_lockfiles(repo)
    assert requested == 2
    assert any(path.name == ".coldclone-entry-limit-exceeded" for path in errors)


def test_directory_traversal_error_is_fail_closed_not_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    hidden = repo / "hidden"
    policy = _policy(tmp_path / "ioc.txt", "keyv")

    def broken_scandir(_root: Path):
        error = PermissionError("denied")
        error.filename = str(hidden)
        raise error

    monkeypatch.setattr(ioc_scan.os, "scandir", broken_scandir)
    assert _run_main(monkeypatch, repo, policy) == 3
    assert "traversal-error: hidden" in capsys.readouterr().err


def test_definitive_hit_precedes_directory_traversal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    lockfile = repo / "package-lock.json"
    lockfile.write_text(
        '{"dependencies":{"node-loggers":{"version":"1.0.0"}}}',
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "ioc.txt", "node-loggers")
    monkeypatch.setattr(
        ioc_scan,
        "discover_lockfiles",
        lambda _root: ([lockfile], [], [repo / "hidden"]),
    )
    assert _run_main(monkeypatch, repo, policy) == 2


def test_no_lockfiles_is_clean_without_calling_osv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    monkeypatch.setattr(
        ioc_scan,
        "query_osv_api",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("OSV must not be queried without a name hit")
        ),
    )
    assert _run_main(monkeypatch, repo, policy) == 0


def test_offline_disables_osv_but_disjoint_exact_version_stays_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz",
                "integrity": "sha512-ok",
            }
        },
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    monkeypatch.setattr(
        ioc_scan,
        "query_osv_api",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("--offline must disable OSV")
        ),
    )
    assert _run_main(monkeypatch, repo, policy, "--offline") == 0


@pytest.mark.parametrize(
    "result",
    [
        ioc_scan.OsvApiClassification(status="success", vulns=[]),
        ioc_scan.OsvApiClassification(
            status="success", vulns=[{"id": "GHSA-ordinary-vulnerability"}]
        ),
        ioc_scan.OsvApiClassification(
            status="failed", diagnostic="network-unavailable"
        ),
    ],
)
def test_osv_clean_normal_cve_or_unavailable_does_not_override_local_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: ioc_scan.OsvApiClassification,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz",
                "integrity": "sha512-ok",
            }
        },
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    calls: list[tuple[str, str | None, str]] = []

    def fake_query(
        package: str, version: str | None = None, *, ecosystem: str
    ) -> ioc_scan.OsvApiClassification:
        calls.append((package, version, ecosystem))
        return result

    monkeypatch.setattr(ioc_scan, "query_osv_api", fake_query)
    assert _scan_hits(repo, policy, use_osv=True) == []
    assert calls == [("keyv", "5.0.0", "npm")]


def test_osv_exact_malicious_advisory_adds_version_hit_and_is_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": "5.0.0",
                "resolved": "https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz",
                "integrity": "sha512-ok",
            }
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    nested = repo / "nested"
    nested.mkdir()
    (nested / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    calls: list[tuple[str, str | None, str]] = []

    def fake_query(
        package: str, version: str | None = None, *, ecosystem: str
    ) -> ioc_scan.OsvApiClassification:
        calls.append((package, version, ecosystem))
        return ioc_scan.OsvApiClassification(
            status="success", vulns=[{"id": "MAL-2099-1"}]
        )

    monkeypatch.setattr(ioc_scan, "query_osv_api", fake_query)
    hits = _scan_hits(repo, policy, use_osv=True)
    assert len(hits) == 2
    assert {hit.verification for hit in hits} == {"osv-malicious-version-match"}
    assert {hit.versions for hit in hits} == {("5.0.0",)}
    assert calls == [("keyv", "5.0.0", "npm")]


def test_osv_mal_alias_is_a_malicious_package_advisory() -> None:
    assert ioc_scan._has_malicious_osv_family([
        {"id": "GHSA-example", "aliases": ["MAL-2099-42"]}
    ])


def test_osv_marker_walk_is_cycle_safe_and_bounded() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    assert not ioc_scan._has_malicious_osv_family([
        {"id": "GHSA-example", "database_specific": cycle}
    ])


def test_malformed_osv_json_is_an_unavailable_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"vulns":[{"bad":' + b"9" * 10_000 + b"}]}"

    monkeypatch.setattr(ioc_scan.urllib.request, "urlopen", lambda *_a, **_k: Response())
    result = ioc_scan.query_osv_api("keyv", "5.0.0", ecosystem="npm")
    assert result.status == "failed"


@pytest.mark.parametrize(
    "body",
    [
        b'{"vulns":[],"vulns":[{"id":"MAL-2099-1"}]}',
        b'{"vulns":[{"id":"MAL-2099-1","score":NaN}]}',
    ],
)
def test_nonstandard_osv_json_cannot_add_a_hit(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return body

    monkeypatch.setattr(ioc_scan.urllib.request, "urlopen", lambda *_a, **_k: Response())
    result = ioc_scan.query_osv_api("keyv", "5.0.0", ecosystem="npm")
    assert result.status == "failed"


@pytest.mark.parametrize(
    "body",
    [
        b'{"vulns":[{"database_specific":{"type":"malicious-code"}}]}',
        b'{"vulns":[{"id":7,"database_specific":{"type":"malicious-code"}}]}',
        b'{"vulns":[{"id":"GHSA-x","aliases":"MAL-2099-1"}]}',
        b'{"vulns":[{"id":"GHSA-x","aliases":[7]}]}',
        b'{"vulns":[{"id":"GHSA-x","database_specific":"malicious-code"}]}',
        b'{"vulns":[{"id":"GHSA-x","ecosystem_specific":["malicious-code"]}]}',
    ],
)
def test_malformed_osv_advisory_fields_cannot_add_a_hit(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return body

    monkeypatch.setattr(ioc_scan.urllib.request, "urlopen", lambda *_a, **_k: Response())
    result = ioc_scan.query_osv_api("keyv", "5.0.0", ecosystem="npm")
    assert result.status == "failed"


def test_schema_valid_osv_malicious_marker_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return (
                b'{"vulns":[{"id":"GHSA-x","database_specific":'
                b'{"classification":"malicious-code"}}]}'
            )

    monkeypatch.setattr(ioc_scan.urllib.request, "urlopen", lambda *_a, **_k: Response())
    result = ioc_scan.query_osv_api("keyv", "5.0.0", ecosystem="npm")
    assert result.status == "success"
    assert ioc_scan._has_malicious_osv_family(result.vulns)


def test_osv_marker_subtree_over_work_budget_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return (
                b'{"vulns":[{"id":"GHSA-x","database_specific":'
                b'{"a":{"b":{"classification":"malicious-code"}}}}]}'
            )

    monkeypatch.setattr(ioc_scan, "_OSV_MARKER_NODE_LIMIT", 2)
    monkeypatch.setattr(ioc_scan.urllib.request, "urlopen", lambda *_a, **_k: Response())
    result = ioc_scan.query_osv_api("keyv", "5.0.0", ecosystem="npm")
    assert result.status == "failed"


def test_osv_query_budget_leaves_additional_local_safe_versions_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for index in range(3):
        nested = repo / str(index)
        nested.mkdir()
        (nested / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/keyv": {"version": f"5.0.{index}"}
            },
        }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    calls: list[str] = []
    monkeypatch.setattr(ioc_scan, "_OSV_QUERY_LIMIT", 2)
    monkeypatch.setattr(
        ioc_scan,
        "query_osv_api",
        lambda _package, version, **_kwargs: (
            calls.append(version)
            or ioc_scan.OsvApiClassification(status="success", vulns=[])
        ),
    )

    assert _scan_hits(repo, policy, use_osv=True) == []
    assert len(calls) == 2


def test_plain_only_package_wide_hit_never_calls_osv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        '{"dependencies":{"node-loggers":{"version":"99.0.0"}}}',
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "ioc.txt", "node-loggers")
    monkeypatch.setattr(
        ioc_scan,
        "query_osv_api",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("plain-only identities are package-wide")
        ),
    )
    hits = _scan_hits(repo, policy, use_osv=True)
    assert len(hits) == 1
    assert hits[0].ioc == "node-loggers"


# --- Bun lockfiles (bun.lock text, bun.lockb binary) -----------------------

# Real `bun install --lockfile-only` output (Bun 1.4.2, binary format 3) for
# {"keyv": "4.5.4", "keyv-next": "npm:keyv@5.0.0"} plus workspace `wsa`.
_BUN_LOCKB_FORMAT3_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgYnVuCmJ1bi1sb2NrZmlsZS1mb3JtYXQtdjAKAwAAAHVBBDE2PrgL"
    "b43KQmQqdpHd/3V3KbA292DcIWvi7WGjCAsAAAAAAAAGAAAAAAAAAAgAAAAAAAAACAAAAAAA"
    "AACAAAAAAAAAAJ4GAAAAAAAAAABmeAAAAAAAAGtleXYAAAAAUwAAAA8AAIBrZXl2AAAAANIA"
    "AAALAACAd3NhAAAAAADdpgjQ5OypTP7oIvT3dBWZx42jaFAA/d3+6CL093QVmW0pHmKqlGJP"
    "/3NhrPDJpucBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAACMAAAAwAACABQAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAGIA"
    "AABAAACAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAACAAAAAAAAAKIAAAAwAACABAAAAAAAAAAFAAAAAAAAAAQAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAN0AAAA+AACAAwAAAAAAAAAAAAAA"
    "AAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAAAAAAAAA"
    "AAAMAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAwAAAAMAAAABAAAABAAAAAAAAAAEAAAAAQAAAAUAAAAAAAAABQAAAAAA"
    "AAAAAAAAAwAAAAMAAAABAAAABAAAAAAAAAAEAAAAAQAAAAUAAAAAAAAABQAAAAAAAAAAAP4P"
    "/gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAQD+D/4BAAABAAAAAAAAAAAAAAAEqtmx"
    "o+NR06YxIrywQzkxQG5bsNKR4GlOHZzrJHKsRXATU8ivqptnMllSuPIJRtaLmDGWdAK/n6JV"
    "fbBgRfTuXQEAAAEA/g/+AQAAAgAAAAAAAAAAAAAABHV59xWYT79FEvu3bSbCItkfnO6lmIkX"
    "qBIec1J7Vgn+KEqTDYm/BQ4UqHnept0MmXceYSu4ixZGJN6zccLfL0wBAAABAP4P/gEAAAMA"
    "AAAAAAAAAAAAAASjFUeQdH8Ql/YI1edbFEtbqaDsnIIJRwbQO0QaYvZy1SjU81OKfU9SKX6v"
    "/7ivkylWAL9+fWSOzHuaNK6MqoinAQAAAQD+D/4BAAAEAAAAAAAAAAAAAAAE4bV5BfR2mqfQ"
    "TJm+V5tPPdf+ZpuhiIvTuAB5g8kcrXOZpTT/QwwVRWBywX1ozr6lEuPdbHxwaJlm9G6mI2sf"
    "SQEAAAEA/g/+AQAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAHgBgAAAAAAAPQGAAAAAAAACjxpbnN0YWxsLmxvY2tmaWxl"
    "LlRyZWU+IDIwIHNpemVvZiwgNCBhbGlnbm9mCgAAAAAAAAAA/v////////8AAAAABQAAACAH"
    "AAAAAAAANAcAAAAAAAAKPHUzMj4gNCBzaXplb2YsIDQgYWxpZ25vZgoAAAAAAAEAAAACAAAA"
    "BAAAAAMAAABgBwAAAAAAAHQHAAAAAAAACjx1MzI+IDQgc2l6ZW9mLCA0IGFsaWdub2YKAAUA"
    "AAADAAAAAQAAAAIAAAAEAAAAqAcAAAAAAAAqCAAAAAAAAAo8WzI2XXU4PiAyNiBzaXplb2Ys"
    "IDEgYWxpZ25vZgoAAAAAAHdzYQAAAAAA/3NhrPDJpucgBgAAAAAMAACAa2V5dgAAAAD+6CL0"
    "93QVmQIBNC41LjQAAAAaAAAACQAAgH/xgcyflue6AgEMAAAADgAAgFMAAAAPAACAx42jaFAA"
    "/d0CASoAAAAAAAAA0gAAAAsAAIBtKR5iqpRiTwIBMy4wLjEAAAB3CAAAAAAAAHcIAAAAAAAA"
    "CjxzZW12ZXIuRXh0ZXJuYWxTdHJpbmcuRXh0ZXJuYWxTdHJpbmc+IDE2IHNpemVvZiwgOCBh"
    "bGlnbm9mCqgIAAAAAAAAwwkAAAAAAAAKPHU4PiAxIHNpemVvZiwgMSBhbGlnbm9mCgAAAAAA"
    "AABwYWNrYWdlcy93c2FucG06a2V5dkA1LjAuMGtleXYtbmV4dGh0dHBzOi8vcmVnaXN0cnku"
    "bnBtanMub3JnL2tleXYvLS9rZXl2LTUuMC4wLnRnekBrZXl2L3NlcmlhbGl6ZWh0dHBzOi8v"
    "cmVnaXN0cnkubnBtanMub3JnL0BrZXl2L3NlcmlhbGl6ZS8tL3NlcmlhbGl6ZS0xLjEuMS50"
    "Z3podHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZy9rZXl2Ly0va2V5di00LjUuNC50Z3pqc29u"
    "LWJ1ZmZlcmh0dHBzOi8vcmVnaXN0cnkubnBtanMub3JnL2pzb24tYnVmZmVyLy0vanNvbi1i"
    "dWZmZXItMy4wLjEudGd6AAAAAAAAAAB3T3JLc1BhQwAKAAAAAAAACAoAAAAAAAAKPHU2ND4g"
    "OCBzaXplb2YsIDggYWxpZ25vZgoAAP9zYazwyabnSAoAAAAAAACACgAAAAAAAAo8c2VtdmVy"
    "LlZlcnNpb24uVmVyc2lvbj4gNTYgc2l6ZW9mLCA4IGFsaWdub2YKAAEAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAoAAAAAAAC4CgAA"
    "AAAAAAo8dTY0PiA4IHNpemVvZiwgOCBhbGlnbm9mCgAAAAAA/3NhrPDJpufwCgAAAAAAAPgK"
    "AAAAAAAACjxzZW12ZXIuU3RyaW5nPiA4IHNpemVvZiwgMSBhbGlnbm9mCgAAAAAAAAAMAACA"
    "Y05mR3ZSc04BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)


# The same package.json locked by Bun 1.1.38 (binary format 2, u32 versions).
_BUN_LOCKB_FORMAT2_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgYnVuCmJ1bi1sb2NrZmlsZS1mb3JtYXQtdjAKAgAAAHVBBDE2PrgL"
    "b43KQmQqdpHd/3V3KbA292DcIWvi7WGj0AoAAAAAAAAGAAAAAAAAAAgAAAAAAAAACAAAAAAA"
    "AACAAAAAAAAAAG4GAAAAAAAAAABmeAAAAAAAAGtleXYAAAAAUwAAAA8AAIBrZXl2AAAAANIA"
    "AAALAACAd3NhAAAAAADdpgjQ5OypTP7oIvT3dBWZx42jaFAA/d3+6CL093QVmW0pHmKqlGJP"
    "/3NhrPDJpucBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAjAAAAMAAAgAUAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAYgAAAEAAAIABAAAAAQAAAAEA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAKIAAAAwAACA"
    "BAAAAAUAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAA"
    "AADdAAAAPgAAgAMAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAEgAAAAAAAAAAAAAAAwAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAwAAAAMAAAABAAAABAAAAAAAAAAEAAAAAQAAAAUAAAAAAAAA"
    "BQAAAAAAAAAAAAAAAwAAAAMAAAABAAAABAAAAAAAAAAEAAAAAQAAAAUAAAAAAAAABQAAAAAA"
    "AAAAAP4P/gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAQD+D/4BAAABAAAAAAAAAAAA"
    "AAAEqtmxo+NR06YxIrywQzkxQG5bsNKR4GlOHZzrJHKsRXATU8ivqptnMllSuPIJRtaLmDGW"
    "dAK/n6JVfbBgRfTuXQEAAAEA/g/+AQAAAgAAAAAAAAAAAAAABHV59xWYT79FEvu3bSbCItkf"
    "nO6lmIkXqBIec1J7Vgn+KEqTDYm/BQ4UqHnept0MmXceYSu4ixZGJN6zccLfL0wBAAABAP4P"
    "/gEAAAMAAAAAAAAAAAAAAASjFUeQdH8Ql/YI1edbFEtbqaDsnIIJRwbQO0QaYvZy1SjU81OK"
    "fU9SKX6v/7ivkylWAL9+fWSOzHuaNK6MqoinAQAAAQD+D/4BAAAEAAAAAAAAAAAAAAAE4bV5"
    "BfR2mqfQTJm+V5tPPdf+ZpuhiIvTuAB5g8kcrXOZpTT/QwwVRWBywX1ozr6lEuPdbHxwaJlm"
    "9G6mI2sfSQEAAAEA/g/+AQAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGwBgAAAAAAAMQGAAAAAAAACjxzcmMuaW5zdGFs"
    "bC5sb2NrZmlsZS5UcmVlPiAyMCBzaXplb2YsIDQgYWxpZ25vZgoAAAAA/v////////8AAAAA"
    "BQAAAPAGAAAAAAAABAcAAAAAAAAKPHUzMj4gNCBzaXplb2YsIDQgYWxpZ25vZgoAAAAAAAEA"
    "AAACAAAABAAAAAMAAAAwBwAAAAAAAEQHAAAAAAAACjx1MzI+IDQgc2l6ZW9mLCA0IGFsaWdu"
    "b2YKAAUAAAADAAAAAQAAAAIAAAAEAAAAeAcAAAAAAAD6BwAAAAAAAAo8WzI2XXU4PiAyNiBz"
    "aXplb2YsIDEgYWxpZ25vZgoAAAAAAHdzYQAAAAAA/3NhrPDJpucgBgAAAAAMAACAa2V5dgAA"
    "AAD+6CL093QVmQIBNC41LjQAAAAaAAAACQAAgH/xgcyflue6AgEMAAAADgAAgFMAAAAPAACA"
    "x42jaFAA/d0CASoAAAAAAAAA0gAAAAsAAIBtKR5iqpRiTwIBMy4wLjEAAABECAAAAAAAAEQI"
    "AAAAAAAACjxzcmMuaW5zdGFsbC5zZW12ZXIuRXh0ZXJuYWxTdHJpbmc+IDE2IHNpemVvZiwg"
    "OCBhbGlnbm9mCnAIAAAAAAAAiwkAAAAAAAAKPHU4PiAxIHNpemVvZiwgMSBhbGlnbm9mCgAA"
    "cGFja2FnZXMvd3NhbnBtOmtleXZANS4wLjBrZXl2LW5leHRodHRwczovL3JlZ2lzdHJ5Lm5w"
    "bWpzLm9yZy9rZXl2Ly0va2V5di01LjAuMC50Z3pAa2V5di9zZXJpYWxpemVodHRwczovL3Jl"
    "Z2lzdHJ5Lm5wbWpzLm9yZy9Aa2V5di9zZXJpYWxpemUvLS9zZXJpYWxpemUtMS4xLjEudGd6"
    "aHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmcva2V5di8tL2tleXYtNC41LjQudGd6anNvbi1i"
    "dWZmZXJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZy9qc29uLWJ1ZmZlci8tL2pzb24tYnVm"
    "ZmVyLTMuMC4xLnRnegAAAAAAAAAAd09yS3NQYUPICQAAAAAAANAJAAAAAAAACjx1NjQ+IDgg"
    "c2l6ZW9mLCA4IGFsaWdub2YKAAD/c2Gs8Mmm5xgKAAAAAAAASAoAAAAAAAAKPHNyYy5pbnN0"
    "YWxsLnNlbXZlci5WZXJzaW9uPiA0OCBzaXplb2YsIDggYWxpZ25vZgoAAAAAAAEAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHgKAAAAAAAAgAoAAAAA"
    "AAAKPHU2ND4gOCBzaXplb2YsIDggYWxpZ25vZgoAAAAAAP9zYazwyabnyAoAAAAAAADQCgAA"
    "AAAAAAo8c3JjLmluc3RhbGwuc2VtdmVyLlN0cmluZz4gOCBzaXplb2YsIDEgYWxpZ25vZgoA"
    "AAAAAAAAAAAAAAwAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)


def _real_bun_lockb(fmt: int = 3) -> bytes:
    import base64

    return base64.b64decode(
        _BUN_LOCKB_FORMAT3_B64 if fmt == 3 else _BUN_LOCKB_FORMAT2_B64
    )


def _bun_lockb_bytes(
    packages: list[tuple[str, int, tuple[int, int, int], str, str]],
    dependencies: list[tuple[str, int, str]] = (),
    *,
    fmt: int = 3,
) -> bytes:
    """Serialize a minimal bun.lockb with the layout Bun writes.

    `packages` rows are (name, resolution_tag, (major, minor, patch), pre, url);
    `dependencies` rows are (name, behavior, literal), where a `bytes` literal
    is written as a raw 8-byte String (to craft hostile pointers). Row 0 must be
    the root.
    """
    import struct

    strings = bytearray()

    def string(value: str) -> bytes:
        raw = value.encode()
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        offset = len(strings)
        strings.extend(raw)
        return struct.pack("<II", offset, len(raw) | 0x80000000)

    version_size = 56 if fmt == 3 else 48
    names, resolutions = b"", b""
    for name, tag, (major, minor, patch), pre, url in packages:
        names += string(name)
        if fmt == 3:
            version = struct.pack("<QQQ", major, minor, patch)
        else:
            version = struct.pack("<III", major, minor, patch) + b"\0" * 4
        version += string(pre) + b"\0" * 8 + b"\0" * 16
        assert len(version) == version_size
        resolutions += bytes([tag]) + b"\0" * 7 + string(url) + version
    count = len(packages)
    table = (
        names + b"\0" * 8 * count + resolutions
        + b"\0" * (8 + 8 + 88 + 20 + 49) * count
    )
    dependency_bytes = b"".join(
        string(name) + b"\0" * 8 + bytes([behavior, 1])
        + (literal if isinstance(literal, bytes) else string(literal))
        for name, behavior, literal in dependencies
    )

    out = bytearray(ioc_scan._BUN_LOCKB_HEADER)
    out += struct.pack("<I", fmt) + b"\0" * 32
    total_end_at = len(out)
    out += b"\0" * 8
    begin = (len(out) + 40 + 7) // 8 * 8
    out += struct.pack("<QQQQQ", count, 8, 8, begin, begin + len(table))
    out += b"\0" * (begin - len(out))
    out += table
    for size, payload in zip(
        ioc_scan._BUN_LOCKB_BUFFER_SIZES,
        (b"", b"", b"", dependency_bytes, b"", bytes(strings)),
    ):
        header_at = len(out)
        out += b"\0" * 16
        out += f"\n<t> {size} sizeof, 1 alignof\n".encode()
        if payload:
            out += b"\0" * (-len(out) % 8)
        start = len(out)
        out += payload
        out[header_at:header_at + 16] = struct.pack("<QQ", start, len(out))
    out += b"\0" * 8
    out[total_end_at:total_end_at + 8] = struct.pack("<Q", len(out))
    return bytes(out)


def _keyv_row(version: tuple[int, int, int], *, url_version: str | None = None):
    text = url_version or ".".join(map(str, version))
    return (
        "keyv", 2, version, "",
        f"https://registry.npmjs.org/keyv/-/keyv-{text}.tgz",
    )


_BUN_ROOT_ROW = ("fixture-root", 1, (0, 0, 0), "", "")


def _bun_lock_text(packages: dict[str, list[object]], **extra: object) -> str:
    document: dict[str, object] = {
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "fixture-root", "dependencies": {"keyv": "*"}}},
        "packages": packages,
    }
    document.update(extra)
    return json.dumps(document, indent=2)


def test_bun_lockfiles_are_discovered_and_mapped_to_npm_extractors() -> None:
    assert {"bun.lock", "bun.lockb"} <= ioc_scan._LOCKFILE_NAMES
    assert ioc_scan._LOCKFILE_POLICY_ECOSYSTEMS["bun.lock"] == "npm"
    assert ioc_scan._LOCKFILE_POLICY_ECOSYSTEMS["bun.lockb"] == "npm"


def test_jsonc_normalizer_strips_only_comments_and_trailing_commas() -> None:
    text = (
        '{\n  // a comment\n  "a": "x, // not a comment ]",\n'
        '  "b": [1, 2, /* c */],\n  "c": "\\"quoted,\\"",\n}\n'
    )
    data, duplicate = ioc_scan._load_jsonc(text)
    assert not duplicate
    assert data == {"a": "x, // not a comment ]", "b": [1, 2], "c": '"quoted,"'}
    with pytest.raises(ValueError):
        ioc_scan._load_jsonc('{"a": "unterminated}')


def test_real_bun_generated_text_lockfile_shape_is_trusted(tmp_path: Path) -> None:
    lockfile = tmp_path / "bun.lock"
    lockfile.write_text(
        '{\n  "lockfileVersion": 2,\n  "configVersion": 1,\n  "workspaces": {\n'
        '    "": {\n      "name": "fx",\n      "dependencies": {\n'
        '        "keyv": "4.5.4",\n        "keyv-next": "npm:keyv@5.0.0",\n'
        '      },\n    },\n    "packages/wsa": {\n      "name": "wsa",\n'
        '      "version": "1.0.0",\n    },\n  },\n  "packages": {\n'
        '    "@keyv/serialize": ["@keyv/serialize@1.1.1", "", {}, "sha512-x"],\n\n'
        '    "json-buffer": ["json-buffer@3.0.1", "", {}, "sha512-x"],\n\n'
        '    "keyv": ["keyv@4.5.4", "", { "dependencies": { "json-buffer": '
        '"3.0.1" } }, "sha512-x"],\n\n'
        '    "keyv-next": ["keyv@5.0.0", "", { "dependencies": '
        '{ "@keyv/serialize": "*" } }, "sha512-x"],\n\n'
        '    "wsa": ["wsa@workspace:packages/wsa"],\n  }\n}\n',
        encoding="utf-8",
    )
    info = ioc_scan._extract_bun_lock_version_info(lockfile, "keyv")
    assert info == ioc_scan.LockfilePackageVersions(versions=("4.5.4", "5.0.0"))
    assert ioc_scan._extract_bun_lock_version_info(lockfile, "wsa").mixed_or_untrusted
    assert ioc_scan._extract_bun_lock_version_info(
        lockfile, "keyv-next"
    ).mixed_or_untrusted


def test_bun_lock_clean_version_passes_and_malicious_version_halts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "bun.lock").write_text(_bun_lock_text({
        "keyv": ["keyv@4.5.4", "", {}, "sha512-x"],
    }), encoding="utf-8")
    assert _scan_hits(clean, policy) == []
    assert _run_main(monkeypatch, clean, policy, "--offline") == 0

    for key, identity in (
        ("keyv", "keyv@6.0.0"),          # direct
        ("which/keyv", "keyv@6.0.0"),    # nested install path
        ("keyv-next", "keyv@6.0.0"),     # npm alias installs the real identity
    ):
        repo = tmp_path / key.replace("/", "_")
        repo.mkdir()
        (repo / "bun.lock").write_text(_bun_lock_text({
            key: [identity, "", {}, "sha512-x"],
        }), encoding="utf-8")
        hits = _scan_hits(repo, policy)
        assert [(hit.ioc, hit.versions, hit.verification) for hit in hits] == [
            ("keyv", ("6.0.0",), "ioc-list-version-match")
        ], key
        assert _run_main(monkeypatch, repo, policy, "--offline") == 2


@pytest.mark.parametrize(
    "packages, extra",
    [
        ({"keyv": ["keyv@workspace:packages/keyv"]}, {}),
        ({"keyv": ["keyv@github:owner/keyv#abc", {}, "owner-keyv-abc"]}, {}),
        ({"keyv": ["keyv@https://evil.example/keyv.tgz", {}]}, {}),
        ({"keyv": ["other@1.0.0", "", {}, "sha512-x"]}, {}),  # alias key hides keyv
        ({"keyv": "keyv@4.5.4"}, {}),                          # malformed record
        ({}, {}),                                   # declared but never resolved
        ({"keyv": ["keyv@4.5.4", "", {}, "sha512-x"]}, {"lockfileVersion": 99}),
        ({"keyv": ["keyv@4.5.4", "", {}, "sha512-x"]}, {"workspaces": []}),
    ],
)
def test_bun_lock_untrusted_evidence_cannot_clear_a_version_scoped_name(
    tmp_path: Path, packages: dict[str, object], extra: dict[str, object]
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lock").write_text(_bun_lock_text(packages, **extra), encoding="utf-8")
    hits = _scan_hits(repo, policy)
    assert [hit.ioc for hit in hits] == ["keyv"]
    assert hits[0].verification == "name-only"


def test_bun_lock_peer_only_mention_is_not_an_install(tmp_path: Path) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lock").write_text(json.dumps({
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "root", "dependencies": {"cache": "1.0.0"}}},
        "packages": {
            "cache": ["cache@1.0.0", "", {"peerDependencies": {"keyv": "*"}}, "x"],
        },
    }), encoding="utf-8")
    assert _scan_hits(repo, policy) == []


def test_bun_lock_escaped_identity_and_duplicate_keys_fail_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "evil-pkg")
    escaped = tmp_path / "escaped"
    escaped.mkdir()
    (escaped / "bun.lock").write_text(
        '{"lockfileVersion": 1, "packages": {'
        '"evil-pkg": ["evil-\\u0070kg@1.0.0", "", {}, "x"],}}',
        encoding="utf-8",
    )
    assert [hit.ioc for hit in _scan_hits(escaped, policy)] == ["evil-pkg"]

    duplicate = tmp_path / "duplicate"
    duplicate.mkdir()
    (duplicate / "bun.lock").write_text(
        '{"lockfileVersion": 1, "packages": {"a": ["a@1.0.0"], "a": ["a@2.0.0"]}}',
        encoding="utf-8",
    )
    assert _run_main(monkeypatch, duplicate, policy, "--offline") == 3

    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "bun.lock").write_text('{"packages": {"x": [', encoding="utf-8")
    assert _run_main(monkeypatch, broken, policy, "--offline") == 3


@pytest.mark.parametrize("fmt", [2, 3])
def test_real_bun_lockb_parses_every_identity(fmt: int) -> None:
    parsed = ioc_scan._parse_bun_lockb(_real_bun_lockb(fmt))
    assert parsed is not None
    assert [
        (package.name, package.resolution_tag, package.version)
        for package in parsed.packages
    ] == [
        ("fx", 1, None),
        ("keyv", 2, "5.0.0"),
        ("@keyv/serialize", 2, "1.1.1"),
        ("keyv", 2, "4.5.4"),
        ("json-buffer", 2, "3.0.1"),
        ("wsa", 72, None),
    ]
    assert ("keyv-next", "npm:keyv@5.0.0") in {
        (dependency.name, dependency.literal) for dependency in parsed.dependencies
    }


@pytest.mark.parametrize("fmt", [2, 3])
def test_real_bun_lockb_clean_versions_pass_and_patched_release_halts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: int
) -> None:
    import struct

    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "bun.lockb").write_bytes(_real_bun_lockb(fmt))
    assert _scan_hits(clean, policy) == []
    assert _run_main(monkeypatch, clean, policy, "--offline") == 0

    # Rewrite the 4.5.4 record (package row 3) to 6.0.0, URL included.
    data = bytearray(_real_bun_lockb(fmt))
    count = struct.unpack_from("<Q", data, 86)[0]
    field = "<QQQ" if fmt == 3 else "<III"
    record = 128 + 16 * count + (16 + (56 if fmt == 3 else 48)) * 3
    assert struct.unpack_from(field, data, record + 16) == (4, 5, 4)
    struct.pack_into(field, data, record + 16, 6, 0, 0)
    data = bytearray(data.replace(b"keyv/-/keyv-4.5.4.tgz", b"keyv/-/keyv-6.0.0.tgz"))
    malicious = tmp_path / "malicious"
    malicious.mkdir()
    (malicious / "bun.lockb").write_bytes(bytes(data))
    hits = _scan_hits(malicious, policy)
    assert [(hit.ioc, hit.versions) for hit in hits] == [("keyv", ("6.0.0",))]
    assert _run_main(monkeypatch, malicious, policy, "--offline") == 2

    package_wide = _policy(tmp_path / "wide.txt", "json-buffer")
    assert [hit.ioc for hit in _scan_hits(clean, package_wide)] == ["json-buffer"]


@pytest.mark.parametrize("fmt", [2, 3])
def test_bun_lockb_both_layouts_extract_exact_versions(
    tmp_path: Path, fmt: int
) -> None:
    lockfile = tmp_path / "bun.lockb"
    lockfile.write_bytes(_bun_lockb_bytes(
        [_BUN_ROOT_ROW, _keyv_row((4, 5, 4)),
         ("solidity-docgen", 2, (0, 6, 0), "beta.36",
          "https://registry.npmjs.org/solidity-docgen/-/"
          "solidity-docgen-0.6.0-beta.36.tgz")],
        [("keyv", 2, "^4.5.0")],
        fmt=fmt,
    ))
    assert ioc_scan._extract_bun_lockb_version_info(lockfile, "keyv") == (
        ioc_scan.LockfilePackageVersions(versions=("4.5.4",))
    )
    assert ioc_scan._extract_bun_lockb_version_info(
        lockfile, "solidity-docgen"
    ) == ioc_scan.LockfilePackageVersions(versions=("0.6.0-beta.36",))


@pytest.mark.parametrize(
    "packages, dependencies",
    [
        # Version fields disagree with the fetched tarball URL.
        ([_BUN_ROOT_ROW, _keyv_row((4, 5, 4), url_version="6.0.0")], []),
        # Non-registry resolution (git) for the scoped identity.
        ([_BUN_ROOT_ROW, ("keyv", 32, (0, 0, 0), "", "github.com/x/keyv")], []),
        # Declared (non-peer) dependency with no resolved package record.
        ([_BUN_ROOT_ROW], [("keyv", 2, "6.0.0")]),
        # npm alias to the scoped identity with no resolved package record.
        ([_BUN_ROOT_ROW], [("cache-store", 2, "npm:keyv@6.0.0")]),
    ],
)
def test_bun_lockb_untrusted_evidence_cannot_clear_a_version_scoped_name(
    tmp_path: Path,
    packages: list[tuple[str, int, tuple[int, int, int], str, str]],
    dependencies: list[tuple[str, int, str]],
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lockb").write_bytes(_bun_lockb_bytes(packages, dependencies))
    assert [hit.ioc for hit in _scan_hits(repo, policy)] == ["keyv"]


def test_bun_lockb_peer_dependency_without_install_is_safe(tmp_path: Path) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lockb").write_bytes(_bun_lockb_bytes(
        [_BUN_ROOT_ROW], [("keyv", ioc_scan._BUN_DEPENDENCY_PEER, "*")]
    ))
    assert _scan_hits(repo, policy) == []


@pytest.mark.parametrize(
    "mutate",
    [
        # truncated just before the recorded end of the tables
        lambda data: data[:int.from_bytes(data[78:86], "little") - 4],
        lambda data: data.replace(b"format-v0", b"format-v9", 1),  # header
        lambda data: data[:42] + b"\x07" + data[43:],              # unknown format
        lambda data: data.replace(b"1 sizeof", b"2 sizeof", 1),    # annotation
    ],
)
def test_malformed_bun_lockb_fails_closed_but_still_surfaces_raw_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate
) -> None:
    raw = mutate(_real_bun_lockb())
    assert ioc_scan._parse_bun_lockb(raw) is None
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lockb").write_bytes(raw)
    clean_policy = _policy(tmp_path / "ioc.txt", "never-present-package")
    assert _run_main(monkeypatch, repo, clean_policy, "--offline") == 3
    wide_policy = _policy(tmp_path / "wide.txt", "json-buffer")
    assert _run_main(monkeypatch, repo, wide_policy, "--offline") == 2


def test_bun_lockb_string_pointer_out_of_bounds_is_rejected() -> None:
    import struct

    data = bytearray(_bun_lockb_bytes([
        _BUN_ROOT_ROW, ("a-long-package-name", 2, (1, 0, 0), "", ""),
    ]))
    name_at = 128 + 8
    offset, length = struct.unpack_from("<II", data, name_at)
    assert length & 0x80000000
    struct.pack_into("<II", data, name_at, offset + 10_000, length)
    assert ioc_scan._parse_bun_lockb(bytes(data)) is None


@pytest.mark.parametrize("line_end", ["\r", "\u2028", "\u2029"])
def test_bun_lock_line_comment_ends_where_bun_ends_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line_end: str
) -> None:
    # Bun ends `//` at CR/LS/PS, so it reads keyv@6.0.0 and comments out the
    # 4.5.4 decoy; ending the comment only at "\n" would read the decoy.
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lock").write_bytes((
        '{"lockfileVersion": 1,\n'
        ' "workspaces": {"": {"name": "root", "dependencies": {"keyv": "*"}}},\n'
        ' "packages": {\n'
        f'  "keyv": // x{line_end} ["keyv@6.0.0", "", {{}}, "sha512-MAL"] /*\n'
        '         ["keyv@4.5.4", "", {}, "sha512-OK"] /* */\n'
        ' }\n}\n'
    ).encode("utf-8"))
    assert _run_main(monkeypatch, repo, policy, "--offline") in (2, 3)
    info = ioc_scan._extract_bun_lock_version_info(repo / "bun.lock", "keyv")
    assert "4.5.4" not in info.versions


def test_jsonc_rejects_commas_that_follow_no_value() -> None:
    for text in ("[,]", "{,}", '{"a": [1,,]}'):
        with pytest.raises(ValueError):
            ioc_scan._load_jsonc(text)
    assert ioc_scan._load_jsonc('{"a": [1,],}')[0] == {"a": [1]}


@pytest.mark.parametrize(
    "tarball",
    [
        "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
        "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz?/keyv/-/keyv-4.5.4.tgz",
        "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz#/keyv/-/keyv-4.5.4.tgz",
        "https://u:p@evil.example/keyv/-/keyv-4.5.4.tgz",
        "https://evil.example/x/../keyv/-/keyv-4.5.4.tgz",
        "https://evil.example/keyv/-/keyv%2D4.5.4.tgz",
        "ftp://evil.example/keyv/-/keyv-4.5.4.tgz",
    ],
)
def test_bun_tarball_url_must_be_exactly_the_recorded_release(
    tmp_path: Path, tarball: str
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    text_repo = tmp_path / "text"
    text_repo.mkdir()
    (text_repo / "bun.lock").write_text(_bun_lock_text({
        "keyv": ["keyv@4.5.4", tarball, {}, "sha512-x"],
    }), encoding="utf-8")
    assert [hit.ioc for hit in _scan_hits(text_repo, policy)] == ["keyv"]

    binary_repo = tmp_path / "binary"
    binary_repo.mkdir()
    (binary_repo / "bun.lockb").write_bytes(_bun_lockb_bytes([
        _BUN_ROOT_ROW, ("keyv", 2, (4, 5, 4), "", tarball),
    ]))
    assert [hit.ioc for hit in _scan_hits(binary_repo, policy)] == ["keyv"]


def test_bun_custom_registry_tarball_of_the_same_release_is_trusted(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lock").write_text(_bun_lock_text({
        "keyv": [
            "keyv@4.5.4", "https://npm.example.com/keyv/-/keyv-4.5.4.tgz", {}, "x",
        ],
    }), encoding="utf-8")
    assert _scan_hits(repo, policy) == []


@pytest.mark.parametrize(
    "record",
    [
        ["harmless@1.0.0", "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz", {}, "x"],
        ["harmless@https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz", {}],
    ],
)
def test_bun_lock_renamed_install_of_the_package_tarball_cannot_clear(
    tmp_path: Path, record: list[object]
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lock").write_text(json.dumps({
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "root", "dependencies": {"harmless": "*"}}},
        "packages": {"harmless": record},
    }), encoding="utf-8")
    assert [hit.ioc for hit in _scan_hits(repo, policy)] == ["keyv"]


@pytest.mark.parametrize("tag", [2, 80])  # npm, remote tarball
def test_bun_lockb_renamed_install_of_the_package_tarball_cannot_clear(
    tmp_path: Path, tag: int
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bun.lockb").write_bytes(_bun_lockb_bytes([
        _BUN_ROOT_ROW,
        ("harmless", tag, (1, 0, 0), "",
         "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz"),
    ]))
    assert [hit.ioc for hit in _scan_hits(repo, policy)] == ["keyv"]


def test_bun_lockb_repeated_string_pointers_cannot_amplify_memory() -> None:
    import struct
    import time

    big = "a" * (1024 * 1024)
    # The root's long name lands at string-buffer offset 0; the 1 MiB string
    # (a package URL) follows it.
    root_len = len(_BUN_ROOT_ROW[0])
    rows = [_BUN_ROOT_ROW, ("x", 64, (0, 0, 0), "", big)]

    def pointer(offset: int, size: int) -> bytes:
        return struct.pack("<II", offset, size | 0x80000000)

    # Identical pointers decode once: 2,000 references to the 1 MiB string.
    same = [("y", 2, pointer(root_len, len(big)))] * 2000
    started = time.monotonic()
    assert ioc_scan._parse_bun_lockb(_bun_lockb_bytes(rows, same)) is not None
    assert time.monotonic() - started < 5

    # Distinct overlapping ranges would decode ~2 GiB: refuse instead.
    overlapping = [
        ("y", 2, pointer(root_len + i, len(big) - i)) for i in range(2000)
    ]
    started = time.monotonic()
    assert ioc_scan._parse_bun_lockb(_bun_lockb_bytes(rows, overlapping)) is None
    assert time.monotonic() - started < 5


_ENCODED_KEYV_TARBALL = "https://registry.npmjs.org/%6beyv/-/%6beyv-6.0.0.tgz"


@pytest.mark.parametrize(
    "records",
    [
        ["keyv", "VERSION: npm | keyv | 6.0.0"],  # version-scoped
        ["keyv"],                                  # package-wide
    ],
)
def test_percent_encoded_tarball_of_the_package_is_still_seen(
    tmp_path: Path, records: list[str]
) -> None:
    policy = _policy(tmp_path / "ioc.txt", *records)
    text_repo = tmp_path / "text"
    text_repo.mkdir()
    (text_repo / "bun.lock").write_text(json.dumps({
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "root", "dependencies": {"harmless": "*"}}},
        "packages": {
            "harmless": [
                "harmless@1.0.0", _ENCODED_KEYV_TARBALL,
                {"peerDependencies": {"keyv": "*"}}, "sha512-x",
            ],
        },
    }), encoding="utf-8")
    assert [hit.ioc for hit in _scan_hits(text_repo, policy)] == ["keyv"]

    binary_repo = tmp_path / "binary"
    binary_repo.mkdir()
    (binary_repo / "bun.lockb").write_bytes(_bun_lockb_bytes([
        _BUN_ROOT_ROW, ("harmless", 2, (1, 0, 0), "", _ENCODED_KEYV_TARBALL),
    ]))
    assert [hit.ioc for hit in _scan_hits(binary_repo, policy)] == ["keyv"]


def test_local_directories_named_like_the_package_do_not_halt(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0")
    repo = tmp_path / "text"
    repo.mkdir()
    (repo / "bun.lock").write_text(json.dumps({
        "lockfileVersion": 1,
        "workspaces": {
            "": {"name": "root", "dependencies": {"keyv": "4.5.4"}},
            "packages/keyv": {"name": "@acme/keyv-adapter"},
        },
        "packages": {
            "keyv": ["keyv@4.5.4", "", {}, "sha512-x"],
            "@acme/keyv-adapter": ["@acme/keyv-adapter@workspace:packages/keyv"],
            "local": ["local@file:vendor/keyv", {}],
            "linked": ["linked@link:../keyv"],
        },
    }), encoding="utf-8")
    assert _scan_hits(repo, policy) == []

    binary_repo = tmp_path / "binary"
    binary_repo.mkdir()
    (binary_repo / "bun.lockb").write_bytes(_bun_lockb_bytes([
        _BUN_ROOT_ROW, _keyv_row((4, 5, 4)),
        ("adapter", 72, (0, 0, 0), "", "packages/keyv"),
        ("vendored", 4, (0, 0, 0), "", "vendor/keyv"),
    ], [("keyv", 2, "4.5.4")]))
    assert _scan_hits(binary_repo, policy) == []


def test_jsonc_normalizer_memory_stays_proportional_to_input() -> None:
    import tracemalloc

    text = (
        '{"lockfileVersion":1,"workspaces":{"":{"name":"root"}},'
        '"packages":{},"padding":[' + "0," * 524288 + "0,]}"
    )
    tracemalloc.start()
    try:
        data, duplicate = ioc_scan._load_jsonc(text)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not duplicate and len(data["padding"]) == 524289
    # The decoded list itself is ~8 bytes/element; the normalizer must not add
    # per-character bookkeeping on top of it.
    assert peak < 8 * len(text) + 8 * 524289 * 2


@pytest.mark.parametrize(
    "url",
    [
        "https://reader@registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
        "https://a/b@host/keyv/-/keyv-6.0.0.tgz",
        "https://u:p@registry.npmjs.org/%6beyv/-/%6beyv-6.0.0.tgz",
    ],
)
@pytest.mark.parametrize(
    "records", [["keyv", "VERSION: npm | keyv | 6.0.0"], ["keyv"]]
)
def test_url_credentials_cannot_hide_the_fetched_identity(
    tmp_path: Path, url: str, records: list[str]
) -> None:
    policy = _policy(tmp_path / "ioc.txt", *records)
    text_repo = tmp_path / "text"
    text_repo.mkdir()
    (text_repo / "bun.lock").write_text(json.dumps({
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "root", "dependencies": {"harmless": "*"}}},
        "packages": {"harmless": ["harmless@1.0.0", url, {}, "sha512-x"]},
    }), encoding="utf-8")
    assert [hit.ioc for hit in _scan_hits(text_repo, policy)] == ["keyv"]

    binary_repo = tmp_path / "binary"
    binary_repo.mkdir()
    (binary_repo / "bun.lockb").write_bytes(_bun_lockb_bytes([
        _BUN_ROOT_ROW, ("harmless", 2, (1, 0, 0), "", url),
    ]))
    assert [hit.ioc for hit in _scan_hits(binary_repo, policy)] == ["keyv"]


def test_bun_lockb_shared_url_is_inspected_once_per_extraction(
    tmp_path: Path,
) -> None:
    import struct
    import time

    rows = [_BUN_ROOT_ROW, ("other", 2, (1, 0, 0), "", "https://e.example/" + "a" * 1024 * 1024)]
    rows += [("other", 2, (1, 0, 0), "", "")] * 20000
    data = bytearray(_bun_lockb_bytes(rows, [("keyv", 16, "*")]))
    count = len(rows)
    record = 128 + 16 * count
    shared = bytes(data[record + 72 + 8:record + 72 + 16])  # row 1's URL String
    assert shared[7] & 0x80
    for row in range(2, count):
        at = record + 72 * row + 8
        data[at:at + 8] = shared
    lockfile = tmp_path / "bun.lockb"
    lockfile.write_bytes(bytes(data))
    assert ioc_scan._parse_bun_lockb(bytes(data)) is not None
    started = time.monotonic()
    info = ioc_scan._extract_bun_lockb_version_info(lockfile, "keyv")
    assert time.monotonic() - started < 5
    assert info == ioc_scan.LockfilePackageVersions()
