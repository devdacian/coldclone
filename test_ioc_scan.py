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
