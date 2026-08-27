"""Regression tests for the offline known-malicious dependency tripwire."""

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


def _scan_hits(repo: Path, policy: Path) -> list[ioc_scan.IocHit]:
    iocs, _ = ioc_scan.load_ioc_list(policy)
    lockfiles, symlinked, traversal_errors = ioc_scan.discover_lockfiles(repo)
    assert not symlinked
    assert not traversal_errors
    hits, unreadable = ioc_scan.ioc_grep(lockfiles, iocs)
    assert not unreadable
    return ioc_scan.classify_ioc_hits(hits)


def _run_main(
    monkeypatch: pytest.MonkeyPatch, repo: Path, policy: Path
) -> int:
    monkeypatch.setattr(
        sys, "argv", ["ioc_scan.py", str(repo), "--ioc-list", str(policy)]
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
    )
    iocs, stale = ioc_scan.load_ioc_list(policy)
    assert stale == 0
    assert iocs["keyv"].line_no == 3
    assert iocs["keyv"].version_evidence == {
        "npm": (("6.0.0", 2), ("6.1.0", 5))
    }


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
        ("VERSION: npm | bad package | 6.0.0", "invalid VERSION"),
        ("VERSION: npm | a/b | 6.0.0", "invalid VERSION"),
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


def test_canonical_policy_has_exact_pinned_source_version_set() -> None:
    iocs, _ = ioc_scan.load_ioc_list(Path(__file__).with_name("ioc-list.txt"))
    actual = {
        (ecosystem, package, version)
        for package, entry in iocs.items()
        for ecosystem, versions in entry.version_evidence.items()
        for version, _line in versions
    }
    expected = {
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
    }
    assert actual == expected


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


@pytest.mark.parametrize(
    "version,resolved,integrity",
    [
        ("5.0.0", "https://registry.npmjs.org/keyv/-/keyv-5.0.0.tgz", "sha512-ok"),
        ("6.0.0", "https://evil.invalid/keyv/-/keyv-6.0.0.tgz", "sha512-ok"),
        ("6.0.0", "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz", ""),
    ],
)
def test_package_lock_disjoint_or_untrusted_never_clears_plain_hit(
    tmp_path: Path, version: str, resolved: str, integrity: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/keyv": {
                "version": version,
                "resolved": resolved,
                "integrity": integrity,
            }
        }
    }), encoding="utf-8")
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    hits = _scan_hits(repo, policy)
    assert len(hits) == 1
    assert hits[0].ioc == "keyv"
    assert hits[0].verification == "name-only"
    assert hits[0].lockfile_line_no > 0
    assert not hits[0].versions


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
    assert _scan_hits(repo, policy)[0].verification == "name-only"


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
    hits = _scan_hits(repo, policy)
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


def test_yarn_classic_is_exact_but_berry_without_registry_host_is_name_only(
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
    assert berry_hit.verification == "name-only"
    assert not berry_hit.versions


def test_yarn_classic_never_borrows_trust_fields_from_next_block(
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
    assert hits[0].verification == "name-only"


def test_yarn_classic_duplicate_direct_trust_field_falls_back(
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
    assert hits[0].verification == "name-only"


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
        "__metadata:\n  version: 9\n\n"
        '"keyv@npm:^6.0.0":\n  version: 6.0.0\n'
        '  resolution: "keyv@npm:6.0.0"\n',
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
def test_pnpm_empty_duplicate_or_untrusted_resolution_falls_back(
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
    assert _scan_hits(repo, policy)[0].verification == "name-only"


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
    "source,trusted",
    [
        ("registry+https://github.com/rust-lang/crates.io-index", True),
        ("sparse+https://index.crates.io/", True),
        ("git+https://evil.invalid/logtrace", False),
        (None, False),
    ],
)
def test_cargo_registry_trust_is_conjunctive(
    tmp_path: Path, source: str | None, trusted: bool
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
    assert bool(hits[0].versions) is trusted
    assert hits[0].verification == (
        "ioc-list-version-match" if trusted else "name-only"
    )


@pytest.mark.parametrize(
    "extra",
    [
        'version = "1.2.3"\n',
        'source = "sparse+https://index.crates.io/"\n',
        'name = "logtrace"\n',
    ],
)
def test_cargo_duplicate_identity_or_trust_field_falls_back(
    tmp_path: Path, extra: str
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
    assert _scan_hits(repo, policy)[0].verification == "name-only"


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


def test_directory_traversal_error_is_fail_closed_not_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    hidden = repo / "hidden"
    policy = _policy(tmp_path / "ioc.txt", "keyv")

    def broken_walk(root: Path, onerror=None):
        error = PermissionError("denied")
        error.filename = str(hidden)
        assert onerror is not None
        onerror(error)
        yield str(root), [], []

    monkeypatch.setattr(ioc_scan.os, "walk", broken_walk)
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


def test_no_lockfiles_is_clean_and_version_path_has_no_network_or_osv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = _policy(
        tmp_path / "ioc.txt", "keyv", "VERSION: npm | keyv | 6.0.0"
    )
    assert not hasattr(ioc_scan, "query_osv_api")
    assert _run_main(monkeypatch, repo, policy) == 0
