#!/usr/bin/env python3
"""Classify external-review wrapper failures without authorizing unsafe retries.

Reads one JSON request object from stdin and writes one JSON result object to stdout
(error objects are written to stderr with a non-zero exit). The Claude result envelope
is supplied inline via ``result_envelope`` (a dict or a JSON string) or, failing that,
read from the file at ``log_path``.
"""
from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any


CODEX_ALIASES = {
    "codex",
    "codex cli",
    "codex-cli",
    "codex orchestrator",
    "codex-cli orchestrator",
    "gpt",
    "gpt orchestrator",
}
NO_READ_ROOT_FLAGS = {"", "none", "null", "n/a", "prompt-only"}
KNOWN_READ_ROOT_FLAGS = {"--repo", "--cd", "--add-dir"}
USAGE_TOKEN_KEYS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)


def _basename(value: Any) -> str:
    return os.path.basename(str(value or "").strip())


def _runtime(value: Any) -> str:
    return str(value or "").strip().lower()


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _argv_tokens(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    try:
        return shlex.split(str(value))
    except ValueError:
        return str(value).split()


def _derive_read_root_flag(payload: dict[str, Any]) -> str:
    explicit = str(payload.get("read_root_flag") or "").strip()
    if explicit:
        return explicit
    for token in _argv_tokens(payload.get("argv")):
        if token in KNOWN_READ_ROOT_FLAGS:
            return token
    return ""


def _derive_prompt_exports(payload: dict[str, Any], read_root_flag: str) -> bool:
    if _bool(payload.get("diff_inlined")):
        return True
    if read_root_flag in KNOWN_READ_ROOT_FLAGS:
        return True
    if read_root_flag.lower() not in NO_READ_ROOT_FLAGS:
        return True
    return any(token in KNOWN_READ_ROOT_FLAGS for token in _argv_tokens(payload.get("argv")))


def _json_object_from_text(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _load_result_envelope(payload: dict[str, Any]) -> dict[str, Any] | None:
    envelope = _json_object_from_text(payload.get("result_envelope"))
    if envelope is not None:
        return envelope
    log_path = payload.get("log_path")
    if not log_path:
        return None
    try:
        raw = Path(str(log_path)).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _json_object_from_text(raw)


def _all_usage_tokens_zero(usage: Any) -> bool:
    if not isinstance(usage, dict):
        return False
    for key in USAGE_TOKEN_KEYS:
        value = usage.get(key)
        if type(value) is not int or value != 0:
            return False
    return True


def _has_post_preflight_zero_usage_401(payload: dict[str, Any]) -> bool:
    wrapper_stderr = str(payload.get("wrapper_stderr") or "").lower()
    if "external-review-claude: auth ok" not in wrapper_stderr:
        return False
    envelope = _load_result_envelope(payload)
    if envelope is None:
        return False
    # Match api_error_status type-strictly (exact int), mirroring _all_usage_tokens_zero's
    # `type(...) is int` idiom, so a float 401.0 (401.0 == 401 is True in Python) or a bool cannot
    # satisfy this prong. Safe whatever the upstream CLI renders: this gate only authorizes the benign
    # smoke-probe-then-single-retry recovery, and no branch ever sets allow_unsandboxed_retry True, so a
    # rejected non-int can only *withhold* the transient classification (fail-closed), never grant one.
    api_error_status = envelope.get("api_error_status")
    return (
        type(api_error_status) is int
        and api_error_status == 401
        and envelope.get("modelUsage") == {}
        and _all_usage_tokens_zero(envelope.get("usage"))
    )


def classify(payload: dict[str, Any]) -> dict[str, Any]:
    runtime = _runtime(payload.get("runtime"))
    wrapper = _basename(payload.get("attempted_wrapper"))
    read_root_flag = _derive_read_root_flag(payload)
    exit_code = _int_or_none(payload.get("exit_code"))
    prompt_exports = _derive_prompt_exports(payload, read_root_flag)

    result: dict[str, Any] = {
        "classification": "unclassified_external_review_failure",
        "recommended_wrapper": "",
        "read_root_flag": read_root_flag,
        "prompt_exports_repo_diff": prompt_exports,
        "allow_unsandboxed_retry": False,
        "reason": "external-review failures do not authorize unsandboxed repo/diff reruns",
    }

    if runtime in CODEX_ALIASES and wrapper == "external-review-codex.sh":
        result.update(
            {
                "classification": "wrong_wrapper_local_init",
                "recommended_wrapper": "external-review-claude.sh",
                "read_root_flag": "--repo",
                "prompt_exports_repo_diff": True,
                "reason": "Codex/GPT orchestrators must use the reverse Claude wrapper",
            }
        )
        return result

    if wrapper == "external-review-claude.sh":
        if exit_code == 3:
            result.update(
                {
                    "classification": "reverse_wrapper_auth_unavailable",
                    "reason": "reverse wrapper reported no-spend auth/billing preflight unavailability",
                }
            )
            return result
        if exit_code == 2:
            result.update(
                {
                    "classification": "reverse_wrapper_local_config_failure",
                    "reason": "reverse wrapper failed before review with a local usage/config error",
                }
            )
            return result
        if exit_code == 1 and _has_post_preflight_zero_usage_401(payload):
            result.update(
                {
                    "classification": "reverse_wrapper_post_preflight_auth_transient",
                    "reason": "reverse wrapper passed auth preflight, but Claude returned a zero-usage 401; run sterile no-repo smoke probes, then retry the same reverse wrapper once with fresh findings/log paths if smoke succeeds",
                }
            )
            return result

    return result


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"invalid json: {exc}"}), file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print(json.dumps({"error": "input must be a JSON object"}), file=sys.stderr)
        return 2
    print(json.dumps(classify(payload), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
