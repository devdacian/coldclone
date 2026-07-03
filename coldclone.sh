#!/usr/bin/env bash
# coldclone — safely clone and screen an untrusted repo before you open it.
#
# Encodes the deterministic, security-critical steps for getting a hostile repo
# onto your machine without a forgotten flag reopening a known hole (Git LFS
# smudge execution, symlink-following exfiltration, .gitmodules path traversal,
# moving an unsanitized tree across an isolation boundary, recursive `scp -r`
# pulls from an untrusted sandbox).
#
# It is defense-in-depth in FRONT of whatever isolation environment you run (a
# throwaway virtual machine, a container, a sandbox) — not a replacement for
# one. The clone, scan, and sanitize steps run on your host and execute nothing
# from the repo; moving the inert tree INTO the isolation environment and
# inspecting it there stays a deliberate, manual step.
#
# Synopsis:
#   coldclone <url>                       shortcut for: coldclone prep <url>
#   coldclone prep   <url> [--ref R] [--submodules]
#   coldclone fetch  <url> [scratch-parent] [--ref R] [--submodules]
#   coldclone scan   <dir>
#   coldclone sanitize <dir>
#   coldclone sanitize-folder <dir>      non-git folder (extracted ZIP); read in place
#   coldclone check  <dir>
#   coldclone push   <dir> <ssh-target> [--insecure-host-key]
#   coldclone pull   <ssh-target> <dest-dir> <file>... [--insecure-host-key]
#
# Examples:
#   coldclone https://github.com/some/untrusted-repo   # fetch -> scan -> sanitize
#   coldclone prep git@github.com:some/repo --ref v1.2.3 --submodules
#   coldclone push ./coldclone-scratch/repo user@sandbox
#
# Subcommands:
#   fetch  <repo-url> [scratch-parent] [--ref <branch|tag|commit>] [--submodules]
#                         Hardened host clone (LFS smudge off, symlinks off,
#                         no submodule recurse). --ref checks out a specific
#                         branch, tag, or commit (the review target) BEFORE
#                         submodule assembly, so submodules pin to that ref's
#                         recorded SHAs; omitted, it stays on the remote's
#                         default branch. With --submodules, also fetches
#                         each submodule pinned to the parent's SHA. Top-level
#                         .gitmodules paths are wrapper-pre-validated against
#                         traversal (defense-in-depth); nested levels rely on
#                         git's native submodule-path validation
#                         (CVE-2018-11235), and the protocol/symlink/LFS guards
#                         are passed via -c so they apply through --recursive.
#   scan   <repo-dir>     Grep lockfiles for known-malicious dependencies
#                         (ioc_scan.py). HALTs on a hit. Read-only; no execution.
#   sanitize <repo-dir>   Run sanitize_repo.py over the assembled (git) tree.
#                         Fails closed (exit 2) on a missing .git.
#   sanitize-folder <repo-dir>
#                         FOLDER MODE: sanitize a non-git directory (an extracted
#                         ZIP) via sanitize_repo.py --allow-no-git. Skips the
#                         host-controlled sentinel (one-shot, non-idempotent),
#                         actively quarantines any repo-shipped .git/, and is NOT
#                         eligible for check/push (no unforgeable proof). The flow
#                         is sanitize-then-read-IN-PLACE.
#   check  <repo-dir>     Re-prove a tree is still inert (sanitize_repo.py
#                         --check): exit 0 = clean, non-zero = dirty. Transport-
#                         agnostic; run it any time, e.g. before moving a tree.
#                         Intended ONLY for coldclone-FETCHED (git) trees. A
#                         non-git folder IS refused here. A hand-extracted archive
#                         that SHIPS a forged .git sentinel is now REFUSED: the
#                         in-tree sentinel is non-authoritative; authority comes
#                         from the .git-hygiene gate (live hooks / exec config) AND
#                         an out-of-tree, filesystem-identity-keyed host provenance
#                         record that never enters any tree. Still: run
#                         sanitize-folder on an extracted archive, and never run
#                         check/push on a tree coldclone did not fetch.
#   push   <repo-dir> <ssh-target> [--insecure-host-key]
#                         scp the SANITIZED tree into the isolation environment's
#                         fixed remote work dir. Refuses if it was never sanitized.
#                         Git-only (like check); a non-git folder is refused.
#   pull   <ssh-target> <dest-dir> <remote-file>... [--insecure-host-key]
#                         Pull NAMED deliverable files only (never a directory).
#   prep   <repo-url> [--ref <branch|tag|commit>] [--submodules]
#                         fetch -> scan -> sanitize in one shot (common case).
#                         The scan gate runs FIRST so a repo declaring a
#                         malicious dependency is caught before sanitize. Prints
#                         REPO_DIR= and the next step (copy it into your isolation
#                         environment, or `coldclone push`).
#
# Host-key trust: push/pull verify the target host key by default
#   (StrictHostKeyChecking=accept-new against your real known_hosts). Pass
#   --insecure-host-key for an EPHEMERAL target whose host key legitimately
#   changes each run — this disables host-key verification (TOFU is lost), so
#   use it ONLY for a throwaway target you control.
#
# Exit codes: 0 ok, 1 refusal/usage, 2 environment problem, 3 injection-halt
# (sanitize/check/push found high-confidence prompt-injection — review the alert,
# then re-run with --ack-injection once confirmed benign). Note: `scan` and
# `prep` surface an IoC hit as a REFUSAL (exit 1) — the wrapper translates the
# standalone scanner's exit 2 (IoC hit) into a refusal; the scanner's own exit
# codes (2 hit, 3 config error) apply only when you run ioc_scan.py directly.
# (ioc_scan.py's exit 3 is a DIFFERENT script and is remapped in cmd_scan, so a
# wrapper exit 3 is unambiguously the injection-halt above.)
#
# Prompt-injection ack: sanitize/check/push HALT (exit 3) on high-confidence
# prompt-injection and require `--ack-injection` on THE SAME invocation to
# proceed. The wrapper SCRUBS an ambient COLDCLONE_ACK_INJECTION env var unless
# the flag was passed this run (so an exported var can't silently ack every
# future check/push). Direct python users may still use the env var (expert
# mode); the wrapper is the strict primary UX — a deliberate asymmetry.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANITIZER="$SCRIPT_DIR/sanitize_repo.py"
IOC_SCANNER="$SCRIPT_DIR/ioc_scan.py"
SCRATCH_DEFAULT="${COLDCLONE_SCRATCH:-$HOME/coldclone-scratch}"

# Per-run temp dirs (empty git-template dirs) registered for cleanup on EXIT, so a
# `git clone`/`submodule update` failure under `set -e` can't leak them.
_TMPDIRS=()
_cleanup_tmpdirs() { local d; for d in ${_TMPDIRS[@]+"${_TMPDIRS[@]}"}; do [ -n "$d" ] && rm -rf "$d"; done; }
trap _cleanup_tmpdirs EXIT

# Host-key verification ON by default: accept-new records an unknown host's key
# in the user's real known_hosts on first contact, then verifies it on every
# later run (TOFU). `--insecure-host-key` swaps in the relaxed options below for
# an ephemeral target whose key legitimately rotates each run.
SCP_OPTS=(-o StrictHostKeyChecking=accept-new)
SCP_OPTS_INSECURE=(-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no)
CLONE_FLAGS=(-c core.symlinks=false --no-recurse-submodules)
# Neutralize the git-lfs filter at the GIT level (not just the env var, which
# still invokes lfs): empty smudge/clean/process + required=false so a checkout
# never runs the lfs filter process. A repo can only TRIGGER filters whose
# commands are defined in HOST config (a fresh clone can't inject a filter
# command); git-lfs is the only one commonly host-installed, so killing it here
# closes the realistic repo-triggered filter-exec vector. A hardened host must
# not configure other untrusted-triggering custom filter drivers.
LFS_OFF=(-c filter.lfs.smudge= -c filter.lfs.clean= -c filter.lfs.process= -c filter.lfs.required=false)

die()  { echo "coldclone: $*" >&2; exit 1; }
die2() { echo "coldclone: $*" >&2; exit 2; }
die3() { echo "coldclone: $*" >&2; exit 3; }   # tier-2 prompt-injection halt

need() { command -v "$1" >/dev/null 2>&1 || die2 "required tool not found: $1"; }

# --- path-traversal guard for an untrusted .gitmodules `path` value ----------
# Confirms <regpath> resolves strictly UNDER <parent> (rejects absolute and
# `..` escapes). macOS realpath has no -m, so use portable pathlib.
path_under_parent() {
  local parent=$1 regpath=$2
  python3 - "$parent" "$regpath" <<'PY'
import sys, pathlib
parent = pathlib.Path(sys.argv[1]).resolve()
dest = (parent / sys.argv[2]).resolve()
sys.exit(0 if str(dest).startswith(str(parent) + "/") else 1)
PY
}

# --- pinned, path-validated submodule assembly -------------------------------
# Defense-in-depth: pre-reject any traversal/absolute registered path (git also
# rejects these natively since CVE-2018-11235), then let git's own machinery
# resolve URLs (including relative-to-origin), check out the parent-pinned SHAs,
# and recurse — with symlinks OFF (neutralizes the CVE-2024-32002 clone-time RCE
# class on this case-insensitive macOS FS), LFS smudge OFF (no filter exec), and
# the file/ext transports OFF. The .gitmodules URLs are attacker-controlled: an
# `ext::sh -c ...` URL would execute arbitrary commands on the host and a
# `file://` URL would clone a host-local repo into the tree — `-c
# protocol.file.allow=never -c protocol.ext.allow=never` blocks both regardless
# of ambient git config (https/ssh, incl. relative-to-origin, still resolve).
fetch_submodules() {
  local parent=$1 regpath
  [ -f "$parent/.gitmodules" ] || return 0
  # Parse with `-z` so a submodule path containing whitespace is validated in
  # full (awk '{print $2}' would truncate it, validating the wrong string while
  # `git submodule update` acts on the real one). Each -z entry is
  # "key\nvalue\0"; the path value is everything after the first newline.
  while IFS= read -r -d '' entry; do
    regpath="${entry#*$'\n'}"
    [ -n "$regpath" ] || continue
    path_under_parent "$parent" "$regpath" \
      || die "REFUSE: submodule path '$regpath' escapes '$parent' (malicious .gitmodules?)"
    echo "  submodule path validated: $regpath"
  done < <(git -C "$parent" config --file .gitmodules -z --get-regexp '\.path$')

  # Empty template for submodule gitdirs too — so `.git/modules/**` get no hook
  # surface and Layer A does not false-positive on an operator's --submodules
  # fetch. Per-invocation host-owned dir, cleaned up after.
  local _sub_tmpl; _sub_tmpl=$(mktemp -d); _TMPDIRS+=("$_sub_tmpl")
  GIT_LFS_SKIP_SMUDGE=1 git -C "$parent" \
    -c core.symlinks=false -c submodule.recurse=false \
    -c protocol.file.allow=never -c protocol.ext.allow=never \
    -c init.templateDir="$_sub_tmpl" \
    "${LFS_OFF[@]}" \
    submodule update --init --recursive
  rm -rf "$_sub_tmpl"

  # Persist core.symlinks=false into every fetched submodule's own config, so a
  # later host-side checkout inside a submodule can't re-materialize symlinks
  # (the process-scoped -c above only covered the update just run). Parity with
  # the persisted `clone -c core.symlinks=false` on the parent. The sanitize +
  # push --check symlink scans remain the enforced backstop regardless.
  git -C "$parent" submodule foreach --recursive \
    'git config core.symlinks false' >/dev/null
}

sanitized_ok() {
  # FRESH fail-closed re-scan via `sanitize_repo.py --check` — proves the tree
  # is sanitized AS IT IS NOW (no live symlinks, no un-quarantined triggers),
  # not merely that sanitize ran once. Immune to a stale sentinel (tree mutated
  # after sanitize) AND to a forged worktree manifest (the check re-derives the
  # answer from the tree). Its stderr lists any dirty items. Returns the raw rc
  # (incl. 3 = injection-halt) so the caller can translate it.
  #
  # Ack is THREADED as a parameter (shared by cmd_check + cmd_push, so the env is
  # built per-caller). The ambient COLDCLONE_ACK_INJECTION is SCRUBBED with
  # `env -u` unless `--ack-injection` was given THIS invocation — so an exported
  # var can't silently ack every check/push.
  local repo=$1 ack=${2:-}
  [ -f "$SANITIZER" ] || die2 "sanitizer not found next to this script: $SANITIZER"
  if [ -n "$ack" ]; then
    COLDCLONE_ACK_INJECTION=1 python3 "$SANITIZER" --check --ack-injection "$repo"
  else
    env -u COLDCLONE_ACK_INJECTION python3 "$SANITIZER" --check "$repo"
  fi
}

# --- subcommands -------------------------------------------------------------
cmd_fetch() {
  need git; need python3
  local url="" parent="$SCRATCH_DEFAULT" subs=0 ref=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --submodules) subs=1 ;;
      --ref) shift; [ "$#" -gt 0 ] || die "--ref requires a value (branch, tag, or commit)"; ref=$1 ;;
      --ref=*) ref=${1#--ref=} ;;
      -*) die "unknown flag: $1" ;;
      *) if [ -z "$url" ]; then url=$1; else parent=$1; fi ;;
    esac
    shift
  done
  [ -n "$url" ] || die "usage: fetch <repo-url> [scratch-parent] [--ref <branch|tag|commit>] [--submodules]"
  # The ref is auditor-supplied (not from the untrusted repo), but still guard
  # against option-injection into `git checkout`: reject a leading dash.
  case "$ref" in
    -*) die "refuse: --ref value '$ref' starts with '-' (would be parsed as a git flag)" ;;
  esac

  # Reject a credential embedded in the URL (userinfo before the host, e.g.
  # https://TOKEN@github.com/...): git stores it in .git/config, and `push`
  # copies .git/ into the isolation environment — leaking the token and breaking
  # the "the isolation environment holds no GitHub credential" premise (the
  # sanitizer skips .git/). SSH (git@host:org/repo — no `://`) and the credential
  # helper keep .git/config clean.
  case "$url" in
    *://*)
      _auth=${url#*://}; _auth=${_auth%%/*}
      case "$_auth" in
        *@*) die "refuse: clone URL embeds credentials (userinfo '@') — they would land in .git/config and reach the isolation environment. Use SSH (git@github.com:org/repo) or your git credential helper." ;;
      esac
      case "$url" in
        *\?*|*\#*) die "refuse: clone URL has a query/fragment — strip it (a clean repo URL needs none; tokens must not ride in via the URL)." ;;
      esac ;;
  esac

  mkdir -p "$parent"
  local name dest; name=$(basename "$url" .git); dest="$parent/$name"
  [ -e "$dest" ] && die "refuse: $dest already exists — delete it first (scp/cp nest into existing dirs)"

  echo "fetch: hardened clone -> $dest"
  # Empty fetch template: a host `init.templateDir` (or the default
  # /usr/share/git-core/templates) can inject live `.git/hooks/` into a fresh
  # clone. `--template=<empty mktemp -d>` gives the clone NO hook surface so the
  # Layer A .git-hygiene gate does not false-positive on the operator's own
  # fetch. Per-invocation host-owned dir, cleaned up after the clone.
  local _tmpl; _tmpl=$(mktemp -d); _TMPDIRS+=("$_tmpl")
  # `-c protocol.ext.allow=never`: git's default allows the `ext::` transport
  # for top-level clones, so a client-supplied `ext::sh -c ...` repo URL pasted
  # here would execute on the host. `ext::` is never a legitimate clone URL, so
  # block it. `file://` is left at git's default for the PARENT (a user-typed
  # URL that may legitimately be a local repo, and whose content is sanitized
  # before reaching the isolation environment); it stays blocked for attacker-
  # controlled SUBMODULE URLs in fetch_submodules.
  GIT_LFS_SKIP_SMUDGE=1 git -c protocol.ext.allow=never "${LFS_OFF[@]}" \
    clone --template="$_tmpl" "${CLONE_FLAGS[@]}" "$url" "$dest"
  rm -rf "$_tmpl"

  # Backstop: inspect the PERSISTED remote URL after clone (catches a token
  # injected by a global `url.<creds>.insteadOf` rewrite despite a clean input
  # URL, plus any query/fragment). The clone is still host-side scratch, so
  # refusing here is safe — nothing has reached the isolation environment yet.
  _purl=$(git -C "$dest" config --get remote.origin.url 2>/dev/null || echo "")
  case "$_purl" in
    *://*)
      _pauth=${_purl#*://}; _pauth=${_pauth%%/*}
      case "$_pauth" in *@*) rm -rf "$dest"; die "refuse: stored remote URL embeds credentials ($_purl) — clean your git config (no url.insteadOf token rewrite) and retry." ;; esac
      case "$_purl" in *\?*|*\#*) rm -rf "$dest"; die "refuse: stored remote URL has a query/fragment ($_purl) — strip it and retry." ;; esac ;;
  esac

  # Check out the audit target (branch/tag/commit) BEFORE submodule assembly, so
  # submodules pin to the SHAs recorded AT THAT REF rather than the default
  # branch's. A full clone already fetched every remote branch, so any commit
  # reachable from a branch tip (a feature branch, or any of its history) is
  # present — no extra fetch needed. The LFS filter stays neutralized on the
  # re-checkout (it rewrites worktree files), and core.symlinks=false is already
  # persisted in the clone config so symlinks stay inert plain files.
  if [ -n "$ref" ]; then
    echo "fetch: checking out ref: $ref"
    GIT_LFS_SKIP_SMUDGE=1 git -C "$dest" "${LFS_OFF[@]}" -c advice.detachedHead=false \
      checkout "$ref" \
      || { rm -rf "$dest"; die "ref not found in clone: '$ref' — must be a branch, tag, or a commit reachable from one (list with: git ls-remote $url)"; }
    echo "fetch: now at $(git -C "$dest" rev-parse HEAD) ($(git -C "$dest" rev-parse --abbrev-ref HEAD))"
  fi

  if [ -f "$dest/.gitmodules" ]; then
    if [ "$subs" -eq 1 ]; then
      echo "fetch: assembling submodules (pinned + path-validated)"
      fetch_submodules "$dest"
    else
      echo "fetch: NOTE — repo declares submodules; re-run with --submodules to fetch them, or handle per the plan:"
      git -C "$dest" config --file .gitmodules --get-regexp '\.path$' | awk '{print "  - "$2}'
    fi
  fi
  echo "fetch: done. NEXT: $0 scan $dest && $0 sanitize $dest   (or use '$0 prep ...' for the full enforced fetch->scan->sanitize sequence)"
  echo "REPO_DIR=$dest"
}

cmd_scan() {
  # Known-malicious-dependency tripwire — greps lockfiles only (no execution),
  # so it is safe on an untrusted tree. Runs FIRST in prep, before sanitize, so
  # a repo declaring a confirmed-malicious package is caught up front.
  # Exit 2 = hit -> HALT prep; exit 0/1 = no hit (1 also warns the list is stale).
  need python3
  local repo=${1:-}; [ -n "$repo" ] || die "usage: scan <repo-dir>"
  [ -d "$repo" ] || die "no such dir: $repo"
  [ -f "$IOC_SCANNER" ] || die2 "ioc scanner not found next to this script: $IOC_SCANNER"
  local rc=0
  python3 "$IOC_SCANNER" "$repo" || rc=$?
  case "$rc" in
    0|1) ;;  # no malicious dependency found (1 = clean-but-stale-list warning); proceed
    2) die "REFUSE: $repo declares a KNOWN-MALICIOUS dependency (see above). Treat the repo as hostile. It has NOT been moved into any isolation environment; inspect it only inside your isolation environment if you consciously choose to." ;;
    3) die2 "REFUSE: the IoC gate could NOT run on $repo (see above — IoC list missing/unreadable or bad path). Failing CLOSED: fix the gate before proceeding. The repo has NOT been moved into any isolation environment." ;;
    *) die "scan errored (exit $rc) on $repo" ;;
  esac
}

cmd_sanitize() {
  need python3
  local repo="" ack=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --ack-injection) ack=1 ;;
      -*) die "unknown flag: $1" ;;
      *) if [ -z "$repo" ]; then repo=$1; fi ;;
    esac
    shift
  done
  [ -n "$repo" ] || die "usage: sanitize <repo-dir> [--ack-injection]"
  [ -d "$repo" ] || die "no such dir: $repo"
  [ -f "$SANITIZER" ] || die2 "sanitizer not found next to this script: $SANITIZER"
  local rc=0
  if [ -n "$ack" ]; then
    COLDCLONE_ACK_INJECTION=1 python3 "$SANITIZER" --ack-injection "$repo" || rc=$?
  else
    env -u COLDCLONE_ACK_INJECTION python3 "$SANITIZER" "$repo" || rc=$?
  fi
  case "$rc" in
    0) : ;;
    3) die3 "injection detected — review the alert above; re-run: $0 sanitize --ack-injection $repo" ;;
    *) exit "$rc" ;;  # propagate the sanitizer's own failure (tier-1, env, etc.)
  esac
  echo "sanitize: review $repo/.quarantine/MANIFEST.txt before moving the tree"
}

cmd_sanitize_folder() {
  # FOLDER MODE: sanitize a non-git directory (an extracted ZIP) via
  # sanitize_repo.py --allow-no-git. Unlike `sanitize`, this does NOT fail closed
  # on a missing .git; instead it skips the host-controlled sentinel, refuses
  # check/push eligibility, and actively quarantines any repo-shipped .git/. The
  # dominant flow is sanitize-then-read-IN-PLACE — there is no unforgeable proof
  # to gate a sandbox push, so check/push stay git-only.
  need python3
  local repo="" ack=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --ack-injection) ack=1 ;;
      -*) die "unknown flag: $1" ;;
      *) if [ -z "$repo" ]; then repo=$1; fi ;;
    esac
    shift
  done
  [ -n "$repo" ] || die "usage: sanitize-folder <repo-dir> [--ack-injection]"
  [ -d "$repo" ] || die "no such dir: $repo"
  [ -f "$SANITIZER" ] || die2 "sanitizer not found next to this script: $SANITIZER"
  local rc=0
  if [ -n "$ack" ]; then
    COLDCLONE_ACK_INJECTION=1 python3 "$SANITIZER" --allow-no-git --ack-injection "$repo" || rc=$?
  else
    env -u COLDCLONE_ACK_INJECTION python3 "$SANITIZER" --allow-no-git "$repo" || rc=$?
  fi
  case "$rc" in
    0) : ;;
    3) die3 "injection detected — review the alert above; re-run: $0 sanitize-folder --ack-injection $repo" ;;
    *) exit "$rc" ;;  # propagate the sanitizer's own failure (tier-1, env, etc.)
  esac
  echo "sanitize-folder: review $repo/.quarantine/MANIFEST.txt, then read the tree IN PLACE"
  echo "sanitize-folder: NOTE folder mode has no unforgeable sanitize proof — check/push are git-only"
}

cmd_check() {
  # Thin wrapper over sanitize_repo.py --check (via sanitized_ok): re-derive,
  # from the tree as it is NOW, whether it is still inert. Transport-agnostic —
  # run it any time to prove a tree has not been re-armed since sanitize. Exit
  # 0 = inert, non-zero = dirty (the check lists the offending items).
  need python3
  local repo="" ack=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --ack-injection) ack=1 ;;
      -*) die "unknown flag: $1" ;;
      *) if [ -z "$repo" ]; then repo=$1; fi ;;
    esac
    shift
  done
  [ -n "$repo" ] || die "usage: check <repo-dir> [--ack-injection]"
  [ -d "$repo" ] || die "no such dir: $repo"
  # Folder (no .git at all): there is no host-controlled sentinel, so --check
  # cannot prove a sanitize ran. Refuse with the folder-specific remediation
  # BEFORE sanitized_ok (which would otherwise return the generic dirty-tree
  # message — the wrong fix). Use -e NOT -d: a legit gitlink-FILE worktree has
  # `.git` as a FILE and stays git mode.
  if [ ! -e "$repo/.git" ]; then
    die "folder has no unforgeable sanitize proof; sanitize+read in place, or use a git source for sandbox push."
  fi
  local rc=0
  sanitized_ok "$repo" "$ack" || rc=$?
  case "$rc" in
    0) : ;;
    3) die3 "injection detected — review the alert above; re-run: $0 check --ack-injection $repo" ;;
    *) die "not sanitized as-is (see above) — run: $0 sanitize $repo" ;;
  esac
  return 0
}

cmd_push() {
  need scp
  local repo="" target="" ack="" scp_opts=("${SCP_OPTS[@]}")
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --insecure-host-key) scp_opts=("${SCP_OPTS_INSECURE[@]}") ;;
      --ack-injection) ack=1 ;;
      -*) die "unknown flag: $1" ;;
      *) if [ -z "$repo" ]; then repo=$1; elif [ -z "$target" ]; then target=$1; fi ;;
    esac
    shift
  done
  [ -n "$repo" ] && [ -n "$target" ] || die "usage: push <repo-dir> <ssh-target> [--insecure-host-key] [--ack-injection]"
  [ -d "$repo" ] || die "no such dir: $repo"
  # Folder (no .git at all): no host-controlled sentinel → no unforgeable proof
  # to gate moving the tree across the isolation boundary. Refuse with the
  # folder-specific remediation BEFORE sanitized_ok. Use -e NOT -d so a legit
  # gitlink-FILE worktree (`.git` is a FILE) stays git mode.
  if [ ! -e "$repo/.git" ]; then
    die "folder has no unforgeable sanitize proof; sanitize+read in place, or use a git source for sandbox push."
  fi
  local rc=0
  sanitized_ok "$repo" "$ack" || rc=$?
  case "$rc" in
    0) : ;;
    3) die3 "injection detected — review the alert; re-run: $0 push --ack-injection $repo $target" ;;
    *) die "refuse: $repo is not sanitized as-is (see above) — refusing to move an unscreened tree across an isolation boundary; run: $0 sanitize $repo" ;;
  esac
  # The fixed remote work dir (`work/` under the target's login home) must
  # already exist; -r is safe here because the tree is SANITIZED and the host
  # controls it. The literal destination is fixed (not user-supplied), so there
  # is no shell-interpreted remote path to validate.
  echo "push: $repo -> $target:work/"
  scp "${scp_opts[@]}" -r "$repo" "$target":'work/'
  echo "push: done. Delete the host scratch copy when you are finished: rm -rf $repo"
}

cmd_pull() {
  need scp
  local target="" dest="" scp_opts=("${SCP_OPTS[@]}") files=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --insecure-host-key) scp_opts=("${SCP_OPTS_INSECURE[@]}") ;;
      *) if [ -z "$target" ]; then target=$1
         elif [ -z "$dest" ]; then dest=$1
         else files+=("$1"); fi ;;
    esac
    shift
  done
  [ -n "$target" ] && [ -n "$dest" ] && [ "${#files[@]}" -gt 0 ] \
    || die "usage: pull <ssh-target> <dest-dir> <remote-file>... [--insecure-host-key] (named files only)"
  [ -d "$dest" ] || die "no such dest dir: $dest (create your quarantine dir first)"
  local f
  for f in "${files[@]}"; do
    case "$f" in
      */)
        die "refuse: '$f' looks like a directory — pull NAMED files only (no recursive pull from an untrusted remote)" ;;
      *[!A-Za-z0-9._@+,:=~/-]*)
        # Conservative literal-path allowlist. scp can hand the remote path to a
        # shell on the (untrusted) remote, and odd characters weaken the
        # named-file-only intent; restrict to a safe set so a crafted remote
        # filename can't carry shell metacharacters (`;` `\` "\$" backtick
        # ' " & | () <> whitespace …). Real deliverable names fit easily.
        die "refuse: '$f' has a disallowed character — give a literal path in the remote work dir (letters/digits . _ - / @ + , : = ~)" ;;
      *[][{}*?]*)
        # scp expands globs on the REMOTE — a pattern lets the untrusted remote
        # choose which/how many files to send. Require one explicit literal path.
        die "refuse: '$f' contains a glob metacharacter — give one explicit named path per file" ;;
      ".."|"."|../*|*/..|*/../*)
        die "refuse: '$f' is a traversal path — give an explicit file under the remote work dir" ;;
      *)
        echo "pull: $target:$f -> $dest/"
        scp "${scp_opts[@]}" "$target":"$f" "$dest"/ ;;
    esac
  done
  echo "pull: done. Eyeball the files in $dest before use."
}

cmd_prep() {
  local url="" subs="" ref="" ack=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --submodules) subs=--submodules ;;
      --ack-injection) ack=1 ;;
      --ref) shift; [ "$#" -gt 0 ] || die "--ref requires a value (branch, tag, or commit)"; ref=$1 ;;
      --ref=*) ref=${1#--ref=} ;;
      -*) die "unknown flag: $1" ;;
      *) if [ -z "$url" ]; then url=$1; fi ;;
    esac
    shift
  done
  [ -n "$url" ] || die "usage: prep <repo-url> [--ref <branch|tag|commit>] [--submodules]"
  local out repo
  local fetch_args=("$url")
  [ -n "$ref" ]  && fetch_args+=(--ref "$ref")
  [ -n "$subs" ] && fetch_args+=("$subs")
  # Strip fetch's own REPO_DIR= line from the pass-through; prep emits a single
  # canonical REPO_DIR= line at the end (one machine-readable contract line).
  out=$(cmd_fetch "${fetch_args[@]}"); echo "$out" | sed '/^REPO_DIR=/d'
  repo=$(echo "$out" | sed -n 's/^REPO_DIR=//p')
  [ -n "$repo" ] || die "prep: could not determine repo dir from fetch output"
  cmd_scan "$repo"        # known-malicious-dependency tripwire FIRST — HALTs before sanitize on a hit
  if [ -n "$ack" ]; then cmd_sanitize "$repo" --ack-injection; else cmd_sanitize "$repo"; fi
  echo "REPO_DIR=$repo"
  echo "prep: done. NEXT: copy $repo into your isolation environment (or '$0 push $repo <ssh-target>'); verify it stays inert any time with '$0 check $repo'."
}

main() {
  local sub=${1:-}; shift || true
  case "$sub" in
    fetch)    cmd_fetch "$@" ;;
    scan)     cmd_scan "$@" ;;
    ioc)      cmd_scan "$@" ;;   # hidden back-compat alias for `scan`
    sanitize) cmd_sanitize "$@" ;;
    sanitize-folder) cmd_sanitize_folder "$@" ;;
    check)    cmd_check "$@" ;;
    push)     cmd_push "$@" ;;
    pull)     cmd_pull "$@" ;;
    prep)     cmd_prep "$@" ;;
    ""|-h|--help)
      # Print the leading comment block (skip the shebang, stop at the first
      # non-comment line) so this never drifts when the header grows.
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}" ;;
    *)
      # Bare `coldclone <url>` shortcut: route the first arg to `prep` ONLY IF it
      # is not a flag AND is an EXPLICIT remote clone spec — a `scheme://…` URL or
      # an scp-form `user@host:path` (user REQUIRED). A typo'd verb, an unknown
      # flag (`-x`), an ordinary file/dir, and a userless `host:path` all fall
      # through to the error. A local repo uses the explicit `coldclone prep <path>`.
      case "$sub" in
        -*) die "unknown subcommand: $sub (try --help)" ;;
        *://*) cmd_prep "$sub" "$@" ;;
        *@*:*) cmd_prep "$sub" "$@" ;;
        *) die "unknown subcommand: $sub (try --help)" ;;
      esac ;;
  esac
}

main "$@"
