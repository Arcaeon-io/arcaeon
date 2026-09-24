# SPDX-License-Identifier: MIT
"""hooks/receipt_diff.py -- pre-commit hook: mint a receipt over the staged diff.

TRADE-OFF, STATED UP FRONT (read this before changing the exit-code logic):
a pre-commit hook that can block a commit is a hook someone reaches for
`--no-verify` around exactly when it matters most, and once a person learns
that reflex they use it for everything after -- at which point the hook is
decoration, not a gate. So THIS SCRIPT REFUSES TO BE THE REASON A COMMIT DOES
NOT HAPPEN. Minting is best-effort: a failed `git diff`, a failed digest, a
failed ledger append are all caught, reported to stderr as a WARN, and the
process still exits 0. Past argument parsing, there is no code path in this
file that returns nonzero -- that is the trade-off made concrete, not just
asserted. "The receipt could not be minted" and "the commit should not
happen" are two different sentences, and conflating them is exactly what
makes a hook get removed by the second week.

WHAT THE MINTED RECEIPT PROVES:
  - these exact bytes (the `git diff --cached` staged patch, hashed raw) were
    staged, hashed, and appended as one hash-chained row to
    `<repo>/.arcaeon/receipt_diff.ledger.jsonl`, on this machine, at the
    recorded local time.

WHAT IT DOES NOT PROVE:
  - that the diff was reviewed by anyone.
  - that this is the diff that ended up in the resulting commit -- a later
    `git commit --amend`, a merge-conflict resolution, or a hand-edited index
    can all diverge from what was hashed here.
  - that no commit was made with this hook bypassed. `--no-verify` skips this
    file entirely, and a bypassed commit leaves nothing here to see by
    definition. The gap-detection below narrows that blind spot into a
    labelled number; it does not close it (a bypass that also deletes or
    hand-edits the ledger file leaves no trace this hook can find).

BYPASS / GAP DETECTION -- the reason this exists instead of a one-line
`git diff | sha256sum`: each ledger row records `extra.parent_head`, the
`git rev-parse HEAD` at the moment this hook ran. A pre-commit hook always
runs BEFORE the commit object exists, so `parent_head` is the commit the
in-progress commit will become a child of. Exactly one new commit is expected
to land between one hook run and the next (the one the staged diff was for).
On the next run, `git rev-list --count <last-parent-head>..<current-head>`
counts every commit that actually landed in that window; subtracting the one
expected commit gives the number that landed WITHOUT this hook seeing them --
almost always `--no-verify`. That count is written into the new row and
printed to stderr, so the next run STATES the gap instead of quietly starting
clean. See `compute_gap()` for the exact cases (no prior receipt in the
ledger at all, a rewritten/unreachable parent_head, a plain clean run).
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Self-contained on purpose: this file is meant to be run straight out of a
# cloned/vendored copy of this repo by pre-commit's `language: system`, with
# no packaging step and no extra pip install. `arcaeon_ledger` lives right
# next to `hooks/` in this same repo, so put the repo root on sys.path rather
# than requiring the package be installed first.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from arcaeon.record.ledger import Ledger, bind_artefact  # noqa: E402


class GitError(RuntimeError):
    """A git invocation failed. Always caught; never allowed to block a commit."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_git(args: list[str], cwd: Path) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                           text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise GitError(f"git {' '.join(args)} failed to run: {e}") from e
    if r.returncode != 0:
        raise GitError(f"git {' '.join(args)} exited {r.returncode}: "
                       f"{(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()


def get_staged_diff_bytes(repo: Path) -> bytes:
    """`git diff --cached`, captured as raw bytes (binary-safe: this is
    hashed, never decoded, so it never has to agree on an encoding)."""
    try:
        r = subprocess.run(["git", "diff", "--cached"], cwd=str(repo),
                           capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise GitError(f"git diff --cached failed to run: {e}") from e
    if r.returncode != 0:
        raise GitError(f"git diff --cached exited {r.returncode}: "
                       f"{r.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return r.stdout


def get_head_sha(repo: Path) -> Optional[str]:
    """None means an unborn branch (no commits yet), not an error -- the
    caller already confirmed this is a real git repo before calling this."""
    try:
        return run_git(["rev-parse", "--verify", "HEAD"], repo)
    except GitError:
        return None


def ledger_path(repo: Path) -> Path:
    return repo / ".arcaeon" / "receipt_diff.ledger.jsonl"


def _last_row(path: Path) -> Optional[dict]:
    row = None
    for r in Ledger(path):  # empty/missing file yields nothing, never raises
        row = r
    return row


def _commits_since(repo: Path, since_ref: Optional[str], current_head: str) -> int:
    """Count of commits reachable from current_head, excluding those also
    reachable from since_ref. since_ref=None means 'from the start' (an
    unborn-HEAD hook run has no ref to name yet, so its parent_head is None
    and the count must run from the very first commit, not from nothing)."""
    args = ["rev-list", "--count", current_head] if since_ref is None \
        else ["rev-list", "--count", f"{since_ref}..{current_head}"]
    return int(run_git(args, repo))


def compute_gap(repo: Path, last_row: Optional[dict], current_head: Optional[str]) -> dict:
    """Label the gap since the last receipted diff. Never returns silence:
    every branch names a status, and 'clean' is a claim, not a default.

    Exactly one new commit is expected between one hook run and the next --
    the one the staged diff at that run was for. When there IS a prior row,
    the raw commit count since its parent_head has that one expected commit
    subtracted before it counts as a gap. When there is NO prior row, no
    commit was ever accounted for by this ledger, so nothing is subtracted:
    every commit reachable from current_head is unwitnessed history, whether
    that's "hook adopted on a repo that already had commits" or the natural
    result of every earlier commit having been made with the hook bypassed.
    """
    if last_row is None:
        if current_head is None:
            return {"status": "first_receipt", "gap_commits": 0}
        try:
            bypassed = _commits_since(repo, None, current_head)
        except (GitError, ValueError):
            return {"status": "unknown",
                    "message": "no prior receipt in this ledger, and prior history "
                               "could not be counted; gap unmeasurable"}
        if bypassed == 0:
            return {"status": "first_receipt", "gap_commits": 0}
        return {"status": "gap", "gap_commits": bypassed,
                "message": f"{bypassed} commit(s) since the last receipted diff "
                           f"(no prior receipt in this ledger -- hook adopted mid-history)"}
    prev_parent = (last_row.get("extra") or {}).get("parent_head")
    if current_head is None:
        return {"status": "unknown",
                "message": "no commits yet; cannot compare to the prior receipt"}
    if prev_parent == current_head:
        return {"status": "clean", "gap_commits": 0}
    try:
        raw = _commits_since(repo, prev_parent, current_head)
    except (GitError, ValueError):
        return {"status": "unknown",
                "message": "previous receipted parent_head not found in history "
                           "(rewritten?); gap unmeasurable"}
    bypassed = max(0, raw - 1)
    if bypassed == 0:
        return {"status": "clean", "gap_commits": 0}
    return {"status": "gap", "gap_commits": bypassed,
            "message": f"{bypassed} commit(s) since the last receipted diff"}


SCOPE = {
    "proves": [
        "These exact bytes (the `git diff --cached` staged patch) existed, "
        "were hashed, and a hash-chained ledger row for that digest was "
        "appended, on this machine, at the recorded local time.",
    ],
    "does_not_prove": [
        "That the diff was reviewed by anyone.",
        "That this is the diff that ended up in the resulting commit -- a "
        "later `git commit --amend`, a merge-conflict resolution, or a "
        "hand-edited index can all diverge from what was hashed here.",
        "That no commit was made with this hook bypassed. `--no-verify` skips "
        "this hook entirely; the parent_head gap check (see `extra.gap`) "
        "narrows that blind spot into a labelled count, it does not close it.",
    ],
    "method": "sha256 raw-bytes digest of `git diff --cached`'s output, appended "
              "as one row in a local arcaeon-ledger hash chain plus a parent_head "
              "gap check against the previous row.",
}


def mint_receipt(repo: Path) -> dict:
    """Best-effort mint. Returns a result dict describing what happened;
    never raises to its caller (main() wraps this again regardless, per the
    trade-off in the module docstring)."""
    try:
        diff = get_staged_diff_bytes(repo)
    except GitError as e:
        return {"minted": False, "error": f"git diff --cached failed: {e}"}
    if not diff.strip():
        return {"minted": False, "skipped": "nothing staged"}

    current_head = get_head_sha(repo)
    lpath = ledger_path(repo)
    try:
        last_row = _last_row(lpath)
    except Exception as e:  # noqa: BLE001 -- a read failure must not block the commit
        return {"minted": False, "error": f"could not read prior ledger rows: {e}"}
    gap = compute_gap(repo, last_row, current_head)

    try:
        artefact = bind_artefact(diff)
    except Exception as e:  # noqa: BLE001
        return {"minted": False, "error": f"could not digest the staged diff: {e}"}

    body = {
        "receipt_version": "arcaeon-receipt-diff/0.1",
        "kind": "staged-diff",
        "issued_at": _now_iso(),
        "subject": {"repo": str(repo), "diff_bytes": len(diff)},
        "checks": [{"check": "staged_diff_digest", "digest": artefact["digest"],
                    "bytes": len(diff), "gap": gap}],
        "scope": SCOPE,
        "extra": {"parent_head": current_head, "gap": gap, "artefact": artefact},
    }
    try:
        ledger = Ledger(lpath)
        chain = ledger.append(body)
    except Exception as e:  # noqa: BLE001 -- ledger-append failure must not block the commit
        return {"minted": False, "error": f"ledger append failed: {e}", "gap": gap}

    return {"minted": True, "chain": chain, "path": str(lpath), "gap": gap}


def main(argv: Optional[list[str]] = None) -> int:
    cwd = Path.cwd()
    try:
        repo = Path(run_git(["rev-parse", "--show-toplevel"], cwd)).resolve()
    except GitError as e:
        sys.stderr.write(f"receipt_diff: WARN not inside a git repo ({e}); "
                         f"skipping mint, NOT blocking the commit\n")
        return 0

    try:
        result = mint_receipt(repo)
    except Exception as e:  # noqa: BLE001 -- see module docstring: this must never block
        sys.stderr.write(f"receipt_diff: WARN receipt could not be minted "
                         f"({type(e).__name__}: {e}); NOT blocking the commit\n")
        return 0

    if result.get("skipped"):
        return 0
    if result.get("error"):
        sys.stderr.write(f"receipt_diff: WARN {result['error']}; NOT blocking the commit\n")
        return 0

    gap = result.get("gap") or {}
    if gap.get("message"):
        sys.stderr.write(f"receipt_diff: {gap['message']}\n")
    sys.stderr.write(f"receipt_diff: minted (chain {result.get('chain', '')[:16]}...) "
                     f"-> {result.get('path')}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
