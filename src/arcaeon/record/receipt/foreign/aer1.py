# SPDX-License-Identifier: MIT
"""AER-1 execution receipts (issuer zambo.dev): detect and verify.

The issuer's rule: recompute sha256 over the published canonical bytes and
compare. A receipt row carries result_sha256 and output_hash; both are the
sha256 hex of the receipt's canonical bytes, which the issuer's API serves
base64-encoded as `canonical_bytes` at https://zambo.dev/api/receipt/<id>.

This module fetches nothing. The caller supplies the decoded canonical bytes
(`receipt verify --canonical-bytes <file>`); without them the answer is
COULD NOT LOOK, never a pass. What VERIFIED proves is narrow: the bytes the
caller supplied hash to both digests on the row. It does not check the
issuer's anchors, chain claim or conformance kit, and bytes served by the
issuer's own server are the issuer's word about them.

Workflow receipts (AER-1 revision -03, Section 8) carry `merkle_root` over a
`steps` list of step receipts. Each step's digest is checked against its own
canonical bytes (BROKEN names the step that differs). The root is recomputed
from the listed step digests in the order given: leaves are the raw 32-byte
digests, each parent is sha256(left || right), an odd last node is paired
with itself. That construction is our assumption, not read from the spec:
a root that does not match it is COULD NOT LOOK, never BROKEN, until it is
confirmed against -03 Section 8. The workflow's output hash and goal
binding are not checked.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Optional

from arcaeon import verdict as V

ISSUER = "zambo.dev"
FORMAT = "AER-1"
API = "https://zambo.dev/api/receipt/"
DIGEST_FIELDS = ("result_sha256", "output_hash")


@dataclass(frozen=True)
class Verdict:
    word: str      # V.VERIFIED, V.BROKEN or V.COULD_NOT_LOOK
    reason: str


UNCONFIRMED = "merkle construction unconfirmed against AER-1 -03 section 8"


def detect_workflow(obj: Any) -> bool:
    """True for a JSON object carrying merkle_root and a steps list (AER-1 -03
    Section 8 workflow receipt) and no Arcaeon receipt_version."""
    if not isinstance(obj, dict):
        return False
    if "merkle_root" not in obj or not isinstance(obj.get("steps"), list):
        return False
    ver = obj.get("receipt_version")
    return not (isinstance(ver, str) and ver.startswith("arcaeon-receipt/"))


def detect(obj: Any) -> bool:
    """True for a JSON object carrying result_sha256 and output_hash, or a
    workflow receipt (merkle_root plus steps), and no Arcaeon
    receipt_version."""
    if not isinstance(obj, dict):
        return False
    if detect_workflow(obj):
        return True
    if not all(f in obj for f in DIGEST_FIELDS):
        return False
    ver = obj.get("receipt_version")
    return not (isinstance(ver, str) and ver.startswith("arcaeon-receipt/"))


def receipt_id(obj: dict) -> Optional[str]:
    for k in ("id", "receipt_id"):
        if isinstance(obj.get(k), str) and obj[k]:
            return obj[k]
    url = obj.get("receipt_url")
    if isinstance(url, str) and url.rstrip("/"):
        return url.rstrip("/").rsplit("/", 1)[-1]
    return None


def _norm(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    v = v.strip().lower()
    return v[len("sha256:"):] if v.startswith("sha256:") else v


def verify(obj: dict, canonical_bytes: bytes | None) -> Verdict:
    rid = receipt_id(obj) if isinstance(obj, dict) else None
    if canonical_bytes is None:
        where = API + (rid or "<id>")
        return Verdict(V.COULD_NOT_LOOK,
                       "no canonical bytes supplied; they come from the issuer's API "
                       f"({where}, field canonical_bytes, base64), pass the decoded "
                       "bytes with --canonical-bytes <file>; this verifier fetches nothing")
    got = hashlib.sha256(canonical_bytes).hexdigest()
    bad = [f for f in DIGEST_FIELDS if _norm(obj.get(f)) != got]
    if bad:
        return Verdict(V.BROKEN,
                       f"sha256 of the supplied canonical bytes is {got[:16]}..., "
                       "does not match " + " or ".join(bad))
    return Verdict(V.VERIFIED,
                   f"sha256 of the supplied canonical bytes ({got[:16]}...) matches "
                   "result_sha256 and output_hash; issuer anchors and chain not checked")


def _step_digests(step: Any) -> list[str]:
    """The digest(s) a step lists: a bare hex string, or a step receipt's
    result_sha256 / output_hash (whichever are present)."""
    if isinstance(step, str):
        d = _norm(step)
        return [d] if d else []
    if isinstance(step, dict):
        return [d for d in (_norm(step.get(f)) for f in DIGEST_FIELDS) if d]
    return []


def _step_name(i: int, step: Any) -> str:
    rid = receipt_id(step) if isinstance(step, dict) else None
    return f"step {i + 1}" + (f" ({rid})" if rid else "")


def merkle_root(digests: list[str]) -> str:
    """Our assumed Section 8 construction (see module docstring)."""
    level = [bytes.fromhex(d) for d in digests]
    if not level:
        raise ValueError("no leaves")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def verify_workflow(obj: dict, step_bytes: "list[bytes] | None") -> Verdict:
    steps = obj.get("steps") or []
    rid = receipt_id(obj)
    if not steps:
        return Verdict(V.COULD_NOT_LOOK, "workflow receipt lists no steps")
    if step_bytes is None:
        return Verdict(V.COULD_NOT_LOOK,
                       f"workflow receipt{' ' + rid if rid else ''} has {len(steps)} step(s); "
                       "no canonical bytes supplied, pass one --canonical-bytes <file> per "
                       "step, in order; this verifier fetches nothing")
    if len(step_bytes) != len(steps):
        return Verdict(V.COULD_NOT_LOOK,
                       f"workflow receipt has {len(steps)} step(s) but {len(step_bytes)} "
                       "canonical-bytes file(s) were supplied")
    leaves = []
    for i, (step, data) in enumerate(zip(steps, step_bytes)):
        ds = _step_digests(step)
        if not ds:
            return Verdict(V.COULD_NOT_LOOK, f"{_step_name(i, step)} lists no digest")
        got = hashlib.sha256(data).hexdigest()
        if any(d != got for d in ds):
            return Verdict(V.BROKEN,
                           f"{_step_name(i, step)}: sha256 of its supplied canonical bytes "
                           f"is {got[:16]}..., does not match the step's listed digest")
        leaves.append(ds[0])
    want = _norm(obj.get("merkle_root"))
    try:
        root = merkle_root(leaves)
    except ValueError:
        return Verdict(V.COULD_NOT_LOOK, "a step digest is not sha256 hex; " + UNCONFIRMED)
    if want != root:
        return Verdict(V.COULD_NOT_LOOK,
                       f"all {len(steps)} step digests match their bytes; merkle_root does "
                       f"not match our recomputed root {root[:16]}...; " + UNCONFIRMED)
    return Verdict(V.VERIFIED,
                   f"all {len(steps)} step digests match their bytes and merkle_root "
                   f"({root[:16]}...) matches, under our assumed construction (leaves in "
                   "listed order, sha256 of concatenated raw digests, odd leaf duplicated); "
                   "output hash, goal binding, issuer anchors and chain not checked")
