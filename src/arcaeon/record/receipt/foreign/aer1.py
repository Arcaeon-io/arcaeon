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


def detect(obj: Any) -> bool:
    """True for a JSON object carrying result_sha256 and output_hash and no
    Arcaeon receipt_version."""
    if not isinstance(obj, dict):
        return False
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
