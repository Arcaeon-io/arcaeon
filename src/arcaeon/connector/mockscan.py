# SPDX-License-Identifier: MIT
"""arcaeon.connector.mockscan: a FAKE vendor, so the adapter shape has something to read.

"mockscan" is not a product. It stands in for any scanner that hands back a verdict
as JSON. Its format:

    {
      "scanner": "mockscan",
      "scan_id": "ms-0001",
      "result":  "pass" | "fail" | "error" | "unknown" | "skipped",
      "target":  {"name": "report.pdf", "sha256": "<64 hex>"},
      "signature": {"alg": "ed25519", "keyid": "mockscan-2026", "sig": "<base64>"}
    }

`target` and `signature` are optional. The table below is the whole mapping; any
other word, a missing `result`, or a payload that also carries a second verdict
field (`verdict`, `status`, `results`) reads COULD NOT LOOK.
"""
from __future__ import annotations

from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

from .core import AdapterError, Extracted, VendorAdapter, register

__all__ = ["MockScanAdapter", "MOCKSCAN", "TABLE"]

TABLE = {
    "pass": VERIFIED,
    "fail": BROKEN,
    "error": COULD_NOT_LOOK,
    "unknown": COULD_NOT_LOOK,
    "skipped": COULD_NOT_LOOK,
}

_RIVAL_FIELDS = ("verdict", "status", "results")


class MockScanAdapter(VendorAdapter):
    name = "mockscan"
    version = "1"
    table = TABLE

    def extract(self, doc: dict) -> Extracted:
        if doc.get("scanner") != "mockscan":
            raise AdapterError("not a mockscan payload (scanner field is not 'mockscan')")
        if "result" not in doc:
            raise AdapterError("mockscan payload has no result field")
        rivals = [k for k in _RIVAL_FIELDS if k in doc]
        if rivals:
            raise AdapterError(f"ambiguous: result and {rivals} both present")
        target = doc.get("target")
        if target is not None and not isinstance(target, dict):
            raise AdapterError("mockscan target is not an object")
        target = target or {}
        return Extracted(word=doc["result"], vendor_id=doc.get("scan_id"),
                         subject_name=target.get("name"), subject_sha256=target.get("sha256"),
                         attestation=doc.get("signature"))


MOCKSCAN = register(MockScanAdapter())
