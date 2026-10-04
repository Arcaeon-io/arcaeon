# SPDX-License-Identifier: MIT
"""arcaeon.connector.core: a vendor's verdict JSON becomes one RELAYED chain row.

THE ROW (kind "check.verdict.relayed"), every key always present:

    kind                 "check.verdict.relayed"
    relayed              True. Always. This row carries someone else's verdict.
    checked_by_us        False. Always. We did not re-judge the bytes they judged.
    vendor               {"name", "adapter_version"}: whose verdict, read by which table
    vendor_id            the vendor's own id for the check (request id, scan id), or None
    vendor_word          the vendor's verdict word exactly as they wrote it, or None
    relayed_verdict      their word in OUR words: VERIFIED, BROKEN or COULD NOT LOOK
    mapping              {"rule"}: "table" (the word is in the adapter's table),
                         "unknown_word", "not_a_word", or "not_read" (the payload
                         itself could not be read)
    subject              {"name", "sha256"} the vendor says it checked, or None
    attestation          {"status", "checked_by_us", "claimed"}: the vendor's OWN
                         claim of a signature. status is "CLAIMED" or "NONE";
                         checked_by_us is False. Phase 1 never checks a vendor
                         signature, so it never says one is valid.
    vendor_payload_digest  "sha256:raw-bytes:v1:<hex>" over the bytes exactly as received
    vendor_payload_bytes   their length
    received_at          our clock when we received it (ISO 8601 UTC)

and, when it applies:

    vendor_payload       the payload verbatim (keep_payload=True), so a re-check
                         needs nothing else
    could_not_look       {looked_for, where, reason_word, reason} (arcaeon.verdict)

There is deliberately NO bare `verdict` key. A script that greps rows for
`verdict == "VERIFIED"` must not mistake a vendor's pass for our own check.

THE RULE: a word the adapter's table does not hold, a word that is not a string,
a payload that is not JSON, too big, too deep, carries a duplicate key, or that
the adapter cannot read, all map to COULD NOT LOOK. Nothing unknown maps to
VERIFIED. import_verdict never raises on what a vendor sends.

Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from arcaeon.record.row import digest_bytes, loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

__all__ = ["ROW_KIND", "OUR_WORDS", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_STR",
           "ATTESTATION_CLAIMED", "ATTESTATION_NONE", "AdapterError", "Extracted",
           "VendorAdapter", "register", "adapter_for", "map_word", "import_verdict",
           "recheck"]

ROW_KIND = "check.verdict.relayed"
#: The only words a relayed verdict can land on.
OUR_WORDS = (VERIFIED, BROKEN, COULD_NOT_LOOK)
#: A payload over this is digested but never parsed.
MAX_PAYLOAD_BYTES = 1 << 20
#: Containers nested deeper than this are refused (a verdict is a shallow object).
MAX_DEPTH = 32
#: Any string we copy out of a payload into a row is cut to this many characters.
MAX_STR = 256

ATTESTATION_CLAIMED = "CLAIMED"
ATTESTATION_NONE = "NONE"

#: The keys a re-check recomputes and compares. received_at is ours, not theirs,
#: and ts / chain are the ledger's.
_RECOMPUTED = ("kind", "vendor", "vendor_id", "vendor_word", "relayed_verdict", "mapping",
               "subject", "attestation", "vendor_payload_digest", "vendor_payload_bytes")


class AdapterError(ValueError):
    """The payload parsed as JSON but is not this vendor's shape. Read as COULD NOT LOOK."""


@dataclass
class Extracted:
    """What an adapter reads out of one vendor payload. Strings are cut by the caller."""
    word: Any                       # the vendor's verdict word, as found (may not be a str)
    vendor_id: Any = None           # their request / scan id
    subject_name: Any = None        # what they say they checked
    subject_sha256: Any = None      # its sha256 hex, if they gave one
    attestation: dict | None = None  # their own signature claim, fields as they wrote them
    notes: list = field(default_factory=list)


class VendorAdapter:
    """One vendor's format. Subclass, set `name`, `version`, `table`, write `extract`.

    `table` maps the vendor's verdict words (written casefolded) to one of
    OUR_WORDS. A table that maps anywhere else, or holds two keys that fold to
    the same word, is refused when the adapter is built: an adapter bug must not
    be able to mint a word we do not speak.
    """
    name: str = ""
    version: str = "1"
    table: dict = {}

    def __init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise TypeError("a VendorAdapter needs a non-empty name")
        folded = {}
        for k, v in self.table.items():
            if not isinstance(k, str) or k != k.strip().casefold():
                raise TypeError(f"{self.name}: table key {k!r} must be a casefolded, stripped str")
            if v not in OUR_WORDS:
                raise TypeError(f"{self.name}: table maps {k!r} to {v!r}; "
                                f"only {OUR_WORDS} are allowed")
            if k in folded:
                raise TypeError(f"{self.name}: table key {k!r} appears twice")
            folded[k] = v
        self.table = dict(folded)

    def extract(self, doc: dict) -> Extracted:  # pragma: no cover - abstract
        raise NotImplementedError


_ADAPTERS: dict[str, VendorAdapter] = {}


def register(adapter: VendorAdapter) -> VendorAdapter:
    """Make an adapter findable by its name (recheck uses this)."""
    _ADAPTERS[adapter.name] = adapter
    return adapter


def adapter_for(name: str) -> VendorAdapter | None:
    """The registered adapter for a vendor name, or None. The built-in mock registers lazily."""
    if not isinstance(name, str):
        return None
    if name not in _ADAPTERS:
        from . import mockscan  # noqa: F401  (registers itself)
    return _ADAPTERS.get(name)


def map_word(adapter: VendorAdapter, word: Any) -> tuple[str, str]:
    """(our word, rule). Only an exact table hit (after strip + casefold) can be
    anything but COULD NOT LOOK."""
    if not isinstance(word, str):
        return COULD_NOT_LOOK, "not_a_word"
    hit = adapter.table.get(word.strip().casefold())
    if hit is None:
        return COULD_NOT_LOOK, "unknown_word"
    return hit, "table"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_str(v: Any) -> str | None:
    """A string fit for a chain row and for JCS: lone surrogates escaped, cut to MAX_STR.
    Non-strings become None (we do not stringify what the vendor did not write as text)."""
    if not isinstance(v, str):
        return None
    return v.encode("utf-8", "backslashreplace").decode("utf-8")[:MAX_STR]


def _sha256_hex(v: Any) -> str | None:
    if isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v.lower()):
        return v.lower()
    return None


def _too_deep(doc: Any, limit: int) -> bool:
    """Iterative: no recursion on hostile input."""
    stack = [(doc, 1)]
    while stack:
        node, d = stack.pop()
        if isinstance(node, dict):
            kids = node.values()
        elif isinstance(node, list):
            kids = node
        else:
            continue
        if d > limit:
            return True
        stack.extend((k, d + 1) for k in kids)
    return False


def _attestation(claim: Any) -> dict:
    if claim is None:
        return {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
    if not isinstance(claim, dict):
        return {"status": ATTESTATION_CLAIMED, "checked_by_us": False,
                "claimed": {"unreadable": True}}
    out = {}
    for k in sorted(claim)[:8]:
        v = claim[k]
        key = _safe_str(k)
        if key is None:
            continue
        s = _safe_str(v)
        if isinstance(v, str) and len(v) > 64:
            # a signature blob is kept by digest, never verbatim and never "checked"
            out[key + "_digest"] = digest_bytes(v.encode("utf-8", "surrogatepass"))
        else:
            out[key] = s
    return {"status": ATTESTATION_CLAIMED, "checked_by_us": False, "claimed": out}


def _base(adapter: Any, received_at: str | None) -> dict:
    name = getattr(adapter, "name", None)
    return {
        "kind": ROW_KIND,
        "relayed": True,
        "checked_by_us": False,
        "vendor": {"name": _safe_str(name), "adapter_version": _safe_str(getattr(adapter, "version", None))},
        "vendor_id": None,
        "vendor_word": None,
        "relayed_verdict": COULD_NOT_LOOK,
        "mapping": {"rule": "not_read"},
        "subject": None,
        "attestation": _attestation(None),
        "vendor_payload_digest": None,
        "vendor_payload_bytes": None,
        "received_at": received_at if isinstance(received_at, str) else _now_iso(),
    }


def _cnl(row: dict, looked_for: str, reason_word: str, reason: str) -> dict:
    row["relayed_verdict"] = COULD_NOT_LOOK
    row["could_not_look"] = could_not_look(looked_for, "vendor payload", reason_word, reason)
    return row


def import_verdict(adapter: VendorAdapter, raw: Any, *, received_at: str | None = None,
                   keep_payload: bool = False) -> dict:
    """One vendor payload (the bytes as received) -> one relayed row (a dict, not yet
    appended; hand it to Ledger.append). Never raises on the payload's content."""
    row = _base(adapter, received_at)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if not isinstance(raw, (bytes, bytearray)):
        return _cnl(row, "vendor payload bytes", "unreadable",
                    f"payload is a {type(raw).__name__}, not bytes")
    raw = bytes(raw)
    row["vendor_payload_digest"] = digest_bytes(raw)
    row["vendor_payload_bytes"] = len(raw)
    if not isinstance(adapter, VendorAdapter):
        return _cnl(row, "an adapter", "missing", "no VendorAdapter was given")
    if not raw:
        return _cnl(row, "vendor verdict JSON", "empty", "the payload is empty")
    if len(raw) > MAX_PAYLOAD_BYTES:
        return _cnl(row, "vendor verdict JSON", "unreadable",
                    f"payload is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte parse limit; "
                    f"digested, not read")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _cnl(row, "vendor verdict JSON", "unreadable", "payload is not UTF-8")
    if keep_payload:
        row["vendor_payload"] = text
    try:
        doc = loads_strict(text)
    except ValueError as e:  # includes duplicate keys and too-deep nesting
        return _cnl(row, "vendor verdict JSON", "unreadable",
                    f"payload is not one unambiguous JSON value: {type(e).__name__}")
    if _too_deep(doc, MAX_DEPTH):
        return _cnl(row, "vendor verdict JSON", "unreadable",
                    f"payload nests deeper than {MAX_DEPTH}")
    if not isinstance(doc, dict):
        return _cnl(row, "vendor verdict object", "unreadable",
                    f"payload is a JSON {type(doc).__name__}, not an object")
    try:
        ex = adapter.extract(doc)
        if not isinstance(ex, Extracted):
            raise AdapterError(f"adapter returned {type(ex).__name__}, not Extracted")
    except AdapterError as e:
        return _cnl(row, f"a {adapter.name} verdict", "name_not_found", _safe_str(str(e)) or "")
    except Exception as e:  # a buggy adapter is a could-not-look, never a traceback
        return _cnl(row, f"a {adapter.name} verdict", "unreadable",
                    f"the adapter failed: {type(e).__name__}")
    row["vendor_id"] = _safe_str(ex.vendor_id)
    row["vendor_word"] = _safe_str(ex.word)
    sname, ssha = _safe_str(ex.subject_name), _sha256_hex(ex.subject_sha256)
    row["subject"] = {"name": sname, "sha256": ssha} if (sname or ssha) else None
    row["attestation"] = _attestation(ex.attestation)
    word, rule = map_word(adapter, ex.word)
    row["mapping"] = {"rule": rule}
    row["relayed_verdict"] = word
    if rule != "table":
        row["could_not_look"] = could_not_look(
            "a verdict word this adapter's table holds", "vendor payload", "name_not_found",
            f"vendor word {row['vendor_word']!r} is not in the {adapter.name} table" if rule == "unknown_word"
            else "the vendor verdict is not a word")
    return row


def _result(verdict: str, summary: str, row: Any = None, **extra) -> dict:
    rv = row.get("relayed_verdict") if isinstance(row, dict) else None
    out = {"verdict": verdict, "relayed_verdict": rv, "reason": summary,
           "what_was_checked": "that the vendor payload is the bytes we received and the row "
                               "says what the adapter reads in it; NOT the vendor's own verdict"}
    out.update(extra)
    return out


def recheck(row: Any, payload: Any = None, *, adapter: VendorAdapter | None = None) -> dict:
    """Re-check a relayed row against the vendor payload.

    VERIFIED: the payload's digest matches and re-importing it gives the same row.
    BROKEN: the digest does not match (payload or row edited after import), the row
    no longer says it is relayed, or a recomputed field differs (named in `fields`).
    COULD NOT LOOK: no payload to check against, no adapter for the vendor, an
    adapter version that is not the one the row was read with, or not a relayed row.

    `payload` is the vendor bytes you kept; if None, the row's own `vendor_payload`
    is used (keep_payload=True at import). Never raises.
    """
    if not isinstance(row, dict) or row.get("kind") != ROW_KIND:
        return _result(COULD_NOT_LOOK, "not a relayed verdict row", row,
                       **could_not_look("a check.verdict.relayed row", "row", "name_not_found",
                                        "the row is not a relayed verdict row"))
    if row.get("relayed") is not True or row.get("checked_by_us") is not False:
        return _result(BROKEN, "the row no longer says it is a relayed verdict", row,
                       fields=["relayed", "checked_by_us"])
    if payload is None:
        payload = row.get("vendor_payload")
    if isinstance(payload, str):
        payload = payload.encode("utf-8", "surrogatepass")
    if not isinstance(payload, (bytes, bytearray)):
        return _result(COULD_NOT_LOOK, "no vendor payload to check against", row,
                       **could_not_look("the vendor payload bytes", "argument or row", "missing",
                                        "no payload was given and the row keeps none"))
    stored = row.get("vendor_payload_digest")
    if not isinstance(stored, str):
        return _result(BROKEN, "the row carries no payload digest", row,
                       fields=["vendor_payload_digest"])
    if digest_bytes(bytes(payload)) != stored:
        return _result(BROKEN, "the vendor payload does not match the digest in the row", row,
                       fields=["vendor_payload_digest"])
    vendor = row.get("vendor") if isinstance(row.get("vendor"), dict) else {}
    ad = adapter if adapter is not None else adapter_for(vendor.get("name"))
    if not isinstance(ad, VendorAdapter) or ad.name != vendor.get("name"):
        return _result(COULD_NOT_LOOK, "no adapter for this vendor", row,
                       **could_not_look(f"an adapter for {vendor.get('name')!r}", "registry",
                                        "missing", "no adapter by the row's vendor name"))
    if ad.version != vendor.get("adapter_version"):
        return _result(COULD_NOT_LOOK, "the adapter version differs from the one the row was read with",
                       row, **could_not_look(f"adapter version {vendor.get('adapter_version')!r}",
                                             "registry", "missing",
                                             f"only version {ad.version!r} is installed"))
    again = import_verdict(ad, bytes(payload), received_at=row.get("received_at"))
    diff = [k for k in _RECOMPUTED if again.get(k) != row.get(k)]
    if diff:
        return _result(BROKEN, "the row differs from what the payload says", row, fields=diff)
    return _result(VERIFIED, "payload digest matches and the row re-reads the same", row)
