"""arcaeon-audit — tamper-evident audit logs for AI agents.

The EU AI Act (Article 12) requires providers of high-risk AI systems to keep
automatic records of events over the system's lifetime and to be able to produce
them. **It does not require tamper-evidence** — that word is not in it, and this
package will not tell you otherwise. The reason to want integrity anyway is
evidentiary, not statutory: when a record is challenged (DORA reconstructibility,
the revised Product Liability Directive's presumption where evidence in your
control is not produced, an auditor, a dispute), "we logged it" is a self-report.
Observability tools show you what your agent did; they do not let you show the
record was not altered after the fact.

`arcaeon-audit` is the thin, boring, correct layer that does. Every agent action
is appended to a hash-chained log (via arcaeon-ledger): edit, delete, or reorder
any past record and every later link breaks and verification names the exact row.
Then `export_bundle()` produces a regulator-legible folder — the records, an
integrity report, and a manifest mapping to Article 12's requirements — so
"prove what your agent did" is one function call.

    from arcaeon.prove.audit import AuditLog
    log = AuditLog("agent-audit.jsonl", system_id="triage-agent-v3",
                   provider="Acme AI")
    log.record(
        event="tool_call", agent="triage-agent-v3",
        inputs={"patient_msg": "chest pain"},
        outputs={"routed_to": "ER", "priority": 1},
        decision="escalate", principal="triage-agent-v3",
    )
    assert log.verify().ok            # tamper-evident, any time
    log.export_bundle("audit-export/")  # regulator-ready folder

Zero heavy deps (arcaeon-ledger is stdlib-only). One JSONL file. MIT.

NOTE: this is an engineering control that produces tamper-evident, exportable
records. It is not legal advice and does not by itself make a system compliant;
Article 12 compliance depends on WHAT you log and your broader obligations.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from arcaeon.record.ledger import Ledger, verify_file, authority
from arcaeon.record.row import RESERVED_KEYS
from arcaeon.verdict import VERIFIED, BROKEN, COULD_NOT_LOOK
from arcaeon.record.ledger.witness import (
    WitnessStore, publish_head, verify_against_witness,
)

__version__ = "0.1.8"
__all__ = ["AuditLog", "verify_file", "export_bundle", "witness_nature_of",
           "FINDING_WORD", "word_for_finding", "finding_of"]

# Bundle schema version. v1 (implicit, <=0.1.3) had no witness-NATURE fields in
# integrity.json's `witness` block — only the verification verdict, or None. v2
# adds `kind` / `identifier` / `independence` / `independence_source` / `note`
# so a regulator can judge
# whether the witness was independent. Additive: old readers ignore the new keys,
# and `witness_nature_of()` reads old bundles back as `kind: unknown`.
BUNDLE_SCHEMA_VERSION = 2

# The event categories Article 12 / high-risk-AI recordkeeping care about. Not
# exhaustive law — a practical vocabulary so exported logs are legible to an auditor.
EVENT_TYPES = (
    "system_start", "system_stop",      # periods of use (Art.12(2)(a))
    "input", "reference_check",          # input data / reference DB (Art.12(2)(c),(b))
    "tool_call", "decision", "output",   # the agent acting
    "human_review", "override",          # human oversight actions
    "error", "flag",                     # anomalies worth a record
)


# Keys the audit log stamps itself. A record whose AUTHOR chose its timestamp is
# a self-report wearing a chain; the whole product is the difference between
# those two things. Refused at record() rather than silently overwritten.
# `authority` and `chain` are stamped one layer down, by the ledger (0.1.8):
# a caller's `authority=` was silently REPLACED by the block record() builds
# and a caller's `chain=` silently POPPED -- the same quiet-drop this set
# exists to refuse, just two keys further along.
_RESERVED_ROW_KEYS = RESERVED_KEYS | {"system_id"}  # the row format's own keys + audit's


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AuditLog:
    """A tamper-evident, append-only audit log for one AI system's actions.

    Optionally bound to an external WITNESS (`witness` + `witness_namespace`).
    A hash chain proves a log was not edited or reordered, but it provably
    CANNOT prove it was not truncated — drop the last N rows and the prefix
    still chains clean. A witness is an outside record of the log's head; pin to
    it on a cadence with `pin_to_witness()`, and `export_bundle()` will then
    cross-check the export against it and refuse to stamp a truncated log PASS.
    """
    path: str | Path
    system_id: str
    provider: str = ""
    witness: Any = None            # a WitnessStore, a path to one, or None
    witness_namespace: str | None = None
    _ledger: Ledger = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._ledger = Ledger(self.path)

    def pin_to_witness(self, witness: Any = None,
                       namespace: str | None = None,
                       *, received_at: str | None = None) -> dict:
        """Record this log's CURRENT head with an external witness.

        Call on a cadence (the MAX gap between pins is your real security
        parameter — an attacker picks the gap). Uses the AuditLog's configured
        witness/namespace unless overridden here. Returns the stored pin.
        """
        store = _resolve_witness(witness if witness is not None else self.witness)
        ns = namespace or self.witness_namespace
        if store is None or not ns:
            raise ValueError("pin_to_witness needs a witness and a namespace "
                             "(set them on the AuditLog or pass them here)")
        return publish_head(store, ns, self._ledger, received_at=received_at)

    def record(self, *, event: str, agent: str,
               inputs: Any = None, outputs: Any = None,
               decision: str | None = None,
               principal: str | None = None,
               capability_version: str | None = None,
               time_source: str = "local",
               **extra: Any) -> str:
        """Append one audit record. Returns its chain hash.

        `event` should be one of EVENT_TYPES (not enforced — unknown types are
        allowed but flagged in the export so nothing is silently miscategorized).
        `principal` (defaults to `agent`) + `capability_version` bind WHO acted
        with what authority, so "was this edited?" becomes "was this edited AND
        was the writer authorized?"

        `**extra` carries arbitrary domain fields onto the record and they are
        chained like everything else — EXCEPT `ts`, `system_id`, `authority`
        and `chain`, which this log (or the ledger under it) stamps itself and
        REFUSES from the caller (ValueError). A record whose author picked its
        own timestamp is a self-report wearing a chain, which is the exact
        thing this package exists to distinguish. If you have a domain field by
        one of those names, pass it as e.g. `ts_value`.
        """
        row: dict[str, Any] = {
            "ts": _now_iso(),
            "system_id": self.system_id,
            "event": event,
            "agent": agent,
        }
        if inputs is not None:
            row["inputs"] = inputs
        if outputs is not None:
            row["outputs"] = outputs
        if decision is not None:
            row["decision"] = decision
        # RESERVED STAMPS ARE NOT CALLER-WRITABLE (pre-invite audit 2026-08-23).
        # `row.update(extra)` ran AFTER the stamps above, so **extra could
        # overwrite `ts` and `system_id`. A backdated timestamp and a forged
        # system id then CHAINED GREEN — the chain faithfully seals whatever it
        # is handed — and manifest.json reported the forged range as
        # `period_covered`, against a summary that says records are "appended
        # automatically at the time it happens". The integrity layer was telling
        # the truth about bytes the caller had already lied in.
        # It also broke by ACCIDENT: any caller with a domain field named `ts`
        # silently corrupted the audit clock.
        # Reserved keys are refused loudly rather than dropped silently — a
        # dropped field is its own quiet surprise.
        collisions = _RESERVED_ROW_KEYS & set(extra)
        if collisions:
            raise ValueError(
                "these keys are stamped by the audit log and cannot be supplied "
                f"by the caller: {sorted(collisions)}. The timestamp and system "
                "id are the two things an audit record must not let its author "
                "choose. Pass domain data under a different name (e.g. "
                f"{sorted(collisions)[0]}_value) — it will be chained just the same."
            )
        row.update(extra)
        auth = authority(principal or agent,
                         capability_version=capability_version,
                         time_source=time_source)
        return self._ledger.append(row, authority=auth)

    def verify(self):
        """Tamper-evidence check over the whole log. Returns ledger.VerifyResult."""
        return self._ledger.verify()

    def __iter__(self):
        return iter(self._ledger)

    def export_bundle(self, out_dir: str | Path, *,
                      witness: Any = None,
                      witness_namespace: str | None = None,
                      instrument_notes: str | None = None) -> Path:
        """Produce a regulator-ready export folder. Returns its path.

        Contents:
          - records.jsonl        the full hash-chained audit log (verbatim)
          - integrity.json       verdict (word) + finding: chain_ok, truncation_checked/ok, breaks
          - manifest.json        system id, provider, period covered, counts by event
          - ARTICLE_12_SUMMARY.md human-readable mapping to Art.12 requirements
          - witness.json         the external-witness pin + truncation verdict
                                 (only when a witness is consulted)
          - INSTRUMENT_NOTES.md  the author's own account of this check's known
                                 false positives, false negatives, and what was
                                 not exercised — verbatim, unvalidated (only
                                 when `instrument_notes` is supplied)
        The whole bundle is self-verifying: anyone can re-run verification on
        records.jsonl with arcaeon-ledger and reproduce integrity.json. If a
        witness is configured (here or on the AuditLog), the export also
        cross-checks for truncation — the one failure a chain cannot see alone.
        """
        return export_bundle(
            self.path, out_dir, system_id=self.system_id, provider=self.provider,
            witness=witness if witness is not None else self.witness,
            witness_namespace=witness_namespace or self.witness_namespace,
            instrument_notes=instrument_notes)


def _read_rows(raw: bytes) -> tuple[list[dict], int]:
    """Parse a log's bytes into rows, TOLERANTLY. Returns (rows, unreadable).

    A damaged log is the one you most need to export — that is the whole point
    of handing a regulator an integrity report. Through 0.1.1 this was a bare
    `json.loads` per line inside a `read_text()`, so an unparseable line, a
    non-UTF8 byte, or a bare scalar line raised out of `export_bundle` and no
    bundle was produced at all. Now: undecodable and unparseable lines are
    counted, not fatal; the integrity report names the break either way.

    Decodes the way the ledger's `verify_file` does (utf-8, errors="replace")
    so this reader and that one count the SAME lines (0.1.8): a strict decode
    here made a row with one bad byte "unreadable" for the manifest while
    verify_file parsed it (U+FFFD in place) and counted it as a row, so one
    bundle said `rows: 3` in integrity.json and `record_count: 2` in
    manifest.json. RecursionError is caught alongside ValueError because
    json.loads raises it, not ValueError, on a pathologically nested line.
    """
    rows: list[dict] = []
    unreadable = 0
    for line in raw.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            unreadable += 1
            continue
        if not isinstance(obj, dict):
            unreadable += 1
            continue
        rows.append(obj)
    return rows, unreadable


def _summ(rows: list[dict]) -> dict:
    counts: dict[str, int] = {}
    first_ts = last_ts = None
    unknown: set[str] = set()
    for r in rows:
        ev = r.get("event", "?")
        if not isinstance(ev, str):
            ev = str(ev)
        counts[ev] = counts.get(ev, 0) + 1
        if ev not in EVENT_TYPES:
            unknown.add(ev)
        ts = r.get("ts")
        if isinstance(ts, str) and ts:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
    return {"counts": counts, "first_ts": first_ts, "last_ts": last_ts,
            "unknown_event_types": sorted(unknown)}


def _resolve_witness(witness: Any):
    """Coerce a witness argument to a store object, or None.

    Accepts None, a path/str (wrapped in the reference WitnessStore), or any
    object exposing `.latest(namespace)` (the reference store, or a client
    wrapper over a hosted witness endpoint). Returns the store or None.
    """
    if witness is None:
        return None
    if isinstance(witness, (str, Path)):
        return WitnessStore(witness)
    return witness


# ---- witness NATURE: what a regulator needs to judge INDEPENDENCE -----------
# A witness only proves the log wasn't truncated if it is controlled OUTSIDE the
# log-writer's reach. A local JSONL sitting next to the log is not — the party who
# can truncate the log can re-pin the witness (the forgeable case in the scrutiny
# audit). integrity.json therefore surfaces the witness's KIND and an honest
# `independence` label; a self-controlled witness is labelled as such, never
# dressed up as independent. This does NOT change the truncation verdict — it lets
# a regulator SEE the independence question the verdict cannot answer for them.
_NOTE_LOCAL_FILE = (
    "This witness is a local file, in the same control domain as whoever can write "
    "the log, so it is NOT independent: a party able to truncate or rewrite the log "
    "can also rewrite this witness. A PASS backed by it is SELF-ASSERTED, not "
    "externally verified. Real independence requires a witness outside the "
    "log-writer's control — a remote notary endpoint or a public timestamp anchor.")
_NOTE_REMOTE_URL = (
    "This witness is a remote endpoint a regulator can query independently of the "
    "log-writer; 'externally_verifiable' means a third party can fetch and re-check "
    "the pin. Genuine independence still requires that the endpoint itself is "
    "outside the log-writer's control.")
_NOTE_OTS = (
    "This witness is an OpenTimestamps anchor committed to a public blockchain; the "
    "pin is externally_verifiable by anyone against the public chain, independently "
    "of the log-writer.")
_NOTE_NONE = (
    "No external witness was consulted, so truncation was not checked and "
    "completeness is not witnessed; independence does not apply.")
_NOTE_UNDECLARED = (
    "The witness object did not declare its kind and is not the reference local-file "
    "store; independence is reported as self_asserted (the conservative default, "
    "claiming no independence we cannot establish) until the witness declares itself "
    "externally verifiable via a witness_descriptor().")
_NOTE_LEGACY = (
    "This bundle predates witness-nature reporting (bundle schema < 2); the "
    "witness's kind and independence cannot be determined from it.")

# What a witness_descriptor() may say about itself. `local_file` and `none` are
# established by this tool, never declared; every other string is not a kind.
_DECLARABLE_KINDS = frozenset({"remote_url", "opentimestamps"})
_DECLARABLE_INDEPENDENCE = frozenset({"self_asserted", "externally_verifiable"})


# The public, no-auth read surface of the hosted witness. Its pin store is a
# PUBLIC GitHub repository, so a third party can reach the pin without a
# credential and without asking us for anything.
PUBLIC_WITNESS_BASE = "https://witness.arcaeon.io"


def _verify_query(ns: Any, rows: Any, chain: Any) -> str:
    """The `?ns=&rows=&chain=` query for the public witness, PERCENT-ENCODED.

    The three values are chosen by the audited party (the namespace) or read
    from a pin file (rows, chain), and the bundle hands them to a regulator
    inside a single-quoted `curl` command to paste into a shell. Interpolated
    raw (through 0.1.7), a namespace of `acme'; rm -rf ~; echo '` closed the
    quote and put an arbitrary command in the regulator's terminal, and a
    namespace with `&` or `#` silently rewrote the query. Encoding everything
    (safe="" so `/` is encoded too) leaves only unreserved characters and `%`
    in the string, none of which a POSIX single-quoted string or a URL query
    can misread.
    """
    return "?" + "&".join(f"{k}={quote(str(v), safe='')}"
                          for k, v in (("ns", ns), ("rows", rows), ("chain", chain)))


def _reverify_recipe(witness_block: dict, namespace: str | None) -> dict:
    """How a STRANGER re-checks this bundle without trusting whoever made it.

    The old recipe was one line: pip install arcaeon-ledger, run verify_file on
    records.jsonl. That is a real check and it is NOT independent verification —
    it re-runs OUR tool over bytes WE handed the reader, and it can only speak to
    the chain. Completeness rides on witness.json, which is a copy the log's own
    owner generated. Nothing pointed the reader at a source outside our control.

    We had already built and deployed the thing that fixes it (a public, no-auth
    GET against a witness whose pin store is a public git repo) and referenced it
    nowhere in the bundle. This is that string change (pre-invite audit finding
    C6, 2026-08-23): the difference between "re-run our tool on our bytes" and
    "fetch the pin from a source we do not control and compare it yourself."
    """
    recipe: dict = {
        "step_1_chain": {
            "what_it_proves": "no record in this file was edited, reordered, or "
                              "removed from the MIDDLE. It cannot see truncation "
                              "of the tail, and it is not independent of us.",
            "run": "pip install 'arcaeon-ledger>=0.5.9'; python -c \"from "
                   "arcaeon_ledger import verify_file; "
                   "r = verify_file('records.jsonl'); print(r); "
                   "raise SystemExit(0 if r.ok else 1)\"",
            "note": "branch on r.ok — it is TRI-STATE. True = verified, False = "
                    "broken, None = the chain could not speak for these rows "
                    "(not a pass). Printing it is not checking it.",
        },
    }
    ns = namespace or witness_block.get("namespace")
    rows = witness_block.get("witness_rows")
    chain = witness_block.get("witness_chain")
    if ns and rows is not None and chain:
        q = _verify_query(ns, rows, chain)
        recipe["step_2_completeness_INDEPENDENT"] = {
            "what_it_proves": "the head this bundle claims was witnessed is the "
                              "head the PUBLIC witness holds — fetched from a "
                              "source the log's owner does not control. This is "
                              "the step that does not require trusting us.",
            "run": f"curl -s '{PUBLIC_WITNESS_BASE}/api/verify{q}'",
            "read": "witnessed / is_current_head / raw_record_url. Then open "
                    "raw_record_url yourself: it is a file in a PUBLIC git "
                    "repository, and its commit history is linked as `history`.",
            "no_credential_required": True,
            "only_resolves_if": "this namespace was pinned to the public hosted "
                                "witness. A privately-held witness will not "
                                "appear here, and that absence is information: it "
                                "means completeness rests on a record you cannot "
                                "independently reach.",
        }
    else:
        recipe["step_2_completeness_INDEPENDENT"] = {
            "unavailable": "no witness namespace/head is recorded in this bundle, "
                           "so there is nothing for a third party to fetch. "
                           "Completeness was NOT independently established.",
        }
    recipe["what_none_of_this_proves"] = (
        "that the log is COMPLETE in the sense of containing everything that "
        "happened. The agent holds the pen; anything never written is not "
        "recoverable from these files by any check.")
    return recipe


def _witness_nature(store: Any) -> dict:
    """Classify a witness's KIND + INDEPENDENCE for the bundle. Honest by default.

    Returns {kind, identifier, independence, independence_source, note}.
    `independence_source` says WHO decided the independence label —
    established_by_type / self_declared_by_witness / conservative_default /
    no_witness — because the label alone cannot tell a regulator whether the
    audited party wrote it. A witness may self-declare via
    a `witness_descriptor()` method returning that shape (how a hosted/OTS client
    advertises `externally_verifiable`); otherwise the reference `WitnessStore` is
    a local file (`self_asserted`), and anything else is treated conservatively —
    we never claim an independence we cannot establish.
    """
    if store is None:
        return {"kind": "none", "identifier": None,
                "independence": "none",
                "independence_source": "no_witness",
                "note": _NOTE_NONE}
    # ORDER IS THE FIX (pre-invite audit 2026-08-23, C4). This isinstance check
    # used to sit AFTER the descriptor branch, so it was reachable only by a store
    # that declined to describe itself. A local file that also implements
    # witness_descriptor() could therefore call itself externally_verifiable, and
    # the one honest label in the function was unreachable for anything motivated
    # to avoid it. What we can ESTABLISH outranks what the object CLAIMS.
    if isinstance(store, WitnessStore):
        return {"kind": "local_file", "identifier": str(store.path),
                "independence": "self_asserted",
                "independence_source": "established_by_type",
                "note": _NOTE_LOCAL_FILE}
    describe = getattr(store, "witness_descriptor", None)
    if callable(describe):
        try:
            d = describe() or {}
        except Exception:
            d = {}
        # ALLOWLISTED VOCABULARY (0.1.8). Both `kind` and `independence` were
        # copied out of the auditee's dict verbatim, so a descriptor could put
        # any string it liked into the two fields a regulator weighs a PASS on:
        # independence "CERTIFIED_BY_REGULATOR" shipped as-is, and kind "none"
        # made the summary omit the independence paragraph entirely (it skips
        # kind none because that means no witness). A witness may declare only
        # the kinds and labels this bundle documents; anything else is the
        # conservative default, as if it had said nothing.
        if isinstance(d, dict) and d.get("kind") in _DECLARABLE_KINDS:
            # DEFAULT TO THE WEAKEST, NOT THE STRONGEST. This defaulted to
            # `externally_verifiable`, so a four-line shim wrapping a local file in
            # the log owner's own directory — omitting `independence` entirely —
            # earned the single strongest label in the bundle. `independence` is
            # the field a regulator uses to weigh a PASS, and it was writable by
            # the party being audited, by omission.
            claimed = d.get("independence")
            if claimed not in _DECLARABLE_INDEPENDENCE:
                claimed = None
            identifier = d.get("identifier")
            refetchable = isinstance(identifier, str) and identifier.startswith(
                ("http://", "https://", "btc:", "ots:"))
            if claimed == "externally_verifiable" and not refetchable:
                # a claim of external verifiability with nothing a third party can
                # go and fetch is not a claim we pass through
                claimed = "undeclared"
            independence = claimed or "undeclared"
            # `note` is prose a regulator reads; never let the audited object write
            # it. _NOTE_OTS in particular states a fact about the Bitcoin chain,
            # and it was emitted on the strength of a dict the auditee supplied.
            note = (_NOTE_OTS if d.get("kind") == "opentimestamps"
                    else _NOTE_REMOTE_URL)
            if independence != "self_asserted":
                note = ("SELF-DECLARED BY THE WITNESS OBJECT, not established by "
                        "this tool — verify the identifier yourself before relying "
                        "on it. " + note)
            return {"kind": d.get("kind"),
                    "identifier": identifier,
                    "independence": independence,
                    "independence_source": "self_declared_by_witness",
                    "note": note}
    endpoint = getattr(store, "url", None) or getattr(store, "endpoint", None)
    if endpoint:
        # Having a URL attribute proves NOTHING about independence — a witness at
        # http://localhost/i-control-this has a url. externally_verifiable is granted
        # ONLY by witness_descriptor() self-declaration above; an undeclared remote
        # is reported conservatively, per this function's own docstring ("we never
        # claim an independence we cannot establish"). External audit 2026-08-23:
        # a bare object with a .url earned the full externally_verifiable label,
        # un-doing exactly what the 0.1.4 release existed to make honest.
        return {"kind": "remote_url", "identifier": str(endpoint),
                "independence": "undeclared",
                "independence_source": "conservative_default",
                "note": _NOTE_UNDECLARED}
    return {"kind": "remote_url", "identifier": None,
            "independence": "self_asserted",
            "independence_source": "conservative_default",
            "note": _NOTE_UNDECLARED}


def witness_nature_of(integrity: dict) -> dict:
    """Read the witness NATURE from a loaded integrity.json, tolerant of OLD bundles.

    New bundles (schema v2+) carry `kind`/`identifier`/`independence`/`note` under
    `witness`. Bundles from <=0.1.3 have no such fields (the `witness` value was the
    verification verdict, or None), so their witness's independence is genuinely
    unknowable from the bundle — this reports `kind: unknown` rather than guessing.
    Never raises on a missing or legacy block.
    """
    w = integrity.get("witness") if isinstance(integrity, dict) else None
    if isinstance(w, dict) and w.get("kind"):
        return w
    return {"kind": "unknown", "identifier": None,
            "independence": "unknown", "note": _NOTE_LEGACY}


#: The detailed finding -> the one Arcaeon word. It follows the export exit
#: code exactly: 0 -> VERIFIED, 1 -> BROKEN, anything else (the check could
#: not complete or was not understood) -> COULD NOT LOOK.
#: EMPTY_LOG is COULD NOT LOOK (qa-fixes 2026-09-24), matching `arcaeon verify`
#: on an empty file: nothing was recorded, so nothing was verified. It is
#: still not an accusation; its exit code moved with the word (0 -> 3).
FINDING_WORD = {
    "PASS": VERIFIED,
    "VERIFIED_MODULO_TRUNCATION": VERIFIED,
    "EMPTY_LOG": COULD_NOT_LOOK,
    "FAIL": BROKEN,
    "TRUNCATION_DETECTED": BROKEN,
    "REWRITE_DETECTED": BROKEN,
}


def word_for_finding(finding: str) -> str:
    """The `verdict` word for a detailed `finding`. Unknown -> COULD NOT LOOK."""
    return FINDING_WORD.get(finding, COULD_NOT_LOOK)


def finding_of(integrity: dict) -> str:
    """The detailed finding of an integrity.json, from either bundle shape.

    0.9.0+ bundles carry it in `finding`; bundles exported by arcaeon-audit
    0.1.x carried it in `verdict`."""
    if "finding" in integrity:
        return integrity["finding"]
    return integrity.get("verdict", "")


def export_bundle(log_path: str | Path, out_dir: str | Path, *,
                  system_id: str = "", provider: str = "",
                  witness: Any = None,
                  witness_namespace: str | None = None,
                  instrument_notes: str | None = None) -> Path:
    """Build a regulator-ready export folder from a log file. See AuditLog.export_bundle."""
    log_path = Path(log_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # records.jsonl is a BYTE-FOR-BYTE copy of the log, and integrity.json is
    # computed over that copy — not over the source. Through 0.1.1 the records
    # were re-serialized (so the bundle's bytes were not the log's, including a
    # CRLF rewrite on Windows) while the verdict was computed on the original,
    # which meant the bundle carried a verdict about a file it did not contain.
    # A regulator-facing artefact has to be self-contained: what is in the folder
    # is what was checked, and `records_sha256` pins exactly which bytes.
    raw = log_path.read_bytes()
    records_path = out / "records.jsonl"
    with records_path.open("wb") as fh:
        fh.write(raw)

    rows, unreadable = _read_rows(raw)

    vr = verify_file(records_path)

    # ---- truncation cross-check against an external witness (optional) -------
    # A hash chain provably CANNOT detect truncation: delete the last N rows and
    # the surviving prefix still chains clean, so `chain_ok` alone would stamp a
    # truncated log PASS (it did, through 0.1.2 — the gap this closes). The only
    # thing that catches it is an OUTSIDE record of the head. If a witness pin
    # exists for this log's namespace, compare the EXPORTED records against it;
    # if none is configured, say so plainly rather than implying a completeness
    # the chain cannot prove. An honest non-check, never a silent clean PASS.
    truncation_checked = False
    truncation_ok: bool | None = None
    wv = None
    store = _resolve_witness(witness)

    # The witness's NATURE (kind + independence) is knowable even without a
    # namespace/pin, and a regulator needs it to judge whether a PASS rests on an
    # independent witness or a self-controlled file. `witness_block` starts as the
    # nature descriptor and gains the verification fields when a pin is consulted.
    witness_block: dict = _witness_nature(store)
    witnessed = False   # was a witness+namespace actually cross-checked?

    if store is not None and witness_namespace:
        witnessed = True
        wv = verify_against_witness(store, witness_namespace, Ledger(records_path))
        witness_block.update({"namespace": witness_namespace,
                              "verdict": wv.verdict, "detail": wv.detail,
                              "witness_rows": wv.witness_rows,
                              "witness_chain": wv.witness_chain,
                              "local_rows": wv.local_rows,
                              # Did the WITNESS prove its own file was not edited?
                              # arcaeon-ledger 0.5.9+ answers this; older versions
                              # and every remote client that exposes only .latest()
                              # cannot, and "cannot" must not read as "did".
                              # Surfaced here because a verdict that records the
                              # answer and tells no consumer is the same failure
                              # this field exists to close (self-audit 2026-08-23).
                              "self_integrity": getattr(
                                  wv, "witness_self_integrity", "unknown")})
        pin = store.latest(witness_namespace)
        if pin is not None:
            # the raw pin carries as_of / received_at and any extra fields the
            # witness recorded (e.g. an OTS anchor receipt) — passed through.
            witness_block["pin"] = pin
        if wv.verdict == "no_record":
            truncation_checked = False   # configured, but nothing to check against
        else:
            truncation_checked = True
            # TRI-STATE, like `chain_ok` (0.1.8). `wv.verdict == "consistent"`
            # made this False for witness_broken / local_broken / any verdict
            # this version does not know -- cases where the ledger REFUSED to
            # compare ("no comparison is meaningful") -- so integrity.json
            # carried `truncation_ok: false` beside a WITNESS_CHECK_FAILED
            # verdict whose prose says "do not read this as tampering". False
            # is an accusation; a comparison that never ran is None.
            truncation_ok = {"consistent": True, "truncated": False,
                             "rewritten": False}.get(wv.verdict)

    # ---- one distinguished top-level verdict --------------------------------
    # chain_ok (tamper within the log) AND truncation_checked (was a witness
    # consulted) AND truncation_ok are reported SEPARATELY, and the bundle only
    # says PASS when truncation was actually checked and passed. No witness ->
    # "verified-modulo-truncation", never a clean PASS.
    #
    # TRI-STATE HONESTY (external audit, 2026-08-23). Two accusation bugs lived
    # here and both put a false charge in a regulator-facing document:
    #   * `if not vr.ok` collapsed the ledger's deliberate ok=None (empty file,
    #     scope "empty" — "absence of evidence, not evidence of tampering") into
    #     FAIL: "The record set has been altered, truncated, or reordered." A
    #     customer's DAY-ONE export accused them of tampering.
    #   * every witness verdict this code didn't recognize fell into
    #     TRUNCATION_DETECTED ("this log is MISSING records") — so a corrupted
    #     WITNESS file, or any verdict a newer ledger adds (0.5.9 adds
    #     witness_broken/local_broken), became an accusation against the LOG.
    # Rule, same as everywhere else in this shop: an accusatory verdict must be
    # EARNED by the specific evidence for it; everything unrecognized is named
    # as unrecognized, loudly, and never mapped onto the nearest accusation.
    # THE OVERSHOOT, and its correction (2026-08-23, pre-invite adversarial
    # audit). The tri-state fix above cured a false-FAIL and created a
    # false-PASS, which is worse: `verify_file` returns ok=None for TWO
    # different reasons — an empty file (scope "empty") and unchained rows
    # skipped (scope "bounded_prechain_skipped") — and this chain collapsed
    # both into EMPTY_LOG. Because that branch ran FIRST it ALSO masked a
    # positive witness detection. Demonstrated: strip every chain link, alter
    # a witnessed row, delete three more; the witness correctly returns
    # "truncated" and the regulator-facing summary read "no records have been
    # written yet. There is nothing to verify and nothing to accuse."
    #
    # Two rules now hold this order:
    #   1. A POSITIVE EXTERNAL DETECTION OUTRANKS ANY SCOPE VERDICT. What the
    #      witness saw is evidence; what our chain could not scan is not.
    #   2. EMPTY_LOG means EMPTY — scope "empty" AND zero rows. Rows that
    #      exist but could not be verified are UNVERIFIED_SCOPE: not a pass,
    #      not an accusation, and never "nothing was written".
    # Rule 2 also protects the honest adopter: the documented adoption path
    # leaves prechain rows, so a real customer's real log was exporting as
    # "no records have been written yet".
    if wv is not None and wv.verdict == "rewritten":
        verdict = "REWRITE_DETECTED"
    elif wv is not None and wv.verdict == "truncated":
        verdict = "TRUNCATION_DETECTED"
    elif wv is not None and wv.verdict in ("witness_broken", "local_broken"):
        # the fault is in the named artifact, not necessarily the record set
        verdict = "WITNESS_CHECK_FAILED"
    elif wv is not None and wv.verdict == "no_record":
        # C9 (pre-invite audit): `wv is not None` only when the CALLER explicitly
        # configured both a witness AND a namespace (see `wv = None` default
        # above) — this is not "nobody asked", it is "somebody asked THIS exact
        # namespace and nothing was there". That used to fall through to the
        # tri-state chain below and land on VERIFIED_MODULO_TRUNCATION, exit 0,
        # identical to a caller who never configured a witness at all. A
        # mistyped or miscased namespace silently disabled the check, at zero
        # visible cost, chosen by the same party being audited. Now it is a
        # check that could not complete, not a clean skip.
        verdict = "WITNESS_CHECK_FAILED"
    elif vr.ok is None and getattr(vr, "verified_scope", "") == "empty" and vr.rows == 0:
        verdict = "EMPTY_LOG"            # nothing recorded yet; nothing to accuse
    elif vr.ok is None:
        # rows exist, the chain could not speak for them: say exactly that
        verdict = "UNVERIFIED_SCOPE"
    elif not vr.ok:
        verdict = "FAIL"
    elif not truncation_checked:
        verdict = "VERIFIED_MODULO_TRUNCATION"
    elif truncation_ok:
        verdict = "PASS"
    else:
        # a verdict this version has never heard of: report it verbatim rather
        # than converting the unknown into the worst available accusation.
        # `is not None`, not truthiness (0.1.8): WitnessVerdict is truthy ONLY
        # on "consistent", so `if wv` was False for every verdict that reaches
        # a prose line below, and each one printed its generic fallback -- this
        # verdict read ":none", TRUNCATION_DETECTED lost the ledger's row
        # arithmetic, WITNESS_CHECK_FAILED said "witness unavailable" for a
        # witness that answered. integrity.json had the detail; the summary
        # a regulator reads did not.
        verdict = f"UNRECOGNIZED_WITNESS_VERDICT:{wv.verdict if wv is not None else 'none'}"

    # 0.9.0: `verdict` is the one Arcaeon word (arcaeon.verdict), and the
    # detailed ten-value string that `verdict` carried through arcaeon-audit
    # 0.1.8 now lives, unchanged and permanently, in `finding`. The word
    # follows the export exit code (FINDING_WORD below); the finding is what
    # tells PASS from VERIFIED_MODULO_TRUNCATION and EMPTY_LOG.
    integrity = {"verdict": word_for_finding(verdict),
                 "finding": verdict,
                 "chain_ok": vr.ok,
                 "truncation_checked": truncation_checked,
                 "truncation_ok": truncation_ok,
                 "ok": vr.ok,   # retained: chain-only verdict, == chain_ok
                 "rows": vr.rows, "chained": vr.chained,
                 "first_break": vr.first_break,
                 "breaks": getattr(vr, "breaks", None),
                 "unreadable_lines": unreadable,
                 "witness": witness_block,
                 "bundle_schema": BUNDLE_SCHEMA_VERSION,
                 "records_sha256": hashlib.sha256(raw).hexdigest(),
                 "verified_file": "records.jsonl",
                 "checked_at": _now_iso(),
                 "how_to_reverify": _reverify_recipe(witness_block, witness_namespace)}

    # ---- instrument defects: the checker's own account of its blind spots ----
    # OPTIONAL, author-supplied, and embedded VERBATIM. The convention (README:
    # "Instrument defects") asks for three things — known false-positive modes,
    # known false-negative modes, and what was NOT exercised — because a checker
    # that names where it lies is worth more than one that only reports verdicts,
    # and a bundle whose limitations live in a chat log instead of the bundle has
    # laundered an absence into a presence.
    # There is deliberately NO validation of the content: the value is the slot
    # existing and travelling with the artefact, not this tool having an opinion
    # about what belongs in it. Same byte-for-byte discipline as records.jsonl —
    # a disclosure reflowed or "normalized" by the tool reporting on it is no
    # longer the author's disclosure — so the notes are written as raw bytes and
    # pinned with their own sha256. When no notes are supplied nothing is added:
    # no key, no file, no warning (an absent optional disclosure is not an
    # event, and a nag on every export would train people to ignore it).
    if instrument_notes is not None:
        notes_bytes = instrument_notes.encode("utf-8")
        (out / "INSTRUMENT_NOTES.md").write_bytes(notes_bytes)
        integrity["instrument_notes"] = instrument_notes
        integrity["instrument_notes_sha256"] = hashlib.sha256(notes_bytes).hexdigest()

    (out / "integrity.json").write_text(json.dumps(integrity, indent=2), encoding="utf-8")
    if witnessed:
        # a durable, self-contained cross-reference — nature + verification — only
        # when a witness was actually consulted (nature alone stays in integrity.json)
        (out / "witness.json").write_text(json.dumps(witness_block, indent=2), encoding="utf-8")

    s = _summ(rows)
    manifest = {"system_id": system_id, "provider": provider,
                "record_count": len(rows),
                "unreadable_lines": unreadable,
                "period_covered": {"from": s["first_ts"], "to": s["last_ts"]},
                "event_counts": s["counts"],
                "unknown_event_types": s["unknown_event_types"],
                "generated_at": _now_iso(), "tool": f"arcaeon-audit/{__version__}"}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # How much the CHAIN can say about these rows. Since a witness accusation
    # now outranks the chain-scope verdict (see the verdict chain above), the
    # accusation branches can be reached with an unverified or broken chain —
    # so none of them may assert "the chain itself is intact" unconditionally.
    if vr.ok:
        _chain_state = "the chain itself is intact"
    elif vr.ok is None:
        _chain_state = ("the chain could not speak for these rows (they carry no "
                        "chain links, so nothing was verified locally)")
    else:
        _chain_state = "the chain is ALSO broken"

    if verdict == "EMPTY_LOG":
        integrity_line = (
            "EMPTY_LOG — no records have been written yet. There is nothing to verify "
            "and nothing to accuse: an empty log is an absence of evidence, not "
            "evidence of tampering. (Before 2026-08-23 this case exported as FAIL with "
            "an alteration accusation — an external audit caught it; the ledger's own "
            "ok=None tri-state now passes through honestly.)")
    elif verdict == "WITNESS_CHECK_FAILED":
        integrity_line = (
            f"WITNESS_CHECK_FAILED — {_chain_state}, but the witness "
            f"cross-check could not complete: {wv.detail if wv is not None else 'witness unavailable'}. "
            "The fault is in the witness consultation, not (necessarily) in the record "
            "set. Do not read this as tampering, and do not read it as a pass: the "
            "completeness question is unanswered.")
    elif verdict.startswith("UNRECOGNIZED_WITNESS_VERDICT"):
        integrity_line = (
            f"{verdict} — the witness returned a verdict this version of arcaeon-audit "
            "does not recognize (likely a newer arcaeon-ledger vocabulary). Reported "
            "verbatim rather than mapped onto an accusation. Upgrade arcaeon-audit, or "
            "read the raw witness block in integrity.json.")
    elif verdict == "FAIL":
        integrity_line = (
            f"FAIL — integrity broken at: {vr.first_break}. The record set has been "
            "altered, truncated, or reordered since it was written.")
    elif verdict == "PASS":
        integrity_line = (
            f"PASS — no tampering detected, and the witnessed prefix is complete. Every "
            f"record chains to the prior one, and the log's chain at the witnessed row "
            f"still matches an external witness pin (namespace {witness_namespace!r}, "
            f"{wv.witness_rows if wv is not None else '?'} row(s) witnessed): no records were dropped AT OR BEFORE "
            f"the witnessed point (row {wv.witness_rows if wv is not None else '?'}). This does NOT cover records "
            "written AFTER the last pin — anything logged past the witnessed head can "
            "still be dropped undetectably, so the completeness guarantee runs only up to "
            "the last pin (pin close to export to shrink that window). It also assumes the "
            "witness is controlled INDEPENDENTLY of whoever can write the log: a witness an "
            "attacker can also rewrite proves nothing."
            + ("" if witness_block.get("self_integrity") == "verified" else
               " READ THIS BEFORE RELYING ON THE PASS: the witness did NOT prove its own "
               "record was unedited (self_integrity="
               f"{witness_block.get('self_integrity', 'unknown')!r}). Every remote/hosted "
               "witness client is this shape, and so is arcaeon-ledger before 0.5.9. The "
               "comparison above therefore rests on a pin whose own integrity was never "
               "established here — an attacker who can write BOTH the log and the pin can "
               "produce exactly this PASS. Check the witness at its source."))
    elif verdict == "TRUNCATION_DETECTED":
        integrity_line = (
            f"TRUNCATION_DETECTED — {_chain_state}, but {wv.detail if wv is not None else 'the witness reported truncation'}. A hash "
            "chain cannot see truncation on its own (a truncated prefix still chains "
            "clean); the external witness caught it. This log is MISSING records that "
            "existed when it was witnessed — it is NOT a complete record and must not "
            "be treated as one.")
    elif verdict == "REWRITE_DETECTED":
        integrity_line = (
            f"REWRITE_DETECTED — {wv.detail if wv is not None else 'the witness reported a rewrite'}. The exported log has enough rows, but its "
            "chain at the witnessed row disagrees with the external witness: history was "
            "rewritten from at or before that point.")
    elif verdict == "UNVERIFIED_SCOPE":
        # WHY the scan was bounded, from the ledger's own scope fields rather
        # than one hardcoded story (audit 2026-08-28). ok=None has more than one
        # cause and 0.6.0 added another: `bounded_declared_break` has prechain
        # == 0, so this rendered "the chain could not speak for 0 of them: they
        # carry no chain links" — a sentence that contradicts itself, names the
        # wrong cause, and then advises a fix ("chain the log going forward")
        # for a condition the reader does not have. The verdict was right and
        # the sentence beside it was false; a regulator reads the sentence.
        _scope = getattr(vr, "verified_scope", "") or "bounded"
        _pre = getattr(vr, "prechain", 0) or 0
        _decl = getattr(vr, "declared_breaks", 0) or 0
        _why, _advice = [], []
        if _pre:
            _why.append(f"{_pre} row(s) carry no chain links, so nothing about "
                        "them was verified locally")
            _advice.append("Chain the log going forward and pin it to a witness; "
                           "rows written from that point on are verifiable.")
        if _decl:
            _why.append(f"{_decl} declared break(s) bound the scan — the chain was "
                        "not checked ACROSS those rows (the breaks are named in "
                        "`declared`, and they stay named permanently)")
            _advice.append("A declared break is an honest permanent record, not a "
                           "repair: the rows on either side of it are chained, the "
                           "join between them is not.")
        if not _why:
            _why.append(f"the chain's scan was bounded (verified_scope={_scope!r}) "
                        "for a reason this version of arcaeon-audit does not "
                        "itemize — read `verified_scope` in integrity.json")
        integrity_line = (
            f"UNVERIFIED_SCOPE — this log contains {vr.rows} record(s) and the chain "
            f"could not speak for all of them (verified_scope={_scope!r}): "
            + "; ".join(_why) + ". This is NOT a pass and NOT an accusation — it is "
            "an unanswered question. " + " ".join(_advice) + (" " if _advice else "")
            + "(Before 2026-08-23 this case exported as EMPTY_LOG — 'no records have "
            "been written yet' — over a log with records in it, which also masked a "
            "positive witness detection. A pre-invite adversarial audit caught it.)")
    else:  # VERIFIED_MODULO_TRUNCATION
        # A HALF-CONFIGURED WITNESS IS A SKIPPED CHECK, NOT AN ABSENT ONE
        # (audit 2026-08-28). `witness` and `witness_namespace` are two
        # arguments and the check needs both; supply exactly one and the
        # truncation cross-check silently does not run, at exit 0, while this
        # sentence told the reader "no external witness was consulted" — over a
        # run whose own `witness` block in the same integrity.json records
        # kind: local_file and the store's path. That is C9's defect (a
        # mistyped namespace silently disabling the check at zero visible cost,
        # chosen by the party being audited) one argument over, and the
        # contradiction is inside a single artefact.
        # The VERDICT is deliberately unchanged here — see CHANGELOG 0.1.7,
        # flagged for a consumer-visible decision rather than taken silently.
        # The prose stops lying either way.
        # (The old `no_pin` branch this replaces was unreachable: wv.verdict ==
        # "no_record" became WITNESS_CHECK_FAILED in 0.1.5's C9 fix, so it can
        # never arrive at VERIFIED_MODULO_TRUNCATION.)
        if store is not None and not witness_namespace:
            why = ("a witness WAS configured but no `witness_namespace` was given, so "
                   "the cross-check never ran — this is a SKIPPED check, not an "
                   "absent one; supply both to close the gap, and")
        elif store is None and witness_namespace:
            why = (f"a namespace ({witness_namespace!r}) was given but no witness was "
                   "configured, so the cross-check never ran — a SKIPPED check, not "
                   "an absent one; supply both to close the gap, and")
        else:
            why = "no external witness was consulted, and"
        integrity_line = (
            "VERIFIED (MODULO TRUNCATION) — no tampering detected: every record chains to "
            f"the prior one. TRUNCATION NOT CHECKED — {why} a hash chain provably cannot "
            "detect truncation on its own (dropping the most recent rows leaves a prefix "
            "that still verifies clean). This is NOT a proof of completeness. Pin the log "
            "to an external witness to close this gap.")
    if witness_block.get("kind") not in (None, "none"):
        integrity_line += (
            f"\n\nWitness independence — kind: {witness_block['kind']}; "
            f"identifier: {witness_block.get('identifier')}; "
            f"independence: {witness_block['independence']}. {witness_block['note']}")
    # Point the reader at a source WE DO NOT CONTROL (pre-invite audit C6). Without
    # this, every instruction in this document resolves to "re-run their tool on
    # the bytes they gave you", which is self-attestation with extra steps.
    _ns = witness_namespace or witness_block.get("namespace")
    _wr, _wc = witness_block.get("witness_rows"), witness_block.get("witness_chain")
    if _ns and _wr is not None and _wc:
        integrity_line += (
            f"\n\nCHECK THIS WITHOUT TRUSTING US. The witnessed head above is held by a "
            f"public witness whose pin store is a PUBLIC git repository. Fetch it yourself, "
            f"no account and no credential:\n\n"
            f"    curl -s '{PUBLIC_WITNESS_BASE}/api/verify{_verify_query(_ns, _wr, _wc)}'\n\n"
            f"Read `witnessed` and `is_current_head`, then open the `raw_record_url` it "
            f"returns — that file lives in the public repo, and its commit history is linked "
            f"as `history`. If those numbers disagree with this bundle, believe the public "
            f"repository, not this document. (If the namespace is not found there, this log "
            f"was pinned to a privately held witness and its completeness rests on a record "
            f"you cannot independently reach — which is itself worth knowing.)")
    if unreadable:
        integrity_line += (f"\n\n{unreadable} line(s) in the log could not be read as a "
                           "record (unparseable, non-UTF8, or not a JSON object). They are "
                           "preserved verbatim in `records.jsonl` and excluded from the "
                           "counts below — an export never silently drops what it cannot read.")
    # The same disclosure, in the human-readable half of the bundle. Verbatim
    # again: whatever the author wrote is dropped in unaltered under its own
    # heading, so a reader who never opens integrity.json still meets the
    # instrument's confessed limits next to its verdict.
    instrument_section = "" if instrument_notes is None else f"""
## Instrument — known defects of this check
*Supplied by the author of this audit and reproduced verbatim; `arcaeon-audit`
does not validate, edit, or vouch for its contents. Also in the bundle as
`INSTRUMENT_NOTES.md` and in `integrity.json` under `instrument_notes`.*

{instrument_notes}
"""

    summary = f"""# Article 12 audit export — {system_id or '(unnamed system)'}

**Provider:** {provider or '(unspecified)'}
**Records:** {len(rows)}  ·  **Period covered:** {s['first_ts']} → {s['last_ts']}
**Generated:** {_now_iso()} by arcaeon-audit/{__version__}

## Integrity
{integrity_line}
{instrument_section}
Verification is reproducible by anyone: `records.jsonl` is hash-chained, so
re-running arcaeon-ledger's `verify_file()` reproduces `integrity.json`. Tamper
evidence does not depend on trusting this tool or its author.

## How this maps to EU AI Act Article 12
*Scope note, stated here because vendors routinely overstate this: Article 12
requires automatic recording of events. It does not require tamper-evidence or
integrity protection — the rows below marked "beyond Article 12" are engineering
properties this tool adds because they make the record usable as evidence, not
because the Act demands them.*

- **Automatic recording of events over the lifetime (Art.12(1)):** every action
  is appended automatically at the time it happens; timestamps are on each row.
- **Traceability appropriate to the intended purpose (Art.12(2)):** records carry
  system_id, agent, event type, inputs, outputs, decisions, and the acting
  principal + capability version.
- **Periods of use (Art.12(2)(a)):** see `system_start`/`system_stop` events and
  `period_covered` in the manifest.
- **Tamper-evidence (beyond Article 12 — the Act does not require this):**
  hash-chaining makes any post-hoc edit, deletion, or reorder detectable and
  locatable — the property a plain log file does not have, and the property that
  makes the record evidence rather than a self-report when it is challenged.
- **Truncation (the one thing a chain cannot catch alone):** deleting the most
  recent records leaves a prefix that still chains clean, so tamper-evidence by
  itself cannot prove a log is *complete*. That gap is closed only by an external
  witness — an outside record of the log's head that a later truncation would
  disagree with. When a witness is consulted, this export reports it under
  `witness` in `integrity.json` (and `witness.json`); a bundle marked PASS has
  been checked against a witness, while "verified modulo truncation" means the
  chain is intact but completeness was not witnessed. See the Integrity line above.
- **Witness independence (judge it yourself):** the `witness` block in
  `integrity.json` names the witness's `kind` (`local_file` / `remote_url` /
  `opentimestamps` / `none`), its `identifier`, and an honest `independence` label
  (`self_asserted` / `externally_verifiable` / `none`). A witness only proves
  completeness if it is controlled INDEPENDENTLY of whoever can write the log — a
  `local_file` witness sits in the writer's own control domain and is labelled
  `self_asserted`, NOT independent. This lets a regulator see the independence
  question rather than take a bare PASS on trust.

## What this is NOT
This is an engineering control that produces tamper-evident, exportable records.
It is not legal advice and does not by itself make a system compliant. Article 12
compliance depends on WHAT you choose to log and your broader obligations under
the Act. This tool gives you the integrity + export primitive; the coverage is
yours to define.

## Event counts
{chr(10).join(f'- {k}: {v}' for k, v in sorted(s['counts'].items())) or '- (none)'}
"""
    (out / "ARTICLE_12_SUMMARY.md").write_text(summary, encoding="utf-8")
    return out
