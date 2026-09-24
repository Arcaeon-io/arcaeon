# SPDX-License-Identifier: MIT
"""arcaeon_ledger.witness — the outside check that closes the truncation gap.

An append-only hash chain cannot, by itself, catch TRUNCATION: lop off the most
recent rows and the remainder still verifies clean (see the README). The fix is an
EXTERNAL WITNESS — a party outside your own control that records your log's head
(chain + row count) on a cadence. Once someone else holds `(rows, chain)` at time
T, no later rewrite can produce a log that both differs from that pin and still
verifies: a truncated log has FEWER rows than the witness saw, and a rewritten one
has a DIFFERENT chain at the witnessed row.

This module ships two halves:

  * `WitnessStore` — the reference witness core: a file-backed, append-only store
    of pins keyed by namespace. It holds ONLY fingerprints (chain + row count +
    time), never your log content — a "password nowhere" design: if the store is
    breached there is nothing sensitive to steal, only hashes useless without the
    original log. A serverless HTTP endpoint (Stage 0 of the hosted service) is a
    thin wrapper over exactly this object; running it locally is a complete,
    offline, zero-cost way to exercise this module. **Note the wording change
    from line 6, caught in independent review 2026-08-24: a store you run
    yourself is NOT the witness this module exists to provide** — line 6
    defines a witness as a party OUTSIDE your own control, and a store you
    alone hold is the opposite of that. Running it locally is for
    development and testing the mechanism; the actual protection requires
    deploying it somewhere the logging party cannot reach (see
    `verify_against_witness`'s docstring below for exactly what a
    self-controlled pin does and does not prove).

  * the client half — `publish_head` (send your current head to a witness) and
    `verify_against_witness` (fetch the last pin and check your log against it,
    HONESTLY: consistent / truncated / rewritten / no-record).

The honest boundary: a witness proves your log was not truncated or rewritten
*relative to what the witness saw, and only as recently as the last pin*. The MAX
gap between pins is your real security parameter, not the average — an attacker
picks the gap. It says nothing about whether the logged content was TRUE; that's
what `bind_artefact` is for. Stdlib only.
"""
from __future__ import annotations

import hashlib

from arcaeon.record.row import body_digest
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from arcaeon.record.ledger import Head, Ledger, UnverifiedLedgerError, chain_at

__all__ = ["WitnessStore", "publish_head", "verify_against_witness", "WitnessVerdict",
           "HostedWitness", "HostedWitnessError"]


@dataclass
class WitnessVerdict:
    """The result of checking a log against an external witness pin.

    verdict:
      "consistent"  — the log still matches what the witness saw at the witnessed
                       row (and may have grown since — that's fine and expected).
      "truncated"   — the log now has FEWER rows than the witness recorded, or the
                       witnessed row is unreachable: witnessed history is missing.
      "rewritten"   — the log has enough rows but its chain at the witnessed row
                       DIFFERS from the pin: history was rewritten from some point.
      "no_record"   — the witness holds no pin for this namespace to check against.
      "witness_broken" — the witness pin file fails its OWN chain: a pin from a
                       tampered witness cannot be trusted, so no comparison is run.
      "local_broken"   — the log fails its own chain; agreement at the pinned row
                       does not make a locally tampered log consistent.
    (The docstring listed only the first four while the code returned six —
    a consumer switching on the documented set silently mishandled a tampered
    witness. Pre-invite audit, 2026-08-23.)

    witness_self_integrity: whether the WITNESS could vouch for itself.
      "verified"      — the store self-verified its own pin chain.
      "unestablished" — the store exposes no verify() (every hosted/remote
                       client is this shape), so its self-integrity was never
                       checked. The comparison still runs, but a caller must not
                       read the result as a witness-backed guarantee.
      "broken"        — the store self-verified and FAILED.
    """
    verdict: str
    detail: str
    witness_rows: int | None = None
    witness_chain: str | None = None
    local_rows: int | None = None
    witness_self_integrity: str = "unestablished"

    def __bool__(self) -> bool:
        # truthy only when the outside check positively confirms consistency
        return self.verdict == "consistent"


#: Chain seed for the pin file. Distinct from the ledger's so a pin digest can
#: never be confused with a log row digest.
_WITNESS_GENESIS = "witness-genesis"


class WitnessVerify(dict):
    """The pin-chain verdict. A dict, so `v["ok"]` reads naturally, but with truthiness
    bound to the verdict rather than to whether the dict has contents.

    Why this is not a plain dict: a non-empty dict is unconditionally truthy, so
    `if store.verify(): trust_the_pins()` returned True over a BROKEN chain. That is the
    same shape as a verifier reporting ok=True over an empty file — the container said
    yes while the verdict inside it said no. Caught by writing the test that asserts
    ok=None is falsy, which a bare dict could never satisfy.

    Truthy ONLY when ok is exactly True. ok=None (legacy pins skipped, or an empty
    store) is falsy on purpose: it is a bounded answer, not a green.
    """

    def __bool__(self) -> bool:
        return self.get("ok") is True


class WitnessStore:
    """Reference witness: an append-only, file-backed store of head pins.

    Holds only fingerprints, never log content. One JSONL file; each line is a
    recorded pin `{namespace, rows, chain, as_of, received_at}`.

    THE PIN FILE IS ITSELF CHAINED (0.5.9). Each record carries `prev`, the digest of
    the record before it, AND `self`, the digest of its own content. Both are needed:
    `prev` catches deletion and reordering, and `self` catches an edit to the LAST pin,
    which a back-link structurally cannot see because nothing links forward from it. The
    first draft of this feature had only `prev`, and a demonstrated-red run showed it
    missing the reviewer's actual attack — editing the only pin in the file. `verify()`
    names the offending line. This closes a gap that was real and was documented
    wrongly: through 0.5.8 the docstring claimed the record was "tamper-evident by
    inspection" because it is written append-only. Append-only describes how this class
    WRITES. It was never a property of the file, and nothing here detected a pin edited
    afterwards. That claim was retracted before the mechanism existed; the mechanism now
    exists.

    LEGACY FILES KEEP WORKING, deliberately. Pins written before 0.5.9 have no `prev`.
    `verify()` reports those as `unchained` and does NOT call them broken, because a
    witness that rejects its own history the moment it upgrades turns every real pin
    into a false alarm, which is worse than having no chain at all. A file with
    unchained rows and no breaks returns `ok=None`, not `ok=True` — falsy, scoped, and
    honest about what was actually checked.

    WHAT THE CHAIN STILL DOES NOT DO, because this is the part that gets overclaimed.
    It makes an edit to a stored pin DETECTABLE. It does not stop anyone with write
    access from discarding the file and minting a fresh consistent one, exactly as the
    ledger's own chain cannot stop a consistent full rewrite. So the protection is
    still substantially the independence of the host: a pin is worth the separation
    between whoever holds it and whoever wrote the log. Put the store somewhere the
    logging party cannot reach. Two further limits worth knowing: a pin constrains
    nothing about rows appended after it was taken, and a pin recorded over an empty
    log constrains nothing at all.

    A hosted witness (Stage 0) is an HTTP endpoint wrapping this: POST a pin ->
    `record`, GET the latest -> `latest`. Running it in-process, as the tests and
    `verify_against_witness` do, is a complete local witness.
    """

    # STAMP-ORDERING GUARD (0.7.4). How far the publisher's `as_of` may run AHEAD of
    # the witness's `received_at` before the pin is refused. Skew between two honest
    # clocks is real and small; a stamp that claims a time the witness had not yet
    # reached is not skew, it is a claim about a time the witness could not have seen.
    # A declared number, so a refusal is a measurement against a published tolerance
    # and not a policy a consumer has to guess at.
    CLOCK_TOLERANCE_S = 300

    # WHAT THIS BOUND IS, AND WHAT IT IS NOT (2026-09-03, from deep-seeker on the
    # Colony). With T published, the attestation is not "this was published now".
    # It is "this was not published more than T after the as_of it claims". A
    # publisher can systematically stamp up to ~T ahead and still be attested:
    # that is bounded backdating-by-skew, and the bound is ON THE RECORD where a
    # consumer can carry it. Declared is what makes it honest.
    #
    # THE STRUCTURAL LIMIT, which is not a bug and should not be filed as one:
    # backdating is UNDETECTABLE within a single clock-authoritative witness. A
    # PAST as_of is consistent with any receipt time, so there is nothing for the
    # witness to compare it against; the previous pin's timestamp is the only
    # lower bound available, which is exactly as tight as one witness can get.
    # You cannot distinguish "published at as_of" from "published later and
    # backdated to as_of" with one clock. That is the information-theoretic
    # boundary of the single-witness design, not an unclosed hole.
    #
    # The only thing that closes it is a SECOND, DISJOINT-PARTY witness clock on
    # the same claim: a received_at that whoever backdates cannot coordinate. So
    # one witness bounds the future by T and the past by the previous pin, and
    # both bounds are honest.

    def __init__(self, path: str | Path):
        self.path = Path(path)
        # Refusals are written HERE, never into the pin chain: the chain stays
        # pins-only so `latest()`/`history()`/`verify()` keep their meaning, and a
        # stranger reading the store can still see that a category error happened
        #
        # HONEST LIMIT OF THIS SIDECAR (2026-09-03, deep-seeker's correction, and
        # it is a good one): this file is OURS. A refusal row here is findable by
        # a stranger and DELETABLE BY US. So the refusal is attested IN BAND (the
        # raised error, which the caller cannot suppress) and recorded BEST
        # EFFORT (this row, which the store's owner could prune). Those are two
        # different strengths and the docstring must not blur them.
        #
        # To make the sidecar itself a stranger's check rather than a
        # self-witness, its digest has to be published somewhere immutable and
        # cross-addressable. Content-address the thing you want a stranger to be
        # able to verify. Not done yet; tracked rather than claimed.
        # rather than inferring it from a silence.
        self.refusals_path = self.path.with_name(self.path.name + ".refused")

    @staticmethod
    def _parse_stamp(s):
        if not isinstance(s, str) or not s:
            return None
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d

    def _refuse(self, kind: str, namespace: str, head: Head, received_at, detail: str):
        row = {"kind": kind, "namespace": namespace, "rows": head.rows,
               "chain": head.chain, "as_of": head.as_of, "received_at": received_at,
               "detail": detail}
        try:
            self.refusals_path.parent.mkdir(parents=True, exist_ok=True)
            with self.refusals_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row) + "\n")
        except OSError:
            pass  # the refusal still raises; the sidecar is the legible copy, not the gate
        raise ValueError(f"{kind}: {detail}")

    def record(self, namespace: str, head: Head, *, received_at: str | None = None) -> dict:
        """Append a pin for `namespace`, chained to the pin before it. Returns the record.

        The chain spans the WHOLE FILE, not one namespace. Per-namespace chaining would
        let an attacker delete every pin for one namespace and leave the rest verifying
        clean, which is the same detachment problem the ledger guards against.

        MONOTONIC GUARD (C3, pre-invite audit 2026-08-23; independently
        re-demonstrated in review 2026-08-24): a witness never goes backward.
        Before this guard, truncate-the-log-then-re-pin sailed through — the
        new, smaller pin became `latest()`, `verify_against_witness` read only
        `latest()`, and the larger old pin (the standing disproof) sat unread
        in `history()`. The hosted JS service has rejected this since 8/14
        ("monotonic violation: a witness never goes backward", 409); the
        Python reference now matches. The bar is the HISTORY HIGH-WATER MARK,
        not `latest()`: a file that already contains a backward pin (written
        before this guard existed) must not anchor the guard to the low mark.
        Equal rows re-pin stays allowed (idempotent heartbeat, same as JS).
        Honest limit, unchanged from the class docstring: this stops a
        backward pin arriving through the API. It cannot stop an actor who
        can rewrite the store file itself — that protection is, as ever, the
        independence of the host.
        """
        high_water = None
        for prior in self.history(namespace):
            r = prior.get("rows")
            if isinstance(r, int) and not isinstance(r, bool) \
                    and (high_water is None or r > high_water):
                high_water = r
        if high_water is not None and head.rows < high_water:
            raise ValueError(
                f"monotonic violation: a witness never goes backward — "
                f"namespace {namespace!r} high-water is {high_water} rows, "
                f"submitted {head.rows}. A shrinking log is exactly the "
                f"truncation this witness exists to catch; if the log was "
                f"legitimately reset, use a new namespace rather than "
                f"rewriting this one's history.")
        # STAMP-ORDERING GUARD (0.7.4): only when this store is clock-authoritative.
        # Two clocks are written on every pin and, until this guard, nothing compared
        # them — a pin whose publisher stamp post-dated the witness's own receipt was
        # admitted, annotated, and served as verified, leaving the comparison to a
        # consumer who would usually not make it. The refusal machinery above already
        # existed; it had been pointed at one invariant and not this one. Found by
        # reading the code in a Colony exchange, 2026-09-02, and posted before fixed.
        # What this does NOT catch: a publisher BACKDATING as_of. A stamp in the past
        # is consistent with any receipt time, so the witness has nothing to refuse
        # it against; that direction is bounded only by the previous pin, and only
        # loosely.
        if received_at is not None:
            recv = self._parse_stamp(received_at)
            pub = self._parse_stamp(head.as_of)
            if recv is None or pub is None:
                self._refuse(
                    "stamp-ordering violation", namespace, head, received_at,
                    f"cannot compare stamps for namespace {namespace!r}: "
                    f"as_of={head.as_of!r} received_at={received_at!r} — a stamp the "
                    f"witness cannot read is not exempt from the comparison, it fails it.")
            ahead = (pub - recv).total_seconds()
            if ahead > self.CLOCK_TOLERANCE_S:
                self._refuse(
                    "stamp-ordering violation", namespace, head, received_at,
                    f"publisher as_of {head.as_of} is {ahead:.0f}s AHEAD of the witness's "
                    f"received_at {received_at} (tolerance {self.CLOCK_TOLERANCE_S}s) for "
                    f"namespace {namespace!r}. The witness cannot have received a pin "
                    f"before the publisher made it; a stamp from the witness's future "
                    f"is a claim about a time the witness could not have seen, and is "
                    f"refused rather than recorded and left for a consumer to notice.")
        rec = {
            "namespace": namespace,
            "rows": head.rows,
            "chain": head.chain,
            "as_of": head.as_of,
            # received_at is the witness's OWN clock — the trust surface is that
            # this timestamp is the witness's, not the publisher's. Left to the
            # caller/server to stamp; None if the store isn't clock-authoritative.
            "received_at": received_at,
            "prev": self._tail_digest(),
        }
        # `self` commits the record to its OWN content, which is what protects the TAIL.
        # `prev` links backwards, so a pure back-chain guards records 1..N-1 and leaves
        # the last one open — and the last one is the pin a verifier actually reads.
        rec["self"] = self._digest_record(rec)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as fh:
            payload = (json.dumps(rec) + "\n").encode("utf-8")
            fh.write(payload)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass          # network mounts may not support fsync; flush is the floor
            # Confirm the pin landed. Same reason as the ledger's append: a path that
            # accepts writes and stores nothing (a Windows reserved device name) would
            # otherwise return a plausible record for a pin that does not exist.
            try:
                landed = fh.tell()
            except OSError as e:
                raise OSError("cannot confirm the pin landed in %s: %s" % (self.path, e))
        if landed < len(payload):
            raise OSError(
                "wrote %d bytes to %s but the file holds %d — the pin was discarded, "
                "nothing was recorded" % (len(payload), self.path, landed))
        return rec

    @staticmethod
    def _digest_record(rec: dict) -> str:
        """Digest one pin's CONTENT. Excludes the two derived fields, `prev` and
        `self`, so the value is reproducible by anyone holding the record."""
        # One hashing rule for rows and pins: arcaeon.record.row.body_digest
        # (surrogatepass-safe, first 32 hex), over the pin minus prev/self.
        return body_digest(rec, ("prev", "self"))

    def _tail_digest(self) -> str:
        """Digest of the last pin in the file, or GENESIS when the file is empty."""
        last = None
        try:
            for raw in self.path.read_text(encoding="utf-8", errors="replace").split("\n"):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    # RecursionError, not just ValueError (2026-09-03). A ~100k
                    # deep array overflows the C decoder and escapes as
                    # RecursionError, which this except walked straight past, so
                    # ONE appended line permanently killed publish_head() while
                    # latest() and history() -- hardened in 0.7.2 -- kept working.
                    # This store is designed to be hosted where strangers POST to
                    # it, and the witness is the only thing that closes the
                    # truncation gap, so silencing it re-opens free truncation.
                    last = json.loads(raw)
                except (ValueError, RecursionError):
                    continue          # unparseable line: verify() names it, record() steps past
        except OSError:
            return _WITNESS_GENESIS
        if not isinstance(last, dict):
            return _WITNESS_GENESIS
        return self._digest_record(last)

    def verify(self) -> dict:
        """Recompute the pin chain. Returns a verdict naming the first break by line.

        Three-valued, matching the ledger's own shape:
          ok=True   — every pin chained and every link recomputed.
          ok=None   — no break found, but `unchained` legacy pins were skipped. FALSY.
                      Not a green: a pre-0.9 file cannot be distinguished from a
                      fabricated prepend, so it does not claim to be.
          ok=False  — a break was found.
        """
        out = WitnessVerify(ok=True, pins=0, chained=0, unchained=0,
                            breaks=0, first_break=None)
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError as e:
            return WitnessVerify({**out, "ok": False, "breaks": 1,
                                  "first_break": "unreadable: %s" % e})
        prev_digest = _WITNESS_GENESIS
        for i, raw in enumerate(lines, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except (ValueError, RecursionError):
                # Same 2026-09-03 fix as publish_head above: a nesting bomb is a
                # named break like any other corrupt line, never a crash that
                # takes the whole verify() sweep with it.
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or "line %d: unparseable" % i
                continue
            if not isinstance(rec, dict):
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or "line %d: not a JSON object" % i
                continue
            out["pins"] += 1
            claimed = rec.get("prev")
            if claimed is None:
                if out["chained"]:
                    # An unchained pin AFTER the chain began is a tamper signal, not
                    # legacy history. Legacy rows can only precede chained ones.
                    out.update(ok=False, breaks=out["breaks"] + 1)
                    out["first_break"] = out["first_break"] or (
                        "line %d: unchained pin after the chain began" % i)
                else:
                    out["unchained"] += 1
                prev_digest = self._digest_record(rec)
                continue
            if claimed != prev_digest:
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or "line %d: pin chain mismatch" % i
            content = self._digest_record(rec)
            own = rec.get("self")
            if own is None:
                # A CHAINED pin (it has `prev`, so we reached here) MUST carry `self`.
                # The first version of this guard only checked `self` when present, and
                # an attacker closed the tail-edit hole by editing the last pin AND
                # DELETING its `self` field: no successor to catch it via `prev`, no
                # `self` to catch it directly. That reopened the exact truncation
                # laundering this whole feature exists to stop. A chained pin missing
                # its self-digest is now a break, not a skipped check. (Legacy pins are
                # unchained, handled above at `claimed is None`, and never reach here.)
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or (
                    "line %d: chained pin missing its self-digest" % i)
            elif own != content:
                # Catches an edit to the LAST pin, which the back-link cannot see.
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or (
                    "line %d: pin content does not match its own digest" % i)
            prev_digest = content
            out["chained"] += 1
        if out["ok"] and out["unchained"]:
            out["ok"] = None          # bounded: legacy pins were not verifiable
        if out["ok"] and out["pins"] == 0:
            out["ok"] = None          # an empty store verifies nothing
        return out

    def latest(self, namespace: str) -> dict | None:
        """The most recently recorded pin for `namespace`, or None."""
        # errors="replace" (pre-invite audit C11, 2026-08-23): verify() in this
        # same file already tolerates a non-UTF8 byte; this read path did not,
        # so a truncated write or a corrupted sector raised UnicodeDecodeError
        # straight through export_bundle instead of producing a verdict. The
        # module's own principle is that a damaged log is the one you most need
        # to export -- this hardened the log path and left the witness path
        # fatal. A replaced byte breaks that ONE JSON line's parse (caught below
        # by the existing ValueError guard); every other line is unaffected.
        found = None
        try:
            for raw in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except (ValueError, RecursionError):
                    continue
                # A valid-JSON line that is not an object ("[]", "42", a
                # 3000-deep array) has no .get — before 0.7.2 that was an
                # AttributeError out of latest(), a crash where a skip belongs.
                if not isinstance(rec, dict):
                    continue
                if rec.get("namespace") == namespace:
                    found = rec  # last one wins (append-only, chronological)
        except OSError:
            return None
        return found

    def history(self, namespace: str) -> list[dict]:
        """All pins recorded for `namespace`, in order."""
        out: list[dict] = []
        try:
            for raw in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except (ValueError, RecursionError):
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("namespace") == namespace:
                    out.append(rec)
        except OSError:
            pass
        return out


def publish_head(store: WitnessStore, namespace: str, ledger: Ledger,
                 *, received_at: str | None = None, extra: dict | None = None) -> dict:
    """Record the ledger's CURRENT head with the witness under `namespace`.

    Call this on a cadence (the max gap between calls is your security parameter).
    `store` is any object with a `record(namespace, head, received_at=)` method —
    the reference `WitnessStore`, or a client wrapper that POSTs to a hosted one
    (`HostedWitness`).

    `extra` (optional, completeness slice 2): additional pin fields such as a
    tape's `pair` / `record_format`. Passed to `store.record(..., extra=)` ONLY
    when the store declares `accepts_extra = True`; any other store gets the
    unchanged call, so existing stores keep working. The core body
    `{namespace, rows, chain}` is never overridable through `extra`.

    REFUSES A ZERO-ROW PIN (pre-invite audit 2026-08-23, C2). `chain_at(path, 0)`
    returns the genesis constant WITHOUT OPENING THE FILE, so a pin taken over an
    empty log compared "genesis" against "genesis", matched, and fell through to
    the library's one truthy verdict — against ANY log, including one truncated
    from 50 rows to 2. This module's own prose already said "a pin recorded over
    an empty log constrains nothing at all"; the code then blessed it, which is
    the anti-truncation mechanism certifying a truncation. A pin that constrains
    nothing is not a weak pin, it is a misleading one, so it is not minted.

    REFUSES AN UNVERIFIED PIN (0.7.6), for the same reason and with more force:
    a witnessed pin is written into somebody else's store and cannot be taken
    back. `head()` now carries the verify verdict, so a log whose chain is
    broken is refused here rather than anchored — the anti-tamper mechanism
    must not put its name on tampered bytes. Checked BEFORE the zero-row guard,
    because a corrupt file often also has zero parseable rows and "the chain is
    broken at line 1" is the more useful of the two refusals. Both raise
    ValueError subclasses, so existing handlers are unaffected.
    """
    head = ledger.head()
    if head.ok is False:
        raise UnverifiedLedgerError(
            f"refusing to publish a head for namespace {namespace!r}: the log "
            f"does not verify ({head.first_break}). A witnessed pin is recorded "
            f"outside your control and cannot be retracted; anchoring a broken "
            f"chain would make the witness attest to the damage. Repair the log, "
            f"or name the break with declare_break(), then publish.")
    if not head.rows:
        raise ValueError(
            "refusing to pin an empty log: a zero-row pin constrains nothing and "
            "would read as a positive confirmation against any log. Append at "
            "least one record before publishing a head.")
    if extra and getattr(store, "accepts_extra", False):
        return store.record(namespace, head, received_at=received_at, extra=extra)
    return store.record(namespace, head, received_at=received_at)


class HostedWitnessError(RuntimeError):
    """The hosted witness did not record the pin. `status` is the HTTP status
    (None when the witness could not be reached); `body` is its JSON answer."""

    def __init__(self, message: str, status: int | None = None, body: dict | None = None):
        super().__init__(message)
        self.status = status
        self.body = body or {}


class HostedWitness:
    """The HTTP client half of the hosted witness: `POST {url}/api/pin` with
    `{namespace, rows, chain}` and a bearer key. Usable anywhere a store is:
    `publish_head(HostedWitness(url, key), ns, ledger)`.

    No default URL, on purpose: nothing pins to a live service unless the
    caller names it. The key is sent as a header and never returned.

    EXTRA FIELDS ARE CHECKED, NOT ASSUMED. The hosted witness (arcaeon-witness
    `api/pin.js`, read 2026-09-22) validates only namespace/rows/chain (and
    fails closed on an unknown `intent`); it does not reject other fields, but
    it builds the stored pin from named fields only, so an unknown field is
    accepted and DROPPED. So `record()` sends `extra`, then compares the pin
    the witness echoes and reports `extra_fields`:
      "recorded"            every extra field is on the stored pin
      "dropped_by_witness"  accepted, not stored (today's witness)
      "refused_by_witness"  the witness 400'd them; ONE retry without them landed
      "not_sent"            no extra fields were given
    A pin whose echoed rows/chain differ from what was sent is an error, not a
    success: the witness would be attesting to a head this log does not have.
    """

    accepts_extra = True

    def __init__(self, url: str, key: str, *, timeout: float = 30.0):
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError(f"witness url must be http(s), got {url!r}")
        self.url = url.rstrip("/")
        self._key = key
        self.timeout = timeout

    def __repr__(self) -> str:  # never print the key
        return f"HostedWitness({self.url!r})"

    def _post(self, body: dict) -> tuple[int, dict]:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(self.url + "/api/pin", method="POST",
                                     data=json.dumps(body).encode("utf-8"))
        req.add_header("Authorization", "Bearer " + self._key)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise HostedWitnessError(f"witness unreachable: {e}"[:300]) from None
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {"error": "witness answered with non-JSON"}
        return status, data if isinstance(data, dict) else {"answer": data}

    def record(self, namespace: str, head: Head, *, received_at: str | None = None,
               extra: dict | None = None) -> dict:
        core = {"namespace": namespace, "rows": head.rows, "chain": head.chain}
        extra = {k: v for k, v in (extra or {}).items() if k not in core and v is not None}
        status, data = self._post(dict(extra, **core))
        extra_status = "not_sent" if not extra else None
        if status == 400 and extra:
            status, data = self._post(core)
            extra_status = "refused_by_witness"
        if status not in (200, 201):
            raise HostedWitnessError(
                f"witness did not record the pin (HTTP {status}): "
                f"{str(data.get('error') or data)[:200]}", status, data)
        pin = data.get("pin") if isinstance(data.get("pin"), dict) else {}
        if (pin.get("rows"), str(pin.get("chain", "")).lower()) != (head.rows, head.chain.lower()):
            raise HostedWitnessError(
                f"witness recorded a different head (rows={pin.get('rows')!r}, "
                f"chain={pin.get('chain')!r}) than was sent (rows={head.rows}, "
                f"chain={head.chain}); not accepted as a pin of this log", status, data)
        if extra_status is None:
            extra_status = ("recorded" if all(pin.get(k) == v for k, v in extra.items())
                            else "dropped_by_witness")
        return {"namespace": namespace, "rows": head.rows, "chain": head.chain.lower(),
                "pinned_at": pin.get("pinned_at"), "seq": pin.get("seq"),
                "next_pin_due_by": pin.get("next_pin_due_by"),
                "witness": self.url, "witness_status": status, "idempotent": status == 200,
                "extra_fields": extra_status,
                "extra_sent": sorted(extra) if extra else [],
                "received_at_publisher": received_at}


def verify_against_witness(store: WitnessStore, namespace: str,
                           ledger: Ledger) -> WitnessVerdict:
    """Check the ledger against the witness's most recent pin for `namespace`.

    This is the outside check the chain alone cannot do. Returns a WitnessVerdict;
    it is truthy only on "consistent". Honest by construction: "truncated" and
    "rewritten" are positive detections, and a re-fetch that can't reach the witness
    is "no_record", never a false ok.

    Two integrity guards run BEFORE the comparison, added in 0.5.9 once both records
    gained a chain of their own: if the witness pin file fails its own chain the
    verdict is "witness_broken", and if the log fails its own chain it is
    "local_broken". Both are falsy. Without these, a forged pin or a locally tampered
    log could still be compared and reported "consistent" — the comparison would
    agree over data that was already broken.
    """
    # BEFORE any comparison, establish that both records can be trusted at all. A
    # "consistent" verdict is the truthy state, and returning truthy while either the
    # witness file or the log is internally broken is the exact container-says-yes
    # defect this library keeps finding: the comparison would agree, over forged data.
    #
    # Witness first. If the pin file fails its own chain, `latest()` may return an
    # edited pin, so agreeing with it proves nothing. ok is False is a real break;
    # ok=None (legacy unchained pins) is bounded, not tampered, and does NOT block.
    #
    # CONTRACT COMPATIBILITY (2026-08-23, caught by arcaeon-audit's suite): the
    # documented witness contract downstream — arcaeon-audit's docstring and
    # CHANGELOG — is "any object exposing .latest(namespace)". Requiring .verify()
    # unconditionally broke every hosted/remote witness client the moment this
    # method appeared. A store that cannot self-verify is not thereby BROKEN; its
    # self-integrity is simply UNESTABLISHED — three-valued, like everything else
    # here. The comparison proceeds and the caller's witness block still records
    # the store's nature (self-declared vs undeclared) for the reader to weigh.
    _verify = getattr(store, "verify", None)
    wv = _verify() if callable(_verify) else {"ok": None, "pins": None,
                                              "note": "store exposes no verify(); "
                                                      "self-integrity unestablished"}
    # Self-integrity of the WITNESS ITSELF, carried on every verdict below so a
    # caller can never mistake "not checked" for "checked and fine". A hosted
    # client exposing only .latest() is the deployment shape, and before this it
    # produced a verdict indistinguishable from one backed by a self-verified
    # witness (pre-invite audit 2026-08-23, C14).
    if not callable(_verify):
        _si = "unestablished"
    elif wv.get("ok") is True:
        _si = "verified"
    elif wv.get("ok") is False:
        _si = "broken"
    else:
        _si = "unestablished"

    def _V(*a, **kw):
        kw.setdefault("witness_self_integrity", _si)
        return WitnessVerdict(*a, **kw)

    # `wv.get("pins", 0)` only substitutes 0 when the KEY IS ABSENT. A remote
    # witness client returning `{"ok": False, "pins": None}` explicitly still
    # raised TypeError on `None > 0` (pre-invite audit C11, found alongside the
    # non-UTF8 crash above — same discipline: this function must return a
    # verdict about EVERY input, including a hostile or malformed one).
    if wv.get("ok") is False and (wv.get("pins") or 0) > 0:
        # pins > 0 is the difference between a TAMPERED witness and an ABSENT one.
        # A missing or empty file reads as ok=False/unreadable but holds no pins, and
        # that is a legitimate no-pin state that falls through to "no_record" below —
        # not a break. Only a genuine chain break AMONG real pins blocks here.
        return _V(
            "witness_broken",
            "the witness pin file fails its own chain (%s): a pin from a tampered "
            "witness cannot be trusted, so no comparison is meaningful"
            % wv.get("first_break"))

    # Then the log itself. Agreeing with a pin at one row says nothing about a log
    # whose own chain is already broken elsewhere.
    lv = ledger.verify()
    if lv.ok is False:
        return _V(
            "local_broken",
            "the log fails its own chain (%s): witness agreement at the pinned row "
            "does not make a locally tampered log consistent" % lv.first_break)

    pin = store.latest(namespace)
    if pin is None:
        return _V("no_record",
                              f"witness holds no pin for namespace {namespace!r}")

    w_rows = pin.get("rows")
    w_chain = pin.get("chain")
    local = ledger.head()
    local_rows = local.rows

    if not isinstance(w_rows, int):
        return _V("no_record", "witness pin missing a valid row count",
                              witness_chain=w_chain, local_rows=local_rows)

    # A ZERO-ROW PIN CONSTRAINS NOTHING (pre-invite audit 2026-08-23, C2).
    # publish_head now refuses to mint one, but pins minted before that fix — or
    # by a remote store that does not refuse — must still never read as a
    # positive confirmation. The comparison below would match "genesis" against
    # "genesis" and return the one truthy verdict against ANY log, including one
    # truncated to almost nothing. "The witness saw nothing" is a no_record, not
    # a pass.
    if w_rows == 0:
        return _V("no_record",
                  "the witness pin for namespace %r was taken over an EMPTY log "
                  "(0 rows): it constrains nothing and cannot confirm this or any "
                  "other log. Re-pin against a non-empty head." % namespace,
                  witness_rows=0, witness_chain=w_chain, local_rows=local_rows)

    if local_rows < w_rows:
        return _V(
            "truncated",
            f"log has {local_rows} rows but the witness recorded {w_rows}: "
            f"{w_rows - local_rows} witnessed row(s) are missing (truncation)",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    local_chain_at = chain_at(ledger.path, w_rows)
    if local_chain_at is None:
        return _V(
            "truncated",
            f"cannot reach row {w_rows} in the log to compare against the witness",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    if local_chain_at != w_chain:
        return _V(
            "rewritten",
            f"log's chain at the witnessed row {w_rows} differs from the pin: "
            f"history was rewritten from at or before that point",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    grew = local_rows - w_rows
    detail = "log matches the witness at the witnessed row"
    if grew:
        detail += f" and has grown {grew} row(s) since (expected)"
    return _V("consistent", detail,
                          witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)
