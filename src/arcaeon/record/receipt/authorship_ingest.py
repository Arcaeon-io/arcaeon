"""Ingest an exported authorship session (from web/authorship-recorder.html)
into an Authorship Receipt.

The exported file carries the events the browser already folded into a
rolling hash (span text digested, never stored). `authorship.AuthorshipSession
.event()` only attaches a `span_digest` to an event when it is given the raw
`text` (it computes the digest itself); it has no way to accept a digest that
was already computed elsewhere. So replaying an export through `session.event
(op, n, ts=ts)` -- the only inputs an export actually carries -- produces a
rolling hash that is missing `span_digest` on every type/paste event, and it
will NOT match the hash the browser page displayed and exported.

authorship.py is out of scope here (not ours to edit), and it does not
support injecting a precomputed span_digest into `event()`. So this module
takes the second path the spec calls for: it still replays every event
through `session.event()` to get real counts (typed/pasted/deleted chars,
paste events, checkpoints, ledger rows) exactly as a live session would, but
the receipt's certified `rolling_hash` is the value independently recomputed
with `authorship.replay(events)` over the *export's own* event dicts (which
do carry span_digest) -- the same computation `verify_export` performs
standalone. Whether that recomputed hash matches the export's own declared
`rolling_hash` is recorded in the receipt as
`extra = {"ingest": "replayed-export", "export_rolling_hash_matches": bool}`,
so a reader can see, on the receipt's face, that the certified hash is a
replay of the export, not a live fold, and whether the export was internally
consistent.

Because `AuthorshipSession.close()` has no way to carry that `extra` block
through to the underlying receipt, this module does not call `close()`.
Instead it finishes the session with the same final checkpoint `close()`
would append (`session._checkpoint("close")`, the ledger-side half of
`close()`) and builds the check/subject exactly as `close()` does, then
calls `core.build_receipt()` directly so the `extra` block is baked into the
body before the digest is computed and before the ledger row is appended --
never patched on afterward, which would desync the body digest from the
ledgered one.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Union

from arcaeon.record.ledger import digest_bytes

from . import authorship
from .core import build_receipt, save_receipt


def _load(path_or_dict: Union[str, Path, dict]) -> dict:
    if isinstance(path_or_dict, dict):
        return path_or_dict
    return json.loads(Path(path_or_dict).read_text(encoding="utf-8"))


def verify_export(path_or_dict: Union[str, Path, dict]) -> dict:
    """Recompute the rolling hash from an export's own events and compare it
    to the `rolling_hash` the export declares. Typed result, never raises on
    a malformed export -- it reports what it could not check."""
    try:
        data = _load(path_or_dict)
    except (OSError, ValueError) as e:
        return {"ok": False, "computed_rolling_hash": None, "declared_rolling_hash": None,
                "events": 0, "note": f"could not load export: {e}"}
    events = data.get("events") or []
    declared = data.get("rolling_hash")
    computed = authorship.replay(events)
    return {"ok": computed == declared, "computed_rolling_hash": computed,
            "declared_rolling_hash": declared, "events": len(events)}


def from_export(path_or_dict: Union[str, Path, dict], *, ledger_path: Union[str, Path],
                namespace: str = "authorship", witness: bool = True, anchor: bool = True) -> dict:
    """Rebuild an AuthorshipSession from an export and issue its receipt.
    See module docstring for why the certified rolling_hash is a replay of
    the export rather than a live fold, and why `close()` is not called."""
    data = _load(path_or_dict)
    events = data.get("events") or []
    author = data.get("author") or ""
    document = data.get("document") or ""
    final_text = data.get("final_text") or ""
    declared_rolling = data.get("rolling_hash")

    session = authorship.AuthorshipSession(ledger_path, namespace=namespace,
                                           author=author, document=document)
    if data.get("started_at"):
        # The export knows when the real writing session began; the session
        # object was just constructed now, during ingest. Keep the subject
        # honest about when the WRITING happened, not when it was replayed.
        session.started_at = data["started_at"]

    for ev in events:
        session.event(ev.get("op"), ev.get("n", 0), ts=ev.get("ts"))

    true_rolling = authorship.replay(events)
    matches = true_rolling == declared_rolling

    session._checkpoint("close")  # the ledger-side half of AuthorshipSession.close()

    total_in = session.typed + session.pasted
    check = {
        "session": session.session_id,
        "events": session.events,
        "first_event": session.first_ts,
        "last_event": session.last_ts,
        "typed_chars": session.typed,
        "pasted_chars": session.pasted,
        "paste_events": session.paste_events,
        "deleted_chars": session.deleted,
        "pasted_share": round(session.pasted / total_in, 3) if total_in else None,
        "final_text_sha256": digest_bytes(final_text.encode("utf-8")),
        "final_text_chars": len(final_text),
        "rolling_hash": true_rolling,
        "checkpoints": session.checkpoints,
    }
    subject = {"author": session.author or "(asserted name absent)",
               "document": session.document or "(untitled)",
               "session": session.session_id, "started_at": session.started_at}
    extra = {"ingest": "replayed-export", "export_rolling_hash_matches": matches}
    return build_receipt(authorship.KIND, subject, [check], authorship.SCOPE,
                         ledger_path=session.ledger_path, namespace=session.namespace,
                         extra=extra, witness=witness, anchor=anchor)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="arcaeon-receipt-authorship-ingest",
                                 description="Turn an authorship-recorder.html export into an Authorship Receipt.")
    ap.add_argument("export", help="path to the exported *.authorship-export.json")
    ap.add_argument("--ledger", default="writing.log.jsonl")
    ap.add_argument("--namespace", default="authorship")
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-anchor", action="store_true")
    ap.add_argument("--no-witness", action="store_true")
    a = ap.parse_args(argv)

    try:
        rc = from_export(a.export, ledger_path=a.ledger, namespace=a.namespace,
                         witness=not a.no_witness, anchor=not a.no_anchor)
    except (OSError, ValueError, KeyError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1

    out = a.out or (Path(a.export).stem + ".receipt.json")
    save_receipt(rc, out)
    print(authorship.exhibit(rc))
    print(f"receipt written: {out}")
    if not rc["extra"]["export_rolling_hash_matches"]:
        print("warning: export's declared rolling_hash did not match its own events", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
