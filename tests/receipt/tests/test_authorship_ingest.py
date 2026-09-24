"""Tests for the Authorship Receipt ingest path: an export built by hand
(typed words, one paste, one delete, one idle gap), replayed through
from_export, checked for count parity, rolling-hash parity against
authorship.replay, receipt verification, and that no span text or final
text ever appears in the issued receipt JSON. Also a JS/Python fold-parity
check against the recorder page's own fold function, run under Node when
available."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from arcaeon.record.ledger import digest_bytes

from arcaeon.record.receipt import authorship, verify_receipt
from arcaeon.record.receipt.authorship_ingest import from_export, main, verify_export

WEB_HTML = Path(__file__).parent.parent / "web" / "authorship-recorder.html"


def _build_export():
    """Hand-built export: three typed words, one paste, one delete, one
    idle gap (60+ seconds), matching the schema authorship-recorder.html
    produces."""
    events = []

    def add(op, n, ts, text=None):
        ev = {"seq": len(events) + 1, "op": op, "n": n, "ts": ts}
        if text is not None:
            ev["span_digest"] = digest_bytes(text.encode("utf-8"))
        events.append(ev)

    add("type", 4, "2026-09-11T08:00:00Z", "The ")
    add("type", 6, "2026-09-11T08:00:01Z", "quick ")
    add("type", 6, "2026-09-11T08:00:02Z", "brown ")
    add("paste", 4, "2026-09-11T08:00:03Z", "fox ")
    add("idle", 75, "2026-09-11T08:01:18Z")            # 75-second gap, no span_digest
    add("delete", 1, "2026-09-11T08:01:19Z")            # deletion, no span_digest
    add("type", 1, "2026-09-11T08:01:20Z", " ")

    final_text = "The quick brown fox "
    rolling_hash = authorship.replay(events)
    return {
        "author": "student-a",
        "document": "essay draft",
        "started_at": "2026-09-11T08:00:00Z",
        "events": events,
        "final_text": final_text,
        "rolling_hash": rolling_hash,
    }, events


def test_from_export_counts_and_rolling_hash_parity(tmp_path):
    export, events = _build_export()
    rc = from_export(export, ledger_path=tmp_path / "writing.log.jsonl")

    check = rc["checks"][0]
    assert check["typed_chars"] == 4 + 6 + 6 + 1     # three type events + the trailing space
    assert check["pasted_chars"] == 4
    assert check["paste_events"] == 1
    assert check["deleted_chars"] == 1
    assert check["events"] == len(events)

    expected_rolling = authorship.replay(events)
    assert check["rolling_hash"] == expected_rolling
    assert rc["extra"]["ingest"] == "replayed-export"
    assert rc["extra"]["export_rolling_hash_matches"] is True


def test_from_export_receipt_verifies(tmp_path):
    export, _ = _build_export()
    ledger_path = tmp_path / "writing.log.jsonl"
    rc = from_export(export, ledger_path=ledger_path, anchor=False)
    res = verify_receipt(rc, ledger_path=ledger_path)
    assert res["ok"], res


def test_from_export_never_leaks_spans_or_final_text(tmp_path):
    export, _ = _build_export()
    rc = from_export(export, ledger_path=tmp_path / "writing.log.jsonl", anchor=False)
    blob = json.dumps(rc)
    for leaked in ("The quick brown fox", "quick", "brown"):
        assert leaked not in blob
    # only the digest of the final text may appear
    assert digest_bytes(export["final_text"].encode("utf-8")) in blob


def test_from_export_flags_tampered_export(tmp_path):
    export, _ = _build_export()
    export = dict(export)
    export["rolling_hash"] = "sha256:not-the-real-hash"
    rc = from_export(export, ledger_path=tmp_path / "writing.log.jsonl", anchor=False)
    assert rc["extra"]["export_rolling_hash_matches"] is False


def test_verify_export_standalone(tmp_path):
    export, _ = _build_export()
    res = verify_export(export)
    assert res["ok"] is True and res["computed_rolling_hash"] == export["rolling_hash"]

    tampered = dict(export)
    tampered["rolling_hash"] = "sha256:nope"
    assert verify_export(tampered)["ok"] is False


def test_paste_then_immediate_edit_does_not_collapse_into_one_event(tmp_path):
    """A-008: a paste followed immediately (same millisecond-ish timestamp,
    zero idle gap) by a typed edit must still be recorded as two distinct
    events, not folded/merged into one. Neither authorship.py's
    AuthorshipSession.event() nor authorship_ingest.from_export()'s replay
    loop has any coalescing logic -- every call appends its own dict with
    the next `seq` unconditionally -- but that is worth a regression test:
    a future "helpful" adjacency-merge optimization would silently corrupt
    the typed/pasted character counts and the ballot the receipt shows."""
    events = [
        {"seq": 1, "op": "paste", "n": 4, "ts": "2026-09-12T08:00:00Z",
         "span_digest": digest_bytes("fox ".encode("utf-8"))},
        # immediate follow-on edit: same timestamp, right after the paste,
        # exactly the shape that a merge-adjacent-same-source optimization
        # would be tempted to coalesce with the paste above.
        {"seq": 2, "op": "type", "n": 1, "ts": "2026-09-12T08:00:00Z",
         "span_digest": digest_bytes("!".encode("utf-8"))},
    ]
    export = {
        "author": "student-a", "document": "essay", "started_at": "2026-09-12T08:00:00Z",
        "final_text": "fox !", "events": events,
        "rolling_hash": authorship.replay(events),
    }
    rc = from_export(export, ledger_path=tmp_path / "writing.log.jsonl", anchor=False)
    check = rc["checks"][0]
    # two events in, two events out -- neither absorbed the other.
    assert check["events"] == 2
    assert check["pasted_chars"] == 4
    assert check["typed_chars"] == 1
    assert check["paste_events"] == 1
    assert len(events) == 2  # the source list itself was never mutated/merged
    assert rc["extra"]["export_rolling_hash_matches"] is True


def test_cli_main(tmp_path):
    export, _ = _build_export()
    export_path = tmp_path / "session.authorship-export.json"
    export_path.write_text(json.dumps(export), encoding="utf-8")
    out = tmp_path / "receipt.json"
    rc = main(["--ledger", str(tmp_path / "writing.log.jsonl"), "--out", str(out),
              "--no-anchor", str(export_path)])
    assert rc == 0 and out.exists()

    tampered = dict(export)
    tampered["rolling_hash"] = "sha256:nope"
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    rc2 = main(["--ledger", str(tmp_path / "writing2.log.jsonl"), "--out", str(tmp_path / "r2.json"),
               "--no-anchor", str(tampered_path)])
    assert rc2 == 2


def test_rolling_hash_avalanches_on_a_single_character_edit():
    """A-023: authorship.py's rolling hash (`_fold`, sha256-based) must not
    let a single-character change in one event's span text produce a
    rolling_hash that only differs in a trailing character or two -- that
    would mean the fold is not actually mixing the whole prior chain into
    each new digest, and a forger could hunt for a near-collision. Two
    otherwise-identical event streams, differing by exactly one character
    in the second event's pasted text (so exactly one span_digest differs),
    must produce a rolling_hash that differs in a large share of its hex
    characters, not just at the tail."""
    def _events(second_word: str):
        return [
            {"seq": 1, "op": "type", "n": 4, "ts": "2026-09-13T00:00:00Z",
             "span_digest": digest_bytes("The ".encode("utf-8"))},
            {"seq": 2, "op": "paste", "n": len(second_word), "ts": "2026-09-13T00:00:01Z",
             "span_digest": digest_bytes(second_word.encode("utf-8"))},
        ]

    hash_a = authorship.replay(_events("quick"))
    hash_b = authorship.replay(_events("quicm"))  # one character different

    assert hash_a != hash_b
    # avalanche sanity, not a strict statistical test: sha256 hex digests
    # that differ by only one input character should differ across roughly
    # half their hex characters, not merely at the position closest to the
    # edit. A near-collision (only a handful of hex chars differing) would
    # mean the fold is not really chaining the prior hash into the new one.
    differing = sum(1 for x, y in zip(hash_a, hash_b) if x != y)
    assert differing > len(hash_a) // 4, (
        f"only {differing}/{len(hash_a)} hex chars differ between {hash_a!r} and {hash_b!r}; "
        "expected an avalanche, not a near-collision")

    # and the same property holds one level up, through the full ingest
    # path (from_export), not just the bare replay helper.
    export_a = {"author": "a", "document": "d", "started_at": "2026-09-13T00:00:00Z",
                "events": _events("quick"), "final_text": "The quick",
                "rolling_hash": hash_a}
    export_b = {"author": "a", "document": "d", "started_at": "2026-09-13T00:00:00Z",
                "events": _events("quicm"), "final_text": "The quicm",
                "rolling_hash": hash_b}
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        rc_a = from_export(export_a, ledger_path=Path(td) / "a.jsonl", anchor=False)
        rc_b = from_export(export_b, ledger_path=Path(td) / "b.jsonl", anchor=False)
    assert rc_a["checks"][0]["rolling_hash"] != rc_b["checks"][0]["rolling_hash"]


def test_from_export_handles_zero_events_without_raising(tmp_path):
    """A-030: an export with an empty edit stream (a session opened and
    closed with no keystrokes at all -- e.g. a recorder started, then the
    tab was closed) must produce a valid, verifiable receipt, not a
    ZeroDivisionError (pasted_share divides by typed+pasted) or any other
    exception."""
    export = {
        "author": "student-a", "document": "empty draft",
        "started_at": "2026-09-13T00:00:00Z",
        "events": [],
        "final_text": "",
        "rolling_hash": authorship.replay([]),
    }
    rc = from_export(export, ledger_path=tmp_path / "writing.log.jsonl", anchor=False)
    check = rc["checks"][0]
    assert check["events"] == 0
    assert check["typed_chars"] == 0 and check["pasted_chars"] == 0
    assert check["pasted_share"] is None  # guarded, not a ZeroDivisionError
    assert check["final_text_chars"] == 0
    assert rc["extra"]["export_rolling_hash_matches"] is True

    res = verify_receipt(rc, ledger_path=tmp_path / "writing.log.jsonl")
    assert res["ok"], res


def test_js_fold_matches_python_fold(tmp_path):
    """Extract the fold function verbatim from the recorder page and run it
    under Node on three vectors, comparing against authorship._fold."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH; cannot check JS/Python fold parity")

    src = WEB_HTML.read_text(encoding="utf-8")
    start_marker, end_marker = "// FOLD-START", "// FOLD-END"
    if start_marker not in src or end_marker not in src:
        pytest.skip("FOLD-START/FOLD-END markers not found in authorship-recorder.html")
    start = src.index(start_marker)
    end = src.index(end_marker) + len(end_marker)
    js_fold_code = src[start:end]

    vectors = [
        {"seq": 1, "op": "type", "n": 3, "ts": "2026-09-11T08:00:00Z",
         "span_digest": digest_bytes("The".encode("utf-8"))},
        {"seq": 2, "op": "paste", "n": 9, "ts": "2026-09-11T08:00:05Z",
         "span_digest": digest_bytes("brown fox".encode("utf-8"))},
        {"seq": 3, "op": "delete", "n": 4, "ts": "2026-09-11T08:00:10Z"},
    ]
    expected = []
    prev = "genesis"
    for ev in vectors:
        prev = authorship._fold(prev, ev)
        expected.append(prev)

    wrapper = js_fold_code + """
const vectors = JSON.parse(process.argv[2]);
(async () => {
  let prev = "genesis";
  const outs = [];
  for (const ev of vectors) {
    prev = await foldEvent(prev, ev);
    outs.push(prev);
  }
  console.log(JSON.stringify(outs));
})();
"""
    script = tmp_path / "fold_check.js"
    script.write_text(wrapper, encoding="utf-8")
    result = subprocess.run([node, str(script), json.dumps(vectors)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    got = json.loads(result.stdout.strip())
    assert got == expected
