"""K066: `evidence-pack --mandate FILE`, the mandate rows section.

For the window: the inside / outside / could-not-look counts, the mandate
file's sha256, and the outside rows verbatim, in mandate_rows.json (with the
mandate's bytes copied to mandate_file.json). Verify rebuilds the section
from records.jsonl, so an edit with its hashes fixed is still BROKEN.
"""
import hashlib
import http.client
import http.server
import json
import threading
import time
from pathlib import Path

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import (MANDATE_COPY, MANDATE_ROWS, build_pack)
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.record.ledger import Ledger

MANDATE = {"who": "pack-agent", "allowed_acts": ["echo"]}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _mandate(tmp_path, body=MANDATE) -> Path:
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


def _gated_ledger(tmp_path, mandate: Path, *, end=True) -> Path:
    """Rows shaped as proxy.py writes them for one gated session."""
    sha = _sha(mandate.read_bytes())
    p = tmp_path / "seam.jsonl"
    lg = Ledger(p)
    base = {"seam": "mcp_stdio", "session": "s-1", "server": "echo"}
    lg.append({**base, "evt": "session_begin", "seq": 1})
    lg.append({**base, "evt": "mandate_loaded", "seq": 2, "mandate": str(mandate),
               "mandate_status": "loaded", "mandate_file_sha256": sha,
               "mandate_mode": "record-only"})
    lg.append({**base, "evt": "tool_call", "seq": 3, "tool": "echo"})
    lg.append({**base, "evt": "mandate_outside", "seq": 4, "verdict": "outside",
               "rule": "allowed_acts", "reason": "refund is not an allowed act",
               "tool": "refund", "mandate_file_sha256": sha, "action": "forwarded"})
    lg.append({**base, "evt": "mandate_could_not_look", "seq": 5,
               "verdict": "could_not_look", "rule": "frame", "reason": "unparsed",
               "looked_for": "a JSON-RPC request", "where": "client stdin",
               "reason_word": "unreadable", "action": "forwarded"})
    if end:
        lg.append({**base, "evt": "session_end", "seq": 6, "reason": "eof",
                   "mandate_inside": 2, "mandate_outside": 1,
                   "mandate_could_not_look": 1})
    return p


def _m(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _rehash(out, *names):
    """Fix the manifest hash of `names` and manifest.sha256, to hide an edit."""
    m = _m(out)
    for n in names:
        m["files"][n] = _sha((out / n).read_bytes())
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    (out / "manifest.sha256").write_bytes(
        f"{_sha((out / 'manifest.json').read_bytes())}  manifest.json\n".encode("ascii"))


def test_counts_sha_and_outside_rows_verbatim(tmp_path):
    mandate = _mandate(tmp_path)
    ledger = _gated_ledger(tmp_path, mandate)
    out = tmp_path / "pack"
    res = build_pack(ledger, out, mandate=mandate)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0, res
    sec = json.loads((out / MANDATE_ROWS).read_text(encoding="utf-8"))
    assert sec["counts"] == {"inside": 2, "outside": 1, "could_not_look": 1}
    assert sec["mandate_file_sha256"] == _sha(mandate.read_bytes())
    assert sec["file_is_named"] is True and sec["sessions_without_end"] == []
    lines = ledger.read_bytes().split(b"\n")
    assert [r["line"] for r in sec["outside_rows"]] == [4]
    assert sec["outside_rows"][0]["raw"].encode("utf-8") == lines[3]
    assert [r["line"] for r in sec["could_not_look_rows"]] == [5]
    assert (out / MANDATE_COPY).read_bytes() == mandate.read_bytes()
    m = _m(out)
    assert m["mandate"]["counts"] == sec["counts"]
    assert m["mandate"]["mandate_file_sha256"] == sec["mandate_file_sha256"]
    for n in (MANDATE_ROWS, MANDATE_COPY):
        assert m["files"][n] == _sha((out / n).read_bytes())
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "## The mandate" in readme and "2 inside, 1 outside, 1" in readme
    assert not {"rate", "percent"} & (set(m["mandate"]) | set(m["mandate"]["counts"]))
    v = verify_pack(out)
    assert v["exit"] == 0, v
    assert next(c for c in v["checks"] if c["check"] == "mandate rows")["counts"] == \
        sec["counts"]


def test_changed_byte_in_mandate_rows_is_broken_naming_the_file(tmp_path):
    mandate = _mandate(tmp_path)
    out = tmp_path / "pack"
    build_pack(_gated_ledger(tmp_path, mandate), out, mandate=mandate)
    p = out / MANDATE_ROWS
    p.write_bytes(p.read_bytes().replace(b'"outside": 1', b'"outside": 0', 1))
    v = verify_pack(out)
    assert v["verdict"] == V.BROKEN and v["exit"] == 1
    assert MANDATE_ROWS in v["finding"]
    # the same edit with every hash fixed to hide it: the rebuild still catches it
    _rehash(out, MANDATE_ROWS)
    v = verify_pack(out)
    assert v["verdict"] == V.BROKEN and v["exit"] == 1
    assert f"{MANDATE_ROWS} differs from the section rebuilt" in v["finding"]


def test_dropped_outside_row_with_hashes_fixed_is_broken(tmp_path):
    mandate = _mandate(tmp_path)
    out = tmp_path / "pack"
    build_pack(_gated_ledger(tmp_path, mandate), out, mandate=mandate)
    p = out / MANDATE_ROWS
    sec = json.loads(p.read_text(encoding="utf-8"))
    sec["outside_rows"] = []
    sec["counts"]["outside"] = 0
    p.write_bytes((json.dumps(sec, indent=2) + "\n").encode("utf-8"))
    m = _m(out)
    m["mandate"]["counts"]["outside"] = 0
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    _rehash(out, MANDATE_ROWS)
    v = verify_pack(out)
    assert v["exit"] == 1 and MANDATE_ROWS in v["finding"]


def test_changed_byte_in_mandate_copy_is_broken(tmp_path):
    mandate = _mandate(tmp_path)
    out = tmp_path / "pack"
    build_pack(_gated_ledger(tmp_path, mandate), out, mandate=mandate)
    p = out / MANDATE_COPY
    p.write_bytes(p.read_bytes().replace(b"echo", b"echx"))
    v = verify_pack(out)
    assert v["exit"] == 1 and MANDATE_COPY in v["finding"]
    _rehash(out, MANDATE_COPY)
    v = verify_pack(out)
    assert v["exit"] == 1 and "mandate rows" in v["finding"]


def test_another_mandate_file_is_could_not_look(tmp_path):
    mandate = _mandate(tmp_path)
    ledger = _gated_ledger(tmp_path, mandate)
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"who": "x", "allowed_acts": ["*"]}), encoding="utf-8")
    out = tmp_path / "pack"
    res = build_pack(ledger, out, mandate=other)
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason_word"] == "name_not_found"
    cnl = json.loads((out / "could_not_look.json").read_text(encoding="utf-8"))
    assert [e["check"] for e in cnl] == ["mandate file is the one the gate loaded"]
    v = verify_pack(out)
    assert v["exit"] == 3 and v["verdict"] == V.COULD_NOT_LOOK


def test_hiding_the_could_not_look_is_broken(tmp_path):
    mandate = _mandate(tmp_path)
    ledger = _gated_ledger(tmp_path, mandate)
    other = tmp_path / "other.json"
    other.write_text("{}", encoding="utf-8")
    out = tmp_path / "pack"
    build_pack(ledger, out, mandate=other)
    m = _m(out)
    m["checks"] = [c for c in m["checks"] if not c["check"].startswith("mandate")]
    m["counts"]["could_not_look"] = 0
    m["verdict"], m["exit"] = V.VERIFIED, 0
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    (out / "could_not_look.json").write_text("[]\n", encoding="utf-8")
    _rehash(out, "could_not_look.json")
    v = verify_pack(out)
    assert v["exit"] == 1
    assert "mandate checks are not the ones" in v["finding"]


def test_session_end_outside_the_window_is_bounded(tmp_path):
    mandate = _mandate(tmp_path)
    out = tmp_path / "pack"
    res = build_pack(_gated_ledger(tmp_path, mandate, end=False), out, mandate=mandate)
    assert res["exit"] == 3 and res["reason_word"] == "bounded"
    sec = json.loads((out / MANDATE_ROWS).read_text(encoding="utf-8"))
    assert sec["sessions_without_end"] == ["s-1"] and sec["counts"]["inside"] == 0
    assert verify_pack(out)["exit"] == 3


def test_missing_mandate_file_is_could_not_look_never_zero(tmp_path):
    mandate = _mandate(tmp_path)
    ledger = _gated_ledger(tmp_path, mandate)
    out = tmp_path / "pack"
    res = build_pack(ledger, out, mandate=tmp_path / "nope.json")
    assert res["exit"] == 3 and res["reason_word"] == "missing"
    assert not (out / MANDATE_COPY).exists()
    assert _m(out)["mandate"]["copy"] is None
    assert verify_pack(out)["exit"] == 3


def test_cli_flag(tmp_path, capsys):
    mandate = _mandate(tmp_path)
    ledger = _gated_ledger(tmp_path, mandate)
    out = tmp_path / "pack"
    rc = evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(out),
                                 "--mandate", str(mandate), "--json"])
    res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["mandate"]["counts"]["outside"] == 1


class _Echo:
    def __init__(self):
        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "content": [{"type": "text", "text": "ok"}]}}).encode()
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _post(port, i, tool):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    c.request("POST", "/", body=json.dumps({
        "jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": tool, "arguments": {"text": f"c{i}"}}}).encode(),
        headers={"Content-Type": "application/json"})
    reply = json.loads(c.getresponse().read())
    c.close()
    return reply


def test_real_gated_session_through_http_forward(tmp_path):
    """A real record-only session: two inside calls and one outside."""
    from arcaeon.record.adapter import http_forward as HF
    mandate = _mandate(tmp_path)
    ledger = tmp_path / "http.seam.jsonl"
    up = _Echo()
    try:
        srv = HF.build_forward_server(up.url, ledger_path=ledger,
                                      mandate_path=mandate).start()
        try:
            _post(srv.port, 1, "echo")
            _post(srv.port, 2, "refund")
            _post(srv.port, 3, "echo")
            time.sleep(0.3)          # record-only judges after forwarding
        finally:
            srv.close()
    finally:
        up.close()
    out = tmp_path / "pack"
    res = build_pack(ledger, out, mandate=mandate)
    sec = json.loads((out / MANDATE_ROWS).read_text(encoding="utf-8"))
    assert sec["counts"] == {"inside": 2, "outside": 1, "could_not_look": 0}, sec
    assert json.loads(sec["outside_rows"][0]["raw"])["tool"] == "refund"
    assert sec["file_is_named"] is True
    assert verify_pack(out)["exit"] == res["exit"]
