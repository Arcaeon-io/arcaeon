"""approval_mcp.py driven as a real subprocess over stdin/stdout, the way an
MCP host actually talks to it. Covers: the protocol handshake, the refusal
that is the whole point (no executing a still-pending proposal), the decision
channel (a dropped file is the only way a decision happens), the three
approve/deny x match/mismatch receipt outcomes, a rejected (empty-principal)
decision file, and that a restart does not lose a pending proposal."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from arcaeon.record.receipt.core import load_receipt, verify_receipt

TOOL_NAMES = {"approval_propose", "approval_status", "approval_executed", "approval_list_pending"}


def _cmd(dirs: dict) -> list:
    return [sys.executable, "-m", "arcaeon.record.receipt.approval_mcp",
            "--ledger", str(dirs["ledger"]),
            "--decisions-dir", str(dirs["decisions"]),
            "--receipts-dir", str(dirs["receipts"]),
            "--state", str(dirs["state"]),
            "--agent", "test-agent"]


def _dirs(tmp_path: Path) -> dict:
    return {"ledger": tmp_path / "approval.log.jsonl",
            "decisions": tmp_path / "decisions",
            "receipts": tmp_path / "receipts",
            "state": tmp_path / "approval_state.json"}


class Client:
    """Minimal JSON-RPC-over-stdio driver for one subprocess."""

    def __init__(self, cmd: list):
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, bufsize=1)
        self._id = 0

    def _send(self, obj: dict) -> None:
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read()
            raise AssertionError(f"no response from server (method={method}); stderr:\n{err}")
        return json.loads(line)

    def call(self, name: str, arguments: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})["result"]

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)


def _payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def _decide(dirs: dict, proposal_id: str, principal, decision, note: str = "") -> None:
    dirs["decisions"].mkdir(parents=True, exist_ok=True)
    (dirs["decisions"] / f"{proposal_id}.json").write_text(
        json.dumps({"principal": principal, "decision": decision, "note": note}), encoding="utf-8")


def test_initialize_and_tools_list(tmp_path):
    dirs = _dirs(tmp_path)
    c = Client(_cmd(dirs))
    try:
        init = c.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "test", "version": "0"}})
        assert init["result"]["protocolVersion"] == "2025-06-18"
        assert init["result"]["serverInfo"]["name"] == "approval"

        listed = c.request("tools/list")
        names = {t["name"] for t in listed["result"]["tools"]}
        assert names == TOOL_NAMES

        # a notification (no id) draws no reply at all
        c._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        # prove the connection is still alive and answering ordinary requests
        again = c.request("tools/list")
        assert {t["name"] for t in again["result"]["tools"]} == TOOL_NAMES
    finally:
        c.close()


def test_never_crashes_on_a_bad_call(tmp_path):
    dirs = _dirs(tmp_path)
    c = Client(_cmd(dirs))
    try:
        resp = c.request("tools/call", {"name": "approval_propose", "arguments": {"action": "not-an-object"}})
        assert resp["result"]["isError"] is True
        # server is still alive afterward
        again = c.request("tools/list")
        assert {t["name"] for t in again["result"]["tools"]} == TOOL_NAMES

        unknown = c.call("nonexistent_tool", {})
        assert unknown["isError"] is True
    finally:
        c.close()


def test_agent_cannot_self_approve_via_tool_arguments(tmp_path):
    """A-025: the decision channel is ONLY the dropped file in --decisions-dir.
    Neither approval_propose's nor approval_executed's inputSchema has a
    `principal`/`decision` field at all, and neither `_approval_propose` nor
    `_approval_executed` reads one out of `args` even if the caller sends
    it. So an agent that tries to smuggle a decision straight through the
    tool call -- passing `principal`/`decision` alongside the real
    arguments, instead of writing a file -- must have zero effect: the
    proposal stays exactly as pending as if those extra keys were never
    sent, and approval_executed is still refused."""
    dirs = _dirs(tmp_path)
    c = Client(_cmd(dirs))
    action = {"kind": "payment", "amount": "9001.00", "to": "attacker-controlled"}
    try:
        proposed = _payload(c.call("approval_propose", {"action": action}))
        proposal_id = proposed["proposal_id"]

        # Attempt to self-approve by stuffing decision fields into the SAME
        # tool call's arguments -- no file ever written to decisions_dir.
        sneaky = c.call("approval_executed", {
            "proposal_id": proposal_id,
            "executed_action": action,
            "principal": "the-agent-itself",
            "decision": "approved",
        })
        assert sneaky.get("isError") is True
        assert "still pending a decision" in _payload(sneaky)["error"]

        # confirm the extra keys did not quietly get treated as a decision:
        # status is still pending, and no decisions-dir side effects exist.
        status = _payload(c.call("approval_status", {"proposal_id": proposal_id}))
        assert status["status"] == "pending"
        assert "principal" not in status
        assert not dirs["decisions"].exists() or not list(dirs["decisions"].glob("*.json"))

        # trying it on approval_propose too -- decision fields there are
        # just ignored extra data, never a way to pre-approve one's own
        # proposal at creation time.
        proposed2 = _payload(c.call("approval_propose", {
            "action": action, "principal": "the-agent-itself", "decision": "approved"}))
        status2 = _payload(c.call("approval_status", {"proposal_id": proposed2["proposal_id"]}))
        assert status2["status"] == "pending"

        # the only real path still works: a file dropped in decisions_dir.
        _decide(dirs, proposal_id, "daniel", "approved")
        now_approved = _payload(c.call("approval_status", {"proposal_id": proposal_id}))
        assert now_approved["status"] == "approved"
        assert now_approved["principal"] == "daniel"
    finally:
        c.close()


def test_full_approval_lifecycle_and_state_survives_restart(tmp_path):
    dirs = _dirs(tmp_path)
    c = Client(_cmd(dirs))
    action = {"kind": "payment", "amount": "49.00", "to": "vendor"}

    try:
        # -- propose ----------------------------------------------------
        proposed = _payload(c.call("approval_propose", {"action": action}))
        assert proposed["status"] == "pending"
        assert proposed["action_digest"]
        proposal_id = proposed["proposal_id"]

        # -- executed-while-pending is refused ---------------------------
        # A-007: the exact refusal text (not just isError/a substring), so a
        # future edit that keeps "pending" in some unrelated message can't
        # slide past this test -- this is THE refusal the whole gate exists
        # for (approval_mcp.py's _approval_executed).
        refused = c.call("approval_executed", {"proposal_id": proposal_id, "executed_action": action})
        assert refused.get("isError") is True
        assert _payload(refused)["error"] == (
            f"proposal {proposal_id!r} is still pending a decision; "
            "refusing to record execution before one is recorded")

        # -- a human decides, out of band ---------------------------------
        _decide(dirs, proposal_id, "daniel", "approved", note="ok")

        # -- status picks the decision up and shows it -------------------
        status = _payload(c.call("approval_status", {"proposal_id": proposal_id}))
        assert status["status"] == "approved"
        assert status["principal"] == "daniel"
        assert status["decided_at"]
        assert (dirs["decisions"] / "applied" / f"{proposal_id}.json").exists()
        assert not (dirs["decisions"] / f"{proposal_id}.json").exists()

        # -- executed with the SAME action: as approved, receipt verifies
        ex = _payload(c.call("approval_executed", {"proposal_id": proposal_id, "executed_action": action}))
        assert ex["executed_as_approved"] is True
        receipt = load_receipt(ex["receipt_path"])
        assert receipt["body_digest"] == ex["receipt_body_digest"]
        v = verify_receipt(receipt, ledger_path=dirs["ledger"])
        assert v["ok"], v

        # -- second proposal: approve, then execute a DIFFERENT action --
        action2 = {"kind": "payment", "amount": "49.00", "to": "vendor-two"}
        p2 = _payload(c.call("approval_propose", {"action": action2}))
        pid2 = p2["proposal_id"]
        _decide(dirs, pid2, "daniel", "approved")
        mismatched = {"kind": "payment", "amount": "4900.00", "to": "vendor-two"}
        ex2 = _payload(c.call("approval_executed", {"proposal_id": pid2, "executed_action": mismatched}))
        assert ex2["executed_as_approved"] is False
        v2 = verify_receipt(load_receipt(ex2["receipt_path"]), ledger_path=dirs["ledger"])
        assert v2["ok"], v2

        # -- third proposal: deny, then null (honored) then the action (not)
        action3 = {"kind": "payment", "amount": "10.00", "to": "vendor-three"}
        p3 = _payload(c.call("approval_propose", {"action": action3}))
        pid3 = p3["proposal_id"]
        _decide(dirs, pid3, "daniel", "denied", note="no")
        ex3a = _payload(c.call("approval_executed", {"proposal_id": pid3, "executed_action": None}))
        assert ex3a["executed_as_approved"] is True
        ex3b = _payload(c.call("approval_executed", {"proposal_id": pid3, "executed_action": action3}))
        assert ex3b["executed_as_approved"] is False
        assert ex3a["receipt_path"] != ex3b["receipt_path"]

        # -- empty-principal decision file: rejected, proposal stays pending
        action4 = {"kind": "payment", "amount": "1.00", "to": "vendor-four"}
        p4 = _payload(c.call("approval_propose", {"action": action4}))
        pid4 = p4["proposal_id"]
        _decide(dirs, pid4, "", "approved")
        still = _payload(c.call("approval_status", {"proposal_id": pid4}))
        assert still["status"] == "pending"
        assert (dirs["decisions"] / "rejected" / f"{pid4}.json").exists()
        assert not (dirs["decisions"] / f"{pid4}.json").exists()

        pending_list = _payload(c.call("approval_list_pending", {}))
        pending_ids = {p["proposal_id"] for p in pending_list}
        assert pending_ids == {pid4}
    finally:
        c.close()

    # -- restart: the still-pending proposal survives via --state --------
    c2 = Client(_cmd(dirs))
    try:
        after_restart = _payload(c2.call("approval_status", {"proposal_id": pid4}))
        assert after_restart["status"] == "pending"
        decided_after_restart = _payload(c2.call("approval_status", {"proposal_id": proposal_id}))
        assert decided_after_restart["status"] == "approved"
        assert decided_after_restart["principal"] == "daniel"
    finally:
        c2.close()
