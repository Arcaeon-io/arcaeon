# SPDX-License-Identifier: MIT
"""Approval Receipt MCP server — the decision never comes from the agent.

Zero dependencies beyond arcaeon-ledger: MCP is JSON-RPC 2.0 over stdio, so
this speaks it directly (same house style as arcaeon-ledger's
arcaeon_ledger/mcp_server.py: initialize, tools/list, tools/call;
notifications get no reply; nothing a caller sends ever crashes the process).

TOOLS:

  approval_propose(action)                       -> {proposal_id, action_digest, status:"pending"}
      Proposes an action for human review. Nothing runs yet.
  approval_status(proposal_id)                    -> {status, principal?, decided_at?}
      status is pending / approved / denied.
  approval_executed(proposal_id, executed_action, outcome?)
                                                   -> {receipt_body_digest, executed_as_approved, receipt_path}
      Closes the loop and writes the Approval Receipt. REFUSED (isError) while
      the proposal is still pending — an agent that could run first and ask
      later would make the whole gate theatre. executed_action is the action
      that actually ran, or null if it did not run at all (the correct shape
      for a denial that was honored).
  approval_list_pending()                         -> [ {proposal_id, action_digest, action_kind, proposed_at, proposer}, ... ]

THE DECISION CHANNEL. The agent never decides. A human (or a Telegram bot, or
a web form, today or later) drops a file `<decisions-dir>/<proposal_id>.json`:

    {"principal": "dana", "decision": "approved", "note": "looks right"}

This server never watches for that file on its own — it has no background
thread and no timer. It picks up pending decision files at the top of every
approval_status / approval_executed / approval_list_pending call (so the very
next thing a caller does after learning a decision might exist sees it), runs
it through ApprovalGate.decide, and moves the file to
`<decisions-dir>/applied/`. A decision file that cannot be honored — empty
principal, an unknown proposal id, a decision that is neither "approved" nor
"denied", a proposal that already has a decision, or a file that isn't even
valid JSON — is moved to `<decisions-dir>/rejected/` instead: refused, named,
and out of the retry loop, and the proposal stays exactly as it was.

STATE. Every proposal (and, once decided, who decided it and how) lives in
`--state`, a plain JSON file rewritten atomically after every change. A
restarted server reads it back and the pending item is still pending —
ApprovalGate's propose/decide/executed are pure functions of the dict they're
handed, so nothing about resuming depends on any in-memory object surviving
the restart.

Run:  python -m arcaeon.record.receipt.approval_mcp --ledger approval.log.jsonl \
        --decisions-dir decisions --receipts-dir receipts \
        --state approval_state.json --agent billing-agent
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .approval import ApprovalGate
from .core import save_receipt

PROTOCOL_VERSION = "2025-06-18"


class _ToolError(ValueError):
    """A caller-fixable argument or sequencing problem. Becomes isError:true."""


# --------------------------------------------------------------------------
# state: {"proposals": {proposal_id: {"proposal": {...}, "status": "...",
#                                      "executions": N}}}
# --------------------------------------------------------------------------

def _empty_state() -> dict:
    return {"proposals": {}}


def _load_state(path: Path) -> dict:
    if not path.exists():
        return _empty_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # A corrupt or half-written state file must not crash the server on
        # boot; start clean rather than refuse to serve at all. The ledger
        # itself is the durable record of what actually happened.
        return _empty_state()
    if not isinstance(data, dict) or not isinstance(data.get("proposals"), dict):
        return _empty_state()
    return data


def _save_state(path: Path, state: dict) -> None:
    """Atomic write: temp file + os.replace, so a crash mid-write never
    leaves --state holding half a JSON document a restart cannot parse."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(state, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# the decision channel
# --------------------------------------------------------------------------

def _quarantine(f: Path, dest_dir: Path, reason: str = "") -> None:
    """Move a decision file aside. A rejection carries its reason in a
    sidecar (<name>.reason.txt) so the human who wrote the file can see why
    it did not take; a quarantine with no reason is a silent no."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f.name
    if target.exists():
        target = dest_dir / f"{f.stem}.{int(time.time() * 1000)}{f.suffix}"
    if reason:
        try:
            (dest_dir / (target.name + ".reason.txt")).write_text(reason[:300] + "\n", encoding="utf-8")
        except OSError:
            pass
    try:
        f.replace(target)
    except OSError:
        pass  # best-effort; a decision file we can't move is not fatal


def _process_decisions(state: dict, decisions_dir: Path, gate: ApprovalGate) -> bool:
    """Apply every pending decision file sitting in decisions_dir. Returns
    True if state changed (caller then persists it). Never raises: a
    malformed or unhandleable decision file is quarantined to rejected/,
    never left to crash a tool call or loop forever."""
    if not decisions_dir.is_dir():
        return False
    applied_dir = decisions_dir / "applied"
    rejected_dir = decisions_dir / "rejected"
    changed = False
    for f in sorted(decisions_dir.glob("*.json")):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _quarantine(f, rejected_dir, "unparseable_json")
            continue
        if not isinstance(raw, dict):
            _quarantine(f, rejected_dir, "not_an_object")
            continue
        proposal_id = f.stem
        rec = state["proposals"].get(proposal_id)
        if rec is None or rec.get("status") != "pending":
            # Unknown proposal, or one that already has a decision: a second
            # decision file for the same id must not silently re-decide it.
            _quarantine(f, rejected_dir, "unknown_proposal" if rec is None else "already_decided")
            continue
        principal = raw.get("principal")
        decision = raw.get("decision")
        note = raw.get("note", "")
        if not isinstance(principal, str) or not principal.strip():
            # "Refuse a decision file whose principal is empty." Left pending,
            # the file quarantined so it is not retried forever.
            _quarantine(f, rejected_dir, "empty_principal")
            continue
        if not isinstance(note, str):
            note = str(note)
        try:
            updated = gate.decide(rec["proposal"], principal=principal,
                                   decision=decision, note=note)
        except (ValueError, TypeError, KeyError) as e:
            # decision not in ("approved","denied"), or anything else
            # malformed about the file's shape. ApprovalGate prefixes its
            # ValueErrors (bad_decision: / empty_principal:) for this line.
            _quarantine(f, rejected_dir, str(e))
            continue
        rec["proposal"] = updated
        rec["status"] = updated["decision"]
        changed = True
        _quarantine(f, applied_dir)
    return changed


# --------------------------------------------------------------------------
# the four tools
# --------------------------------------------------------------------------

def _approval_propose(args: dict, gate: ApprovalGate, state: dict) -> dict:
    action = args.get("action")
    if not isinstance(action, dict):
        raise _ToolError(f"action must be a JSON object, got {type(action).__name__}")
    proposal = gate.propose(action)
    proposal_id = uuid.uuid4().hex
    state["proposals"][proposal_id] = {"proposal": proposal, "status": "pending", "executions": 0}
    return {"proposal_id": proposal_id, "action_digest": proposal["action_digest"], "status": "pending"}


def _approval_status(args: dict, state: dict) -> dict:
    proposal_id = args.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id:
        raise _ToolError("proposal_id must be a non-empty string")
    rec = state["proposals"].get(proposal_id)
    if rec is None:
        raise _ToolError(f"no such proposal_id: {proposal_id!r}")
    out = {"status": rec["status"]}
    p = rec["proposal"]
    if rec["status"] != "pending":
        out["principal"] = p.get("principal")
        out["decided_at"] = p.get("decided_at")
    return out


def _approval_list_pending(state: dict) -> list:
    out = []
    for proposal_id, rec in state["proposals"].items():
        if rec.get("status") != "pending":
            continue
        p = rec["proposal"]
        out.append({"proposal_id": proposal_id, "action_digest": p.get("action_digest"),
                    "action_kind": p.get("action_kind"), "proposed_at": p.get("proposed_at"),
                    "proposer": p.get("proposer")})
    return out


def _approval_executed(args: dict, gate: ApprovalGate, state: dict, receipts_dir: Path) -> dict:
    proposal_id = args.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id:
        raise _ToolError("proposal_id must be a non-empty string")
    rec = state["proposals"].get(proposal_id)
    if rec is None:
        raise _ToolError(f"no such proposal_id: {proposal_id!r}")
    if rec["status"] == "pending":
        # THE refusal. An agent that can run an action and only afterward
        # find out whether it was allowed is not gated at all.
        raise _ToolError(f"proposal {proposal_id!r} is still pending a decision; "
                         "refusing to record execution before one is recorded")
    if "executed_action" not in args:
        raise _ToolError("executed_action is required: an object (what actually ran) "
                         "or null (the action did not run)")
    executed_action = args["executed_action"]
    if executed_action is not None and not isinstance(executed_action, dict):
        raise _ToolError("executed_action must be a JSON object or null, "
                         f"got {type(executed_action).__name__}")
    outcome = args.get("outcome", "")
    if not isinstance(outcome, str):
        raise _ToolError(f"outcome must be a string, got {type(outcome).__name__}")
    receipt = gate.executed(rec["proposal"], executed_action, outcome=outcome,
                            witness=True, anchor=False)
    rec["executions"] = rec.get("executions", 0) + 1
    receipts_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = receipts_dir / f"{proposal_id}-{rec['executions']}.json"
    save_receipt(receipt, receipt_path)
    check = receipt["checks"][0]
    return {"receipt_body_digest": receipt["body_digest"],
            "executed_as_approved": check["executed_as_approved"],
            "receipt_path": str(receipt_path)}


# --------------------------------------------------------------------------
# JSON-RPC / MCP plumbing (same shape as arcaeon_ledger.mcp_server)
# --------------------------------------------------------------------------

TOOLS = [
    {
        "name": "approval_propose",
        "description": ("Propose a consequential action for human review. Nothing runs. "
                        "Returns the proposal id and the action's digest; the action is "
                        "recorded to the ledger but the decision is not made here."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "object", "description": "The action being proposed, "
                          "as a JSON object (e.g. {\"kind\": \"payment\", \"amount\": \"49.00\"}).",
                          "additionalProperties": True},
            },
            "required": ["action"],
        },
    },
    {
        "name": "approval_status",
        "description": ("Check whether a proposal has been decided yet. Picks up any "
                        "waiting decision file in --decisions-dir first, so this is also "
                        "how a decision actually takes effect. Returns status "
                        "(pending/approved/denied), and principal + decided_at once decided."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
            },
            "required": ["proposal_id"],
        },
    },
    {
        "name": "approval_executed",
        "description": ("Record what actually ran (or that nothing ran) for a decided "
                        "proposal, and issue the Approval Receipt. REFUSED with isError "
                        "true if the proposal is still pending — an agent cannot run first "
                        "and ask later. executed_action is the action that ran, as a JSON "
                        "object, or null if it did not run (the correct shape for an "
                        "honored denial). Returns receipt_body_digest, whether the executed "
                        "action's digest matches what was approved (executed_as_approved), "
                        "and the path the receipt JSON was written to."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
                "executed_action": {"type": ["object", "null"]},
                "outcome": {"type": "string", "description": "Optional free-text note on "
                           "what happened when it ran."},
            },
            "required": ["proposal_id", "executed_action"],
        },
    },
    {
        "name": "approval_list_pending",
        "description": ("List every proposal awaiting a decision. Picks up any waiting "
                        "decision files first, so an item that just got decided drops off "
                        "this list."),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _result(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def _error(id_, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": err}


ERROR_TEXT_MAX = 200


def _clip_error(detail: str, limit: int = ERROR_TEXT_MAX):
    """Cut an exception's text to `limit` chars and say so, rather than either
    echoing a hostile caller's own bytes back whole or silently truncating."""
    if len(detail) <= limit:
        return detail, None
    return (f"{detail[:limit]}... [truncated: {len(detail)} chars total, {limit} shown]",
            {"error_truncated": True, "error_len": len(detail), "error_shown": limit})


def _text_content(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


class _Server:
    """Holds the one gate + one state dict a stdio session serves. Split out
    of module-level globals so tests can also drive `handle()` directly
    without a subprocess, mirroring arcaeon_ledger.mcp_server's shape."""

    def __init__(self, *, ledger: str | Path, decisions_dir: str | Path,
                receipts_dir: str | Path, state_path: str | Path, agent: str = ""):
        self.gate = ApprovalGate(ledger, agent=agent)
        self.decisions_dir = Path(decisions_dir)
        self.receipts_dir = Path(receipts_dir)
        self.state_path = Path(state_path)
        self.state = _load_state(self.state_path)

    def _sync_decisions(self) -> None:
        if _process_decisions(self.state, self.decisions_dir, self.gate):
            _save_state(self.state_path, self.state)

    def dispatch(self, mid, name, args) -> dict:
        try:
            if not isinstance(args, dict):
                raise _ToolError(f"arguments must be a JSON object, got {type(args).__name__}")
            if name == "approval_propose":
                out = _approval_propose(args, self.gate, self.state)
                _save_state(self.state_path, self.state)
                return _result(mid, _text_content(out))
            if name == "approval_status":
                self._sync_decisions()
                return _result(mid, _text_content(_approval_status(args, self.state)))
            if name == "approval_list_pending":
                self._sync_decisions()
                return _result(mid, _text_content(_approval_list_pending(self.state)))
            if name == "approval_executed":
                self._sync_decisions()
                out = _approval_executed(args, self.gate, self.state, self.receipts_dir)
                _save_state(self.state_path, self.state)
                return _result(mid, _text_content(out))
            return _result(mid, {**_text_content({"error": f"unknown tool {name}"}), "isError": True})
        except Exception as e:  # never crash the server on one bad call
            detail, extra = _clip_error(str(e))
            payload = {"error": detail}
            if extra is not None:
                payload.update(extra)
            return _result(mid, {**_text_content(payload), "isError": True})

    def handle(self, msg: dict) -> Optional[dict]:
        if not isinstance(msg, dict):
            return _error(None, -32600,
                          f"invalid request: expected a JSON object, got {type(msg).__name__}")
        mid = msg.get("id")
        method = msg.get("method")
        if mid is None:  # notification — no reply
            return None
        if method == "initialize":
            return _result(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "approval", "version": "0.1.0"},
            })
        if method == "tools/list":
            return _result(mid, {"tools": TOOLS})
        if method == "tools/call":
            params = msg.get("params") or {}
            if not isinstance(params, dict):
                return _error(mid, -32602,
                              f"invalid params: expected an object, got {type(params).__name__}")
            name = params.get("name")
            args = params.get("arguments") or {}
            return self.dispatch(mid, name, args)
        return _error(mid, -32601, f"method not found: {method}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="arcaeon-receipt-approval-mcp")
    ap.add_argument("--ledger", default="approval.log.jsonl",
                    help="the ApprovalGate's own hash-chained ledger file")
    ap.add_argument("--decisions-dir", default="decisions",
                    help="where a human (or a bot) drops <proposal_id>.json decision files")
    ap.add_argument("--receipts-dir", default="receipts",
                    help="where approval_executed writes the receipt JSON")
    ap.add_argument("--state", default="approval_state.json",
                    help="JSON file holding proposal state across restarts")
    ap.add_argument("--agent", default="", help="name of the agent this gate serves")
    args = ap.parse_args(argv)

    server = _Server(ledger=args.ledger, decisions_dir=args.decisions_dir,
                     receipts_dir=args.receipts_dir, state_path=args.state, agent=args.agent)

    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(errors="replace")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as e:
            detail, data = _clip_error(str(e))
            resp = _error(None, -32700, f"parse error: {detail}", data=data)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = server.handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
