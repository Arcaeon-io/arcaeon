"""Approval Receipt: a named principal decided on THIS action before it ran.

Buyer: a team shipping agents that take consequential actions (payments,
sends, deploys, record changes) and answering a SOC 2 / ISO 42001 / change-
management auditor's question: "show me a human approved this before it
happened, and show me what ran is what was approved." Today the answer is
a Slack screenshot. This is the receipt instead.

Three ledger rows, in order: propose (action digest), decide (principal,
decision, bound to the proposal digest), execute (digest of what actually
ran, compared). Sequence is what the chain proves; the comparison is what
the receipt prints. A denied action that ran anyway, or an approved action
that ran differently, is the finding the auditor is looking for, and it is
stated in one field: executed_as_approved.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from arcaeon.record.ledger import Ledger, digest_bytes, digest_json

from .core import _now_iso, build_receipt, render_exhibit

KIND = "human-approval"

SCOPE = {
    "proves": [
        "An action with the recorded digest was proposed, a decision on it was recorded under the "
        "named principal, and (if executed) an action with the recorded digest ran afterward, "
        "in that sequence in the issuer's hash chain.",
        "Whether the executed action's digest equals the approved action's digest (executed_as_approved).",
    ],
    "does_not_prove": [
        "That the principal is a human, read the action, or had authority to approve it: the "
        "principal is asserted data, not a signature. Pair with an identity layer for that.",
        "That nothing else ran: only actions routed through this gate are recorded.",
        "That the action was wise, safe, or compliant; only that it was approved as stated.",
    ],
    "method": "three hash-chained rows (proposed / decided / executed) in arcaeon-ledger; action "
              "identity is the sha256 of its canonical JSON.",
}


class ApprovalGate:
    def __init__(self, ledger_path: str | Path, *, namespace: str = "approval", agent: str = ""):
        self.ledger_path = Path(ledger_path)
        self.ledger = Ledger(self.ledger_path)
        self.namespace = namespace
        self.agent = agent

    def propose(self, action: dict, *, proposer: Optional[str] = None) -> dict:
        d = digest_json(action)
        chain = self.ledger.append({"evt": "approval_proposed", "namespace": self.namespace,
                                    "action_digest": d, "action_kind": action.get("kind", ""),
                                    "proposer": proposer or self.agent})
        return {"action_digest": d, "action_kind": action.get("kind", ""),
                "proposed_at": _now_iso(), "proposed_chain": chain,
                "proposer": proposer or self.agent}

    def decide(self, proposal: dict, *, principal: str, decision: str, note: str = "") -> dict:
        # Message prefixes are the machine-readable reason (bad_decision: /
        # empty_principal:) so a gate that quarantines a decision file can
        # record why, not only that.
        if decision not in ("approved", "denied"):
            raise ValueError("bad_decision: decision must be 'approved' or 'denied'")
        if not principal:
            raise ValueError("empty_principal: principal is required; an anonymous approval is not an approval")
        chain = self.ledger.append({"evt": "approval_decided", "namespace": self.namespace,
                                    "action_digest": proposal["action_digest"],
                                    "proposed_chain": proposal["proposed_chain"],
                                    "principal": principal, "decision": decision, "note": note})
        p = dict(proposal)
        p.update({"principal": principal, "decision": decision, "note": note,
                  "decided_at": _now_iso(), "decided_chain": chain})
        return p

    def executed(self, proposal: dict, executed_action: Optional[dict], *,
                 outcome: str = "", witness: bool = True, anchor: bool = False) -> dict:
        """Close the loop and issue the receipt. executed_action=None means
        the action did not run (the correct outcome of a denial)."""
        ex_digest = digest_json(executed_action) if executed_action is not None else None
        ran = executed_action is not None
        approved = proposal.get("decision") == "approved"
        as_approved = (ran and approved and ex_digest == proposal["action_digest"]) or (not ran and not approved)
        chain = self.ledger.append({"evt": "approval_executed", "namespace": self.namespace,
                                    "action_digest": proposal["action_digest"],
                                    "decided_chain": proposal.get("decided_chain"),
                                    "executed_digest": ex_digest, "ran": ran,
                                    "executed_as_approved": as_approved, "outcome": outcome})
        check = {"action_kind": proposal.get("action_kind"),
                 "action_digest": proposal["action_digest"],
                 "principal": proposal.get("principal"), "decision": proposal.get("decision"),
                 "note": proposal.get("note", ""),
                 "proposed_at": proposal.get("proposed_at"), "decided_at": proposal.get("decided_at"),
                 "executed_at": _now_iso() if ran else None,
                 "executed_digest": ex_digest, "ran": ran,
                 "executed_as_approved": as_approved, "outcome": outcome,
                 "rows": {"proposed": proposal.get("proposed_chain"),
                          "decided": proposal.get("decided_chain"), "executed": chain},
                 "flagged": not as_approved}
        subject = {"agent": self.agent or "(unnamed)", "principal": proposal.get("principal"),
                   "executed_as_approved": as_approved}
        return build_receipt(KIND, subject, [check], SCOPE, ledger_path=self.ledger_path,
                             namespace=self.namespace, witness=witness, anchor=anchor)


def _line(c: dict) -> str:
    verdict = "AS APPROVED" if c.get("executed_as_approved") else "!! MISMATCH"
    ran = "ran" if c.get("ran") else "did not run"
    return (f"{verdict}: {c.get('action_kind') or 'action'} {c.get('action_digest','')[-16:]} "
            f"{c.get('decision')} by {c.get('principal')} at {c.get('decided_at')}; {ran}"
            + (f" as {str(c.get('executed_digest'))[-16:]}" if c.get("ran") else ""))


def exhibit(receipt: dict) -> str:
    return render_exhibit(receipt, title="APPROVAL RECEIPT", check_line=_line)


# --------------------------------------------------------------------------
# Artifact Approval: a simpler, one-shot approval of a single artifact.
# --------------------------------------------------------------------------
# Buyer: anyone who needs to show that a NAMED party signed off on a SPECIFIC
# artifact -- a document, a build, a release -- at a point in time, without
# the machinery of ApprovalGate's propose/decide/execute sequence (there is
# nothing here that "runs" afterward to compare against). The artifact
# content and the literal approval text are never stored, only their hashes.

ARTIFACT_KIND = "artifact-approval"

ARTIFACT_SCOPE = {
    "proves": [
        "The named approver's credential signed the recorded artifact hash at the recorded "
        "timestamp, attested by the recorded approval-text hash.",
    ],
    "does_not_prove": [
        "That the approver had the authority to approve this artifact.",
        "That the approver was competent to judge it.",
        "That the artifact itself is good, correct, or fit for purpose.",
    ],
    "method": "sha256 digest of the artifact and of the literal approval text, recorded together "
              "with the approver id and timestamp; neither the artifact nor the approval text is "
              "carried by this receipt.",
}


def hash_artifact(data: bytes) -> str:
    """Convenience: sha256 an artifact's bytes for callers who have the bytes
    on hand rather than a pre-computed hash."""
    return digest_bytes(data)


def artifact_approval_receipt(artifact_hash: str, approver_id: str, approval_text: str, *,
                              ledger_path: str | Path, namespace: str = "artifact-approval",
                              timestamp: Optional[str] = None, extra: Optional[dict] = None,
                              witness: bool = True, anchor: bool = False) -> dict:
    """artifact_hash: a hex digest the caller computed over the artifact (see
    hash_artifact() for bytes on hand); the artifact itself is never passed
    in or stored here. approval_text: the literal statement the approver
    signed (e.g. "I approve this release for production") -- hashed inside
    this function and never stored raw."""
    if not artifact_hash or not str(artifact_hash).strip():
        raise ValueError("artifact_hash is required and must not be the artifact itself")
    if not approver_id:
        raise ValueError("empty_approver: approver_id is required")
    if not approval_text or not approval_text.strip():
        raise ValueError("empty_approval_text: approval_text is required")
    ts = timestamp or _now_iso()
    approval_text_hash = digest_bytes(approval_text.encode("utf-8"))
    check = {"artifact_hash": str(artifact_hash), "approver_id": approver_id,
             "timestamp": ts, "approval_text_hash": approval_text_hash}
    subject = {"approver_id": approver_id, "artifact_hash": str(artifact_hash)}
    return build_receipt(ARTIFACT_KIND, subject, [check], ARTIFACT_SCOPE, ledger_path=ledger_path,
                         namespace=namespace, extra=extra, witness=witness, anchor=anchor,
                         issued_at=ts)


def _artifact_line(c: dict) -> str:
    return (f"approved by {c.get('approver_id')} at {c.get('timestamp')}: "
            f"artifact={str(c.get('artifact_hash'))[-16:]} "
            f"approval_text_hash={str(c.get('approval_text_hash'))[-16:]}")


def artifact_exhibit(receipt: dict) -> str:
    return render_exhibit(receipt, title="ARTIFACT APPROVAL", check_line=_artifact_line)
