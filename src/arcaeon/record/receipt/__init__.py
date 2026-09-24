"""arcaeon-receipt: one receipt shape, five buyers.

The 2026-09-10 lane research found that every new Arcaeon lane is the same
product pointed at a different buyer: a hash-chained, witnessed, timestamp-
anchored record that someone is REQUIRED to hand to a third party. So the
package is one core (`core.py`: build / verify / exhibit) and thin adapters,
each of which owns exactly two things: what its checks look like, and the
scope statement printed on the face of the receipt (what it proves, what it
does not). The scope statement is not a disclaimer bolted on; it is the
product. A receipt that overstates itself is worse than no receipt.

Adapters:
  cite        Citation Receipt: existence checks against CourtListener, for
              filings under AI-disclosure orders. Existence only, never
              correctness, never good-law.
  call        Receipted Call: request/response/payment digests for a paid
              agent-to-agent call (x402 and kin). Delivery evidence, not
              quality evidence. Also carries phone_call_receipt(): opaque
              participant ids, start/end timestamps, and a transcript
              hash for a call that happened between people, not machines.
  approval    Approval Receipt: a named principal decided on an action with
              this digest BEFORE it ran, and the run matched (or did not).
              For SOC 2 / change-management evidence when an agent holds
              the pen. Also carries artifact_approval_receipt(): a simpler
              one-shot sign-off on a single artifact by a named approver.
  authorship  Authorship Receipt: an edit-event stream recorded as it
              happened, typed vs pasted counted, final text bound. Evidence
              of process, not proof of a human.
  ballot      Ballot Receipt: a finished training-sim grade, sealed at the
              moment it closed, for a trainee showing a hiring center the
              score is unaltered. Says nothing about whether the grade
              itself is correct.
"""
from .core import (RECEIPT_VERSION, ADHERENCE_VALUES, build_receipt, verify_receipt,
                   render_exhibit, load_receipt, save_receipt, engagement_scope,
                   attestation, attach_attestation_signature)

__version__ = "0.2.0"
__all__ = ["RECEIPT_VERSION", "ADHERENCE_VALUES", "build_receipt", "verify_receipt",
           "render_exhibit", "load_receipt", "save_receipt", "engagement_scope",
           "attestation", "attach_attestation_signature", "__version__"]
