"""Optional license entanglement for the paid lane. OFF unless asked for.

Idea I-daniel-17. The connector's paid tools are already gated on ARCAEON_KEY,
which answers "does this caller have a witness account". This answers a
different question — "is this copy of the package licensed" — and it answers it
by binding a license key to the LEDGER NAMESPACE being pinned. A borrowed key
would have to pin under the lender's namespace, which puts the borrower's rows
in someone else's public pin history under someone else's name. That is the
entanglement; the gate itself is just the polite door in front of it.

THREE PROPERTIES, on purpose:

  DEFAULT OFF. With LICENSE_GATE_REQUIRED unset (or 0/false/no), nothing here
  imports anything and every call returns None in a few microseconds. The
  connector ships free and behaves exactly as it did before this file existed.

  OPTIONAL IMPORT. The gate lives outside this package (a pip install of
  `arcaeon` does not carry the private monorepo), so it is resolved at call time
  by module name across a small candidate list, overridable with
  LICENSE_GATE_MODULE. A missing gate is not an error while the gate is off.

  FAILS CLOSED WHEN ON. LICENSE_GATE_REQUIRED=1 with no gate module installed
  REFUSES the paid tools. A required check that silently passes because its
  own implementation is missing is the worst of the three outcomes: it looks
  enforced and is not.

Refusals are returned as plain sentences, never raised — same contract as the
no-key upgrade message. In this connector a refusal is a product surface.
"""
from __future__ import annotations

import importlib
import os

#: Set to 1/true/yes to turn the gate on. Anything else, including unset, is off.
REQUIRED_ENV = "LICENSE_GATE_REQUIRED"

#: Where the buyer's license key lives. Distinct from ARCAEON_KEY, which is a
#: witness account credential and answers a different question.
KEY_ENV = "ARCAEON_LICENSE_KEY"

#: Optional explicit module path, for a self-hoster or a test.
MODULE_ENV = "LICENSE_GATE_MODULE"

#: Tried in order. The first is the eventual shipped package; the second is
#: where the implementation lives in the private monorepo today.
GATE_MODULES = ("arcaeon_license_gate", "bridge.license_gate.gate")

_TRUE = {"1", "true", "yes", "on"}


def required() -> bool:
    """Read at CALL time, never cached: a client can change its environment
    between sessions, and a cached 'off' is a gate that never turns on."""
    return os.environ.get(REQUIRED_ENV, "").strip().lower() in _TRUE


def load_gate():
    """The gate module, or None if nothing importable provides one."""
    names = [n for n in (os.environ.get(MODULE_ENV, "").strip(),) if n] or list(GATE_MODULES)
    for name in names:
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


def refusal_for(tool: str, identity: str) -> str | None:
    """None when the call may proceed; a plain sentence when it may not.

    `identity` is the ledger namespace the paid call is about. Tying the
    license to the namespace rather than to a machine or a user account is the
    whole idea: the license covers YOUR ledger.
    """
    if not required():
        return None

    gate = load_gate()
    if gate is None:
        return (
            f"{tool} is refused: {REQUIRED_ENV}=1 is set on this machine but no "
            f"license gate module is installed, so the license could not be "
            f"checked at all.\n"
            f"\n"
            f"This refusal is deliberate. A required check that passes because "
            f"its own implementation is missing would look enforced and be "
            f"nothing. Install the gate, or unset {REQUIRED_ENV} to run the "
            f"connector in its normal free-and-ungated mode."
        )

    try:
        gate.check(os.environ.get(KEY_ENV, ""), identity)
    except gate.LicenseError as e:
        return _refusal_text(tool, identity, e)
    return None


def _refusal_text(tool: str, identity: str, error) -> str:
    """The gate's own sentence, wrapped with what the caller needs to act.

    ASCII only, like every other refusal here: this gets printed to terminals,
    and a cp1252 console turns a well-meant em-dash into a replacement glyph.
    """
    reason = getattr(error, "reason", "refused")
    return (
        f"{tool} is refused by the license gate [{reason}], so nothing was sent.\n"
        f"\n"
        f"{error}\n"
        f"\n"
        f"The license is bound to the ledger namespace being pinned, which here "
        f"is {identity!r}. Set {KEY_ENV}=<your license key>, or unset "
        f"{REQUIRED_ENV} if this copy is not meant to be gated."
    )


def status() -> dict:
    """What arcaeon_status reports about licensing. Never includes the key."""
    on = required()
    gate = load_gate() if on else None
    return {
        "required": on,
        "required_env": REQUIRED_ENV,
        "key_env": KEY_ENV,
        "key_present": bool(os.environ.get(KEY_ENV, "").strip()),
        "gate_module": getattr(gate, "__name__", None),
        "note": (
            "Off by default. When on, the paid tools additionally require a "
            "license key bound to the ledger namespace being pinned; a missing "
            "gate module fails closed."
        ),
    }
