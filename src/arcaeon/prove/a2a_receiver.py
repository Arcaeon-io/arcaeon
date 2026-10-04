# SPDX-License-Identifier: MIT
"""arcaeon.prove.a2a_receiver: the A2A witness extension's reference receiver (TE-23).

    from arcaeon.prove import a2a_receiver as A
    d = A.receive(message_bytes, file_bytes, audience="instructor-1",
                  action="pay", signers=["did:key:z6Mk..."], deal="d-7f3a")
    d.decision        # "allow" or "refuse", from arcaeon.prove.gate.decide
    d.a2a             # where the envelope was found, and what was not there

THE EXTENSION (docs/A2A.md). Its URI is EXTENSION_URI. A sender puts the
labeled-exchange envelope (the same JSON object `arcaeon envelope seal`
writes as FILE.envelope.json) in an Artifact's `metadata` (or a Message's,
when a client hands an agent a file) under the extension URI:

    "extensions": ["https://arcaeon.io/a2a/witness/v1"],
    "metadata": {"https://arcaeon.io/a2a/witness/v1": {"envelope": {...sidecar...}}}

A receiver that declares the extension runs the gate before it acts on the
artifact's file. This module is that step and nothing else: it finds the
envelope, hands it and the file to `gate.decide` (which hands them to
`envelope.verify`, the one and only verifier) and returns the decision.

    nothing under metadata[URI]         COULD NOT LOOK (missing): read only
    metadata[URI] not an envelope        COULD NOT LOOK (unreadable): read only
    no file bytes to check               COULD NOT LOOK (missing): read only
    message not JSON, a duplicate key    COULD NOT LOOK (unreadable): read only
    a key beside `envelope` in the value BROKEN (outside the signed payload)
    anything else                        whatever verify answers

The `extensions` list on the carrier and the A2A-Extensions activation header
are unsigned. They are recorded under `a2a` and change no verdict: a missing
listing does not refuse a good envelope, and a listing does not make a missing
one good.

Stdlib only (verify loads the [sign] backend itself). `receive` raises only on
an unknown action, like `gate.decide`; a hostile message is an answer.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G
from arcaeon.record.row import loads_strict

__all__ = ["EXTENSION_URI", "ENVELOPE_KEY", "A2ADecision", "receive", "receive_files",
           "attach_envelope", "agent_extension", "declares", "main"]

EXTENSION_URI = "https://arcaeon.io/a2a/witness/v1"
#: The one key inside metadata[EXTENSION_URI].
ENVELOPE_KEY = "envelope"
#: A message bigger than this is not read (a raw part rides inside it as base64).
MAX_MESSAGE_BYTES = 32 << 20
_MAX_DEPTH = 8
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
#: Wrapper keys walked to find the carrier: JSON-RPC (result, params), the
#: 1.0 SendMessage response (task, message), a TaskArtifactUpdateEvent
#: (artifact). A Task's `history` is not walked: an old message's envelope is
#: not this exchange's.
_WRAPPERS = ("result", "params", "task", "message", "artifact")


@dataclass
class A2ADecision(G.GateDecision):
    """A gate decision plus `a2a`: the extension URI, which carrier the
    envelope came from (kind, id), whether the carrier listed the extension,
    whether the request activated it (None when not told), and where the file
    bytes came from."""
    a2a: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["a2a"] = dict(self.a2a)
        return out


# --- the sender's side and the agent card ------------------------------------------

def attach_envelope(carrier: dict, envelope: dict) -> dict:
    """Put `envelope` (a sealed sidecar object) under metadata[EXTENSION_URI]
    of an Artifact or Message dict and list the URI in its `extensions`.
    Returns the same dict."""
    meta = carrier.get("metadata")
    if not isinstance(meta, dict):
        meta = carrier["metadata"] = {}
    meta[EXTENSION_URI] = {ENVELOPE_KEY: envelope}
    ext = carrier.get("extensions")
    if not isinstance(ext, list):
        ext = carrier["extensions"] = []
    if EXTENSION_URI not in ext:
        ext.append(EXTENSION_URI)
    return carrier


def agent_extension(required: bool = False) -> dict:
    """The AgentExtension entry for an AgentCard's capabilities.extensions."""
    return {"uri": EXTENSION_URI, "required": bool(required),
            "description": ("Runs the arcaeon gate on an artifact's file before acting: the "
                            "labeled-exchange envelope rides in metadata under this URI. "
                            "Allow means unchanged and labeled for this agent, never true "
                            "or safe.")}


def declares(agent_card: Any) -> bool:
    """True when an AgentCard dict lists EXTENSION_URI in capabilities.extensions."""
    caps = agent_card.get("capabilities") if isinstance(agent_card, dict) else None
    exts = caps.get("extensions") if isinstance(caps, dict) else None
    return isinstance(exts, list) and any(
        isinstance(e, dict) and e.get("uri") == EXTENSION_URI for e in exts)


# --- finding the carrier ------------------------------------------------------------

def _kind(o: dict) -> str | None:
    if isinstance(o.get("parts"), list):
        if "artifactId" in o:
            return "artifact"
        if "messageId" in o or "role" in o:
            return "message"
    return None


def _carriers(o: Any, depth: int = 0, out: list | None = None) -> list:
    """Every Artifact or Message dict reachable through the wrapper keys and a
    Task's `artifacts`, as (kind, id, dict)."""
    out = [] if out is None else out
    if depth > _MAX_DEPTH or not isinstance(o, dict):
        return out
    k = _kind(o)
    if k:
        cid = o.get("artifactId") if k == "artifact" else o.get("messageId")
        out.append((k, cid if isinstance(cid, str) else None, o))
    for key in _WRAPPERS:
        if isinstance(o.get(key), dict):
            _carriers(o[key], depth + 1, out)
    if isinstance(o.get("artifacts"), list):
        for a in o["artifacts"][:1000]:
            _carriers(a, depth + 1, out)
    return out


def _has_value(c: dict) -> bool:
    return isinstance(c.get("metadata"), dict) and EXTENSION_URI in c["metadata"]


def _listed(c: dict) -> bool:
    ext = c.get("extensions")
    return isinstance(ext, list) and EXTENSION_URI in ext


def _file_parts(c: dict) -> list:
    """(filename, base64 text or None, url or None) for each file part: the 1.0
    shape (`raw`, `url`, `filename`) and the 0.3 shape (`kind: file`, `file`:
    {`bytes` | `uri`, `name`})."""
    found = []
    for p in c.get("parts") or []:
        if not isinstance(p, dict):
            continue
        if "raw" in p or "url" in p:
            found.append((p.get("filename"), p.get("raw"), p.get("url")))
        elif p.get("kind") == "file" and isinstance(p.get("file"), dict):
            f = p["file"]
            found.append((f.get("name"), f.get("bytes"), f.get("uri")))
    return found


def _label(kind: str, cid: str | None) -> str:
    safe = (cid or "?").replace("/", "_").replace("\\", "_")[:80]
    return f"A2A {kind} {safe!r}"


# --- the decision -------------------------------------------------------------------

def _utc(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _wrap(d: G.GateDecision, info: dict) -> A2ADecision:
    return A2ADecision(**{f.name: getattr(d, f.name) for f in fields(G.GateDecision)}, a2a=info)


def _cnl(action, audience, deal, purpose, signers, now, info, looked_for, where, word,
         reason, file_label="", env_label="") -> A2ADecision:
    """A COULD NOT LOOK decision made before verify could run (no envelope, no
    file, no message to read). The gate's own rule and wording decide it."""
    r = {"verdict": V.COULD_NOT_LOOK, **V.could_not_look(looked_for, where, word, reason)}
    allowed = action in G.RULES[V.COULD_NOT_LOOK]
    return A2ADecision(decision=G.ALLOW if allowed else G.REFUSE, action=action,
                       verdict=V.COULD_NOT_LOOK,
                       reason=G._reason(action, V.COULD_NOT_LOOK, r, audience, deal),
                       reasons=[reason], could_not_check={k: r[k] for k in
                                                          ("looked_for", "where", "reason_word")},
                       file=file_label, envelope=env_label, audience=audience, deal=deal,
                       purpose=purpose, signers=list(signers), at=_utc(now), report=r, a2a=info)


def _activated(activated) -> bool | None:
    if activated is None:
        return None
    if isinstance(activated, str):
        activated = activated.split(",")
    return EXTENSION_URI in {str(a).strip() for a in activated}


def receive(message: bytes | str | dict, file: bytes | str | Path | None = None, *,
            action: str, audience: str | None, signers=(), deal: str | None = None,
            purpose: str | None = None, artifact_id: str | None = None, activated=None,
            record_dir: str | Path | None = None, ledger: str | Path | None = None,
            now: datetime | None = None) -> A2ADecision:
    """allow or refuse `action` on an A2A artifact's file, from its envelope.

    `message` is the A2A JSON as bytes or text (parsed strictly: a duplicate
    key is unreadable) or an already parsed dict (no duplicate check). It may
    be an Artifact, a Message, a Task, a TaskArtifactUpdateEvent or a JSON-RPC
    request or response around one. `file` is the artifact's file: bytes, or a
    path to them; None takes the bytes from the carrier's one inline file part
    (`raw` or 0.3 `file.bytes`); a `url` part is never fetched. `artifact_id`
    picks the carrier when more than one carries the extension. `activated` is
    the A2A-Extensions value the request carried (a comma-separated string or
    a list), recorded only. The rest goes to `gate.decide` unchanged; `ledger`
    is required with `deal`, as there (D066). Raises ValueError on an unknown
    action or a `deal` without a `ledger`; otherwise never raises."""
    if action not in G.ACTIONS:
        raise ValueError(f"action must be one of {G.ACTIONS}, got {action!r}")
    if deal is not None and ledger is None:
        raise ValueError(G._NEEDS_LEDGER)
    now = now or datetime.now(timezone.utc)
    signers = list(signers or ())
    info: dict[str, Any] = {"extension": EXTENSION_URI, "carrier": None, "id": None,
                            "listed": None, "activated": _activated(activated),
                            "file_from": None}
    try:
        return _receive(message, file, action, audience, signers, deal, purpose, artifact_id,
                        record_dir, ledger, now, info)
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        return _cnl(action, audience, deal, purpose, signers, now, info, "a finished check",
                    "the A2A message", "unreadable",
                    f"the A2A message could not be read to the end ({type(e).__name__})")


def _receive(message, file, action, audience, signers, deal, purpose, artifact_id,
             record_dir, ledger, now, info) -> A2ADecision:
    def cnl(looked_for, where, word, reason, fl="", el=""):
        return _cnl(action, audience, deal, purpose, signers, now, info, looked_for, where,
                    word, reason, fl, el)

    raw_message = None
    if isinstance(message, (bytes, bytearray, str)):
        raw_message = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        if len(raw_message) > MAX_MESSAGE_BYTES:
            return cnl("the A2A message", "the A2A message", "unreadable",
                       f"the message is over {MAX_MESSAGE_BYTES} bytes; not read")
        try:
            message = loads_strict(raw_message.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            return cnl("the A2A message", "the A2A message", "unreadable",
                       f"the message is not one JSON object ({str(e)[:120]}); a duplicate "
                       f"key counts, since two readers would see two messages")
    if not isinstance(message, dict):
        return cnl("the A2A message", "the A2A message", "unreadable",
                   "the message is not a JSON object")
    found = _carriers(message)
    if artifact_id is not None:
        found = [c for c in found if c[1] == artifact_id]
        if not found:
            return cnl(f"the artifact {artifact_id!r}", "the A2A message", "missing",
                       f"no Artifact or Message with id {artifact_id!r} in the message")
    with_value = [c for c in found if _has_value(c[2])]
    if len(with_value) > 1:
        ids = ", ".join(repr(c[1]) for c in with_value[:5])
        return cnl("one carrier of the witness extension", "the A2A message", "bounded",
                   f"{len(with_value)} carriers hold an envelope ({ids}); name one with "
                   f"artifact_id (--artifact) so the right file is checked")
    if not with_value:
        listed = [c for c in found if _listed(c[2])]
        if listed:
            k, cid, c = listed[0]
            info.update(carrier=k, id=cid, listed=True)
            return cnl("the envelope under metadata[witness extension URI]", _label(k, cid),
                       "missing", f"the {k} lists {EXTENSION_URI} in its extensions but its "
                       f"metadata carries no envelope there (stripped or never sent): nothing "
                       f"says what the file is or who sealed it")
        if found:
            info.update(carrier=found[0][0], id=found[0][1], listed=False)
        return cnl("the envelope under metadata[witness extension URI]",
                   _label(*found[0][:2]) if found else "the A2A message", "missing",
                   f"no envelope under metadata[{EXTENSION_URI!r}]: nothing says what the file "
                   f"is or who sealed it")
    kind, cid, carrier = with_value[0]
    label = _label(kind, cid)
    info.update(carrier=kind, id=cid, listed=_listed(carrier))
    env_label = f"{label} metadata[{EXTENSION_URI}].{ENVELOPE_KEY}"
    value = carrier["metadata"][EXTENSION_URI]
    sidecar = value.get(ENVELOPE_KEY) if isinstance(value, dict) else None
    if not isinstance(sidecar, dict):
        return cnl("an arcaeon envelope", env_label, "unreadable",
                   f"metadata[{EXTENSION_URI!r}] is not an object holding an {ENVELOPE_KEY!r} "
                   f"object", el=env_label)
    # A key beside `envelope` is outside the signed payload, the same as a stray
    # key in the sidecar: it goes into the sidecar verify reads, prefixed, so
    # the one verifier reads it as BROKEN and names it.
    sidecar = dict(sidecar)
    for k in value:
        if k != ENVELOPE_KEY:
            sidecar[f"a2a:{k}"] = value[k]
    # --- the file bytes -----------------------------------------------------
    parts = _file_parts(carrier)
    name = next((n for n, _, _ in parts if isinstance(n, str)
                 and _SAFE_NAME.fullmatch(Path(n).name) and ".." not in n), None)
    name = Path(name).name if name else "artifact"
    data: bytes | None = None
    file_path: Path | None = None
    if file is not None and not isinstance(file, (bytes, bytearray)):
        file_path = Path(file)
        info["file_from"] = "path"
        file_label = str(file_path)
    else:
        file_label = f"{label} file {name!r}"
        if file is not None:
            data = bytes(file)
            info["file_from"] = "given"
        else:
            inline = [b for _, b, _ in parts if b is not None]
            if len(inline) != 1:
                why = ("no inline file part (a url part is never fetched here; fetch it and "
                       "pass the bytes)" if not inline else
                       f"{len(inline)} inline file parts and one envelope; pass the bytes")
                return cnl("the artifact's file bytes", label, "missing" if not inline
                           else "bounded", why, file_label, env_label)
            try:
                if not isinstance(inline[0], str):
                    raise ValueError("not a string")
                data = base64.b64decode(inline[0], validate=True)
            except (ValueError, binascii.Error):
                return cnl("the artifact's file bytes", label, "unreadable",
                           "the inline file part is not base64", file_label, env_label)
            info["file_from"] = "inline part"
    # --- the gate --------------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="arcaeon-a2a-") as td:
        tdir = Path(td)
        if file_path is None:
            file_path = tdir / name
            file_path.write_bytes(data)
        env_path = tdir / (name + E.SUFFIX)
        env_path.write_text(json.dumps(sidecar), encoding="utf-8")
        labels = {str(env_path): env_label}
        if info["file_from"] != "path":
            labels[str(file_path)] = file_label
        # before the gate.evidence row is appended, so its pack_digest covers it
        on_pack = lambda out: _evidence_a2a(out, labels, info, raw_message)  # noqa: E731
        d = G.decide(file_path, envelope=env_path, action=action, audience=audience,
                     signers=signers, deal=deal, purpose=purpose, record_dir=record_dir,
                     ledger=ledger, now=now, on_pack=on_pack)
        d = _relabel(d, labels)
    return _wrap(d, info)


def _relabel(d: G.GateDecision, labels: dict) -> G.GateDecision:
    """Temp paths out, labels in: they are gone once this returns."""
    d.file = labels.get(d.file, d.file)
    d.envelope = labels.get(d.envelope, d.envelope)
    for k in ("file", "envelope", "where"):
        if isinstance(d.report.get(k), str):
            d.report[k] = labels.get(d.report[k], d.report[k])
    if d.could_not_check and isinstance(d.could_not_check.get("where"), str):
        d.could_not_check["where"] = labels.get(d.could_not_check["where"],
                                                d.could_not_check["where"])
    return d


def _evidence_a2a(out: Path, labels: dict, info: dict, raw_message: bytes | None) -> None:
    """Keep the A2A message beside the pack's copies and say so in evidence.json."""
    try:
        ev_path = out / "evidence.json"
        ev = json.loads(ev_path.read_text(encoding="utf-8"))
        for key in ("file", "envelope"):
            if isinstance(ev.get(key), dict):
                ev[key]["path"] = labels.get(ev[key].get("path"), ev[key].get("path"))
        rep = ev.get("report") if isinstance(ev.get("report"), dict) else {}
        for k in ("file", "envelope", "where"):
            if isinstance(rep.get(k), str):
                rep[k] = labels.get(rep[k], rep[k])
        extra = dict(info)
        if raw_message is not None:
            (out / "bundle" / "a2a-message.json").write_bytes(raw_message)
            extra["message"] = {"copy": "bundle/a2a-message.json", "bytes": len(raw_message),
                                "sha256": hashlib.sha256(raw_message).hexdigest()}
        ev["a2a"] = extra
        ev_path.write_text(json.dumps(ev, indent=1, ensure_ascii=False) + "\n", encoding="utf-8",
                           newline="\n")
    except Exception:  # noqa: BLE001  the refusal and the gate's pack stand either way
        pass


def receive_files(message: str | Path, file: str | Path | None = None, **kw) -> A2ADecision:
    """`receive` with the message read from a file (strictly, size-capped)."""
    action = kw.get("action")
    if action not in G.ACTIONS:
        raise ValueError(f"action must be one of {G.ACTIONS}, got {action!r}")
    if kw.get("deal") is not None and kw.get("ledger") is None:
        raise ValueError(G._NEEDS_LEDGER)
    p = Path(message)
    try:
        if p.stat().st_size > MAX_MESSAGE_BYTES:
            raise ValueError("over the size limit")
        raw = p.read_bytes()
    except (OSError, ValueError) as e:
        now = kw.get("now") or datetime.now(timezone.utc)
        word = "missing" if not p.exists() else "unreadable"
        return _cnl(action, kw.get("audience"), kw.get("deal"), kw.get("purpose"),
                    list(kw.get("signers") or ()), now,
                    {"extension": EXTENSION_URI, "carrier": None, "id": None, "listed": None,
                     "activated": _activated(kw.get("activated")), "file_from": None},
                    "the A2A message", p.name, word,
                    f"the message file cannot be read ({type(e).__name__})")
    return receive(raw, file, **kw)


# --- CLI (`arcaeon gate a2a`) ----------------------------------------------------------

_SPEC = {"--message": "value", "--file": "value", "--audience": "value", "--signer": "list",
         "--action": "value", "--deal": "value", "--purpose": "value", "--artifact": "value",
         "--activated": "value", "--record-dir": "value", "--ledger": "value",
         "--json": "bool"}


def cli(argv: list[str]) -> int:
    """The `arcaeon gate a2a` subcommand; usage errors raise envelope._Usage."""
    pos, o = E._parse(argv, _SPEC)
    if pos:
        raise E._Usage(f"unexpected argument {pos[0]!r}")
    for need in ("--message", "--audience", "--signer", "--action"):
        if not o.get(need):
            raise E._Usage(f"a2a needs {need}")
    if o["--action"] not in G.ACTIONS:
        raise E._Usage(f"--action must be one of {', '.join(G.ACTIONS)}")
    if o.get("--deal") is not None and not o.get("--ledger"):
        raise E._Usage(G._NEEDS_LEDGER)
    d = receive_files(o["--message"], o.get("--file"), action=o["--action"],
                      audience=o["--audience"], signers=o["--signer"], deal=o.get("--deal"),
                      purpose=o.get("--purpose"), artifact_id=o.get("--artifact"),
                      activated=o.get("--activated"), record_dir=o.get("--record-dir"),
                      ledger=o.get("--ledger"))
    if o.get("--json"):
        print(json.dumps(d.to_dict(), indent=1, ensure_ascii=False))
    else:
        print(d.reason)
    return d.exit_code


def main(argv: list[str] | None = None) -> int:
    return G.main(["a2a", *(sys.argv[1:] if argv is None else argv)])
