# SPDX-License-Identifier: MIT
"""arcaeon.prove.envelope: the labeled-exchange envelope (truth-economy phase 1).

    arcaeon envelope seal FILE --label TEXT --audience ID --deal ID \\
                               --purpose TEXT --not-after WHEN [--key SEEDFILE]
    arcaeon envelope verify FILE --audience ID --signer DID [--deal ID] [--purpose TEXT]

`seal` writes FILE.envelope.json beside FILE. `verify` answers in one of three
words, verify-before-act: VERIFIED (act), BROKEN (refuse, keep the evidence),
COULD NOT LOOK (do not act on money or an irreversible step). The spec,
with what a VERIFIED does and does not prove, is docs/ENVELOPE.md.

THE SHAPE. We did not invent one. The sidecar is a DSSE envelope carrying an
in-toto Statement v1, packaged in the style of a Sigstore bundle (one JSON
object beside the file; it is NOT a conformant Sigstore bundle: no
certificate, no transparency-log entry):

  {"mediaType": "application/vnd.arcaeon.envelope.v1+json",
   "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json",
                    "payload": base64(Statement JSON),
                    "signatures": [{"keyid": "did:key:z...", "sig": base64}]}}

  Statement = {"_type": "https://in-toto.io/Statement/v1",
               "subject": [{"name": basename, "digest": {"sha256": hex}}],
               "predicateType": "https://arcaeon.io/labeled-exchange/v1",
               "predicate": {label, sealed_by, sealed_at, chain, pin_ref,
                             witness_ref, flags, binding, bytes, version}}

  checks (optional, TE-31) = check.verdict.relayed rows `seal --checks`
  carried for this file's sha256, inside the signed payload; absent unless
  given, so an envelope without them is byte-identical to before. A carried
  row is the sender's report; arcaeon.prove.gate reads it like --checks.

  binding = {audience, deal, purpose, not_after}: all four MANDATORY. An
  unbound envelope can be replayed into another deal or at another receiver
  (threat T3), so `seal` refuses to write one and `verify` reads one as BROKEN.

SIGNING. Ed25519 over the DSSE pre-authentication encoding (PAE), through the
same backend the vet receipts use (arcaeon.prove.vet.receipts, the [sign]
extra; imported only when a signature is made or checked, so the base install
stays stdlib-only). The key id is a did:key, self-certifying: the public key is
in the id. `seal` without --key writes an UNSIGNED envelope; `verify` answers
COULD NOT LOOK on it, because a sidecar anyone can rewrite proves nothing
about who sealed the bytes. A signed envelope verifies VERIFIED only against a
key the receiver names (--signer): a valid signature from a key you did not
name says only that SOME key signed it.

PIN AND WITNESS REFS are recorded and shape-checked, never fetched: fetching
them needs the network and is out of scope here. Present, the witness step
reads COULD NOT LOOK (and, with --require-witness, so does the verdict).
With --pins DIR, a local clone of a pins repo (tips/<chain>/<stamp>/
statement.json), the pin_ref is resolved offline: the pin's statement digest
matches = VERIFIED; the pin not in the clone, or the clone unreadable = COULD
NOT LOOK; the pin the witness_ref names there with another digest = BROKEN.

Never raises from verify(): a sidecar that cannot be read is an answer too.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.record.row import (JSON_C14N_PREFIX, DuplicateKeyError, digest_json, file_pin,
                                loads_strict)

__all__ = ["MEDIA_TYPE", "PAYLOAD_TYPE", "STATEMENT_TYPE", "PREDICATE_TYPE", "SUFFIX",
           "BINDING_FIELDS", "SealError", "pae", "envelope_path", "build_statement",
           "seal", "verify", "resolve_pin", "PIN_STATEMENT", "CHECKS_KEY",
           "MAX_CARRIED_CHECKS", "MAX_CARRIED_CHECK_BYTES", "MAX_CARRIED_CHECKS_BYTES",
           "carried_check_rows", "main"]

MEDIA_TYPE = "application/vnd.arcaeon.envelope.v1+json"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://arcaeon.io/labeled-exchange/v1"
SUFFIX = ".envelope.json"
PREDICATE_VERSION = 1
BINDING_FIELDS = ("audience", "deal", "purpose", "not_after")
#: A sidecar bigger than this is not read: an envelope is a few KiB.
MAX_ENVELOPE_BYTES = 1 << 20
#: A step that was not claimed at all (no pin or witness ref recorded).
NOT_CLAIMED = "NOT CLAIMED"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_PIN_REF = re.compile(r"sha256:(json-c14n:v1:|raw-bytes:v1:)?[0-9a-f]{64}")
_WITNESS_REF = re.compile(r"(https://[^\s]{1,2040}|urn:[a-z0-9][a-z0-9-]{0,31}:[^\s]{1,2000})")
#: A pin folder's name in a pins repo: <YYYY-MM-DD>T<HHMM>Z.
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{4}Z")
#: The pin statement in each pin folder, canonical bytes exactly as hashed.
PIN_STATEMENT = "statement.json"
#: A pin statement bigger than this is not read: a statement is a few hundred bytes.
MAX_PIN_STATEMENT_BYTES = 1 << 20
#: How deep under --pins a pin folder is looked for: DIR may be the stamp folder,
#: its <chain> folder, tips/, or the clone root holding tips/.
_PINS_DEPTH = 3
_FLAG = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}")
_DURATION = re.compile(r"([1-9][0-9]{0,4})([dhm])")
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_TOP_KEYS = {"mediaType", "dsseEnvelope"}
_DSSE_KEYS = {"payloadType", "payload", "signatures"}
_PREDICATE_KEYS = {"version", "label", "sealed_by", "sealed_at", "chain", "pin_ref",
                   "witness_ref", "flags", "binding", "bytes"}
#: The predicate key carried check rows ride under (TE-31). Written only when
#: `seal` is given checks, so an envelope sealed without them is byte-identical
#: to one sealed before this key existed.
CHECKS_KEY = "checks"
#: The connector row kind (arcaeon.connector.core.ROW_KIND) the only rows that ride.
CHECK_ROW_KIND = "check.verdict.relayed"
#: The words a carried row's relayed_verdict may hold (arcaeon.connector.core.OUR_WORDS).
_CHECK_WORDS = (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK)
#: At most this many rows ride in one envelope.
MAX_CARRIED_CHECKS = 64
#: One carried row, as compact JSON, is at most this many bytes (a relayed row
#: is 1 to 3 KiB; one kept with its vendor_payload may not fit, by design).
MAX_CARRIED_CHECK_BYTES = 16 << 10
#: All carried rows together are at most this many bytes, so the base64 payload
#: stays well under MAX_ENVELOPE_BYTES and `verify` can still read the sidecar.
MAX_CARRIED_CHECKS_BYTES = 256 << 10
#: A --checks file bigger than this is not read by `seal`.
MAX_CHECKS_FILE_BYTES = 1 << 20

PROVES = ("the file's bytes are the bytes the named key sealed, under this label, "
          "for this audience, deal and purpose, before not_after")
DOES_NOT_PROVE = ("that the content is true or safe (a member can seal a lie honestly, T1), "
                  "that the key belongs to who the label says (you chose to trust it, T6), "
                  "anything about the pin or witness refs (recorded, not resolved), "
                  "or that the receiver's clock is right (not_after is judged by it)")


class SealError(ValueError):
    """`seal` refused: a binding field is missing or malformed, or the file or
    key could not be used. Nothing was written."""


# --- small shared pieces ------------------------------------------------------

def envelope_path(file: str | Path) -> Path:
    """The sidecar for `file`: FILE.envelope.json beside it."""
    p = Path(file)
    return p.with_name(p.name + SUFFIX)


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding: what is signed, never the JSON."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_TS_FMT)


def _parse_time(text: str) -> datetime | None:
    """An RFC 3339 time WITH a zone (Z or +hh:mm), or None. A time with no
    zone is refused: two readers would place it in two different hours."""
    if not isinstance(text, str) or not text.strip():
        return None
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _not_after(text: str, now: datetime) -> datetime:
    """--not-after: an RFC 3339 time with a zone, or a span from now (7d, 12h, 30m)."""
    m = _DURATION.fullmatch(str(text).strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return now + timedelta(**{{"d": "days", "h": "hours", "m": "minutes"}[unit]: n})
    dt = _parse_time(text)
    if dt is None:
        raise SealError(f"--not-after {text!r} is not a time with a zone "
                        f"(2026-10-11T00:00:00Z) or a span (7d, 12h, 30m)")
    return dt


def _text_ok(v: Any, limit: int = 512) -> bool:
    return (isinstance(v, str) and 0 < len(v.strip()) and len(v) <= limit
            and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in v))


#: base58btc, the alphabet did:key uses (the same as arcaeon.prove.vet.receipts,
#: repeated here so reading a key id does not import the signing backend).
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


#: An Ed25519 did:key is always this long: "did:key:z" + 47 base58 digits of
#: 0xed01 + the 32-byte key (checked against every key receipts.did_key makes).
DID_KEY_ED25519_LEN = 56

#: The longest base58 string _b58decode will read. Decoding is quadratic in the
#: length (one bigint digit per character), so an unbounded hostile string hangs.
_B58_MAX_CHARS = 128


def _b58decode(s: str) -> bytes:
    if len(s) > _B58_MAX_CHARS:
        raise ValueError(f"base58 text too long ({len(s)} chars, at most {_B58_MAX_CHARS})")
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError("not base58")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def _pubkey_from_did(did: str) -> bytes:
    """The raw Ed25519 key inside a did:key, or ValueError."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError("keyid is not a did:key")
    if len(did) != DID_KEY_ED25519_LEN:   # before decoding: a hostile length must not hang
        raise ValueError(f"did:key is not an Ed25519 key ({len(did)} chars, "
                         f"an Ed25519 did:key is {DID_KEY_ED25519_LEN})")
    raw = _b58decode(did[len("did:key:z"):])
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        raise ValueError("did:key is not an Ed25519 key")
    return raw[2:]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise ValueError("not a base64 string")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"not base64 ({e})") from None


def _load_seed(key_file: str | Path) -> bytes:
    """A 32-byte Ed25519 seed, base64 on one line (the vet receipts' key-file
    shape). Read only from the file named: no environment variable, no default."""
    try:
        raw = Path(key_file).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as e:
        raise SealError(f"the key file could not be read ({type(e).__name__})") from None
    try:
        seed = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise SealError("the key file is not base64") from None
    if len(seed) != 32:
        raise SealError(f"the key file must decode to 32 bytes, got {len(seed)}")
    return seed


# --- carried check rows (TE-31) ---------------------------------------------------

def _norm_sha(v: Any) -> str | None:
    """64 lower-case hex from a sha256 as a row may write it (case and a
    `sha256:` prefix ignored, the gate's reading), or None."""
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    return s if _HEX64.fullmatch(s) else None


def _check_file_items(p: Path) -> tuple[list[tuple[str, Any]], list[str]]:
    """((where, item), problems) for one --checks file: one JSON object, a JSON
    list, or JSON lines (the shapes `gate decide --checks` reads)."""
    try:
        if p.stat().st_size > MAX_CHECKS_FILE_BYTES:
            return [], [f"{p.name}: over {MAX_CHECKS_FILE_BYTES} bytes, not read"]
        text = p.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return [], [f"{p.name}: cannot be read ({type(e).__name__})"]
    if not text.strip():
        return [], [f"{p.name}: holds no rows"]
    try:
        doc = loads_strict(text)
    except (ValueError, RecursionError):
        doc = None
    if isinstance(doc, (dict, list)):
        items = doc if isinstance(doc, list) else [doc]
        if not items:
            return [], [f"{p.name}: holds no rows"]
        return [(f"{p.name} item {n}", x) for n, x in enumerate(items, 1)], []
    out, problems = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append((f"{p.name} line {n}", loads_strict(line)))
        except (ValueError, RecursionError) as e:
            problems.append(f"{p.name} line {n}: not JSON ({type(e).__name__})")
    return out, problems


def _row_problem(row: Any, sha: str) -> str | None:
    """Why `row` may not ride in an envelope sealing `sha`, or None."""
    if not isinstance(row, dict):
        return f"not a JSON object (a {type(row).__name__})"
    if row.get("kind") != CHECK_ROW_KIND:
        return f"kind {str(row.get('kind'))[:64]!r} is not {CHECK_ROW_KIND}"
    if row.get("relayed") is not True or row.get("checked_by_us") is not False:
        return "relayed is not true or checked_by_us is not false: not a relayed row"
    if row.get("relayed_verdict") not in _CHECK_WORDS:
        return (f"relayed_verdict {str(row.get('relayed_verdict'))[:64]!r} is not one of "
                f"{', '.join(_CHECK_WORDS)}")
    subj = row.get("subject")
    got = _norm_sha(subj.get("sha256")) if isinstance(subj, dict) else None
    if got is None:
        return "no subject.sha256: the row does not say which bytes it judged"
    if got != sha:
        return f"its subject.sha256 is {got}, the sealed file's sha256 is {sha}"
    return None


def carried_check_rows(sources, sha: str) -> list[dict]:
    """The check rows `seal` carries for a file whose sha256 is `sha`. Each
    source is a path to a --checks file (one JSON object, a list, or JSON
    lines) or a row dict. Every row must be a check.verdict.relayed row (relayed,
    not checked by us, a relayed_verdict in our three words) whose
    subject.sha256 is `sha`; any other row, a file that cannot be read or holds
    none, more than MAX_CARRIED_CHECKS rows, a row over MAX_CARRIED_CHECK_BYTES
    or all of them over MAX_CARRIED_CHECKS_BYTES raises SealError naming each
    one. Nothing is dropped: a row rides as given, or the seal is refused."""
    items: list[tuple[str, Any]] = []
    problems: list[str] = []
    for n, src in enumerate(sources or (), 1):
        if isinstance(src, dict):
            items.append((f"checks= row {n}", src))
            continue
        got, bad = _check_file_items(Path(src))
        items.extend(got)
        problems.extend(bad)
    rows, total = [], 0
    for where, row in items:
        why = _row_problem(row, sha)
        if why is None:
            try:
                size = len(json.dumps(row, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=False).encode("utf-8"))
            except (TypeError, ValueError) as e:
                why = f"not plain JSON ({type(e).__name__})"
            else:
                if size > MAX_CARRIED_CHECK_BYTES:
                    why = (f"{size} bytes as JSON, over the {MAX_CARRIED_CHECK_BYTES}-byte "
                           f"limit for one carried row (import it without its vendor_payload)")
                total += size
        if why is not None:
            problems.append(f"{where}: {why}")
        else:
            rows.append(row)
    if len(items) > MAX_CARRIED_CHECKS:
        problems.append(f"{len(items)} rows given; an envelope carries at most "
                        f"{MAX_CARRIED_CHECKS}")
    elif total > MAX_CARRIED_CHECKS_BYTES:
        problems.append(f"the rows are {total} bytes together, over the "
                        f"{MAX_CARRIED_CHECKS_BYTES}-byte limit an envelope carries")
    if problems:
        more = f" (and {len(problems) - 8} more)" if len(problems) > 8 else ""
        raise SealError("refusing to carry check rows: " + "; ".join(problems[:8]) + more
                        + f". Only {CHECK_ROW_KIND} rows for this file's sha256 ride, and "
                        f"none is dropped")
    return [json.loads(json.dumps(r)) for r in rows]         # a plain-JSON copy


# --- seal -----------------------------------------------------------------------

def build_statement(file: str | Path, *, label: str, audience: str, deal: str, purpose: str,
                    not_after: str, sealed_by: str | None = None, key_id: str | None = None,
                    chain: str | None = None, pin_ref: str | None = None,
                    witness_ref: str | None = None, flags: list[str] | tuple = (),
                    now: datetime | None = None, checks=None) -> dict:
    """The in-toto Statement for `file`. SealError when a binding field is
    missing or malformed or the file cannot be read; nothing is written.
    `checks` (paths of --checks files, or row dicts) puts the check rows in
    predicate.checks (carried_check_rows says which may ride); empty or None
    writes no checks key at all."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    fields = {"label": label, "audience": audience, "deal": deal, "purpose": purpose,
              "not-after": not_after}
    missing = [k for k, v in fields.items() if not (isinstance(v, str) and v.strip())]
    if missing:
        raise SealError("refusing to seal an unbound envelope: missing "
                        + ", ".join("--" + k for k in missing)
                        + " (audience, deal, purpose and not-after bind it to one exchange)")
    for k in ("label", "audience", "deal", "purpose"):
        if not _text_ok(fields[k]):
            raise SealError(f"--{k} must be one line of text, at most 512 characters")
    if sealed_by is not None and not _text_ok(sealed_by):
        raise SealError("--by must be one line of text, at most 512 characters")
    na = _not_after(not_after, now)
    if na <= now:
        raise SealError(f"--not-after {_utc(na)} is not after now ({_utc(now)})")
    if chain is not None and not _text_ok(chain, 256):
        raise SealError("--chain must be one line of text, at most 256 characters")
    if pin_ref is not None and not _PIN_REF.fullmatch(pin_ref):
        raise SealError("--pin-ref must be sha256:<64 hex> (or sha256:json-c14n:v1:<64 hex>, "
                        "sha256:raw-bytes:v1:<64 hex>)")
    if witness_ref is not None and not _WITNESS_REF.fullmatch(witness_ref):
        raise SealError("--witness-ref must be an https:// URL or a urn:")
    flags = list(flags or ())
    bad = [f for f in flags if not (isinstance(f, str) and _FLAG.fullmatch(f))]
    if bad:
        raise SealError(f"--flag {bad[0]!r}: lower-case letters, digits and _ . : - only, "
                        f"at most 64 characters")
    pin = file_pin(file)
    if "sha256" not in pin:
        raise SealError(f"cannot read the file to seal ({pin.get('error')})")
    carried = carried_check_rows(checks, pin["sha256"]) if checks else None
    stmt = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": Path(file).name, "digest": {"sha256": pin["sha256"]}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "version": PREDICATE_VERSION,
            "label": label,
            "sealed_by": {"name": sealed_by, "key": key_id},
            "sealed_at": _utc(now),
            "chain": chain,
            "pin_ref": pin_ref,
            "witness_ref": witness_ref,
            "flags": sorted(set(flags)),
            "binding": {"audience": audience, "deal": deal, "purpose": purpose,
                        "not_after": _utc(na)},
            "bytes": pin["bytes"],
        },
    }
    if carried is not None:
        stmt["predicate"][CHECKS_KEY] = carried
    return stmt


def seal(file: str | Path, *, key_file: str | Path | None = None, force: bool = False,
         **fields) -> dict:
    """Write FILE.envelope.json and return the envelope. `fields` are
    build_statement's keywords. With `key_file` the statement is signed
    (Ed25519 over PAE); without it the envelope is UNSIGNED. SealError on any
    refusal, before anything is written."""
    out = envelope_path(file)
    if out.exists() and not force:
        raise SealError(f"{out.name} already exists; pass --force to replace it")
    seed = pub = None
    key_id = None
    if key_file is not None:
        seed = _load_seed(key_file)
        try:
            from arcaeon.prove.vet import receipts as R
            pub = R.public_key_from_seed(seed)
        except Exception as e:  # noqa: BLE001  ReceiptsUnavailable: no backend
            raise SealError(f"signing needs an Ed25519 backend: pip install 'arcaeon[sign]' "
                            f"({type(e).__name__})") from None
        key_id = R.did_key(pub)
    statement = build_statement(file, key_id=key_id, **fields)
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    sigs = []
    if seed is not None:
        sig = R._sign_bytes(seed, pae(PAYLOAD_TYPE, payload))
        sigs.append({"keyid": key_id, "sig": _b64(sig)})
    env = {"mediaType": MEDIA_TYPE,
           "dsseEnvelope": {"payloadType": PAYLOAD_TYPE, "payload": _b64(payload),
                            "signatures": sigs}}
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(env, indent=1) + "\n")
    return env


# --- verify ---------------------------------------------------------------------

def _report(file, env_path) -> dict:
    return {"verdict": None, "reason": None, "file": str(file), "file_sha256": None,
            "envelope": str(env_path),
            "steps": {"envelope": None, "signature": None, "file": None, "binding": None,
                      "witness": None},
            "sealed": None, "signers": [], "findings": [], "not_checked": [],
            "proves": PROVES, "does_not_prove": DOES_NOT_PROVE}


def _could_not_look(r: dict, step: str, looked_for: str, where, reason_word: str,
                    reason: str) -> dict:
    r["steps"][step] = V.COULD_NOT_LOOK
    r.update({"verdict": V.COULD_NOT_LOOK, "reason": reason,
              **V.could_not_look(looked_for, str(where), reason_word, reason)})
    return r


def _read_envelope(r: dict, env_path: Path):
    """The sidecar as (dsse dict, payload bytes), or None with r set to COULD NOT LOOK."""
    if not env_path.exists():
        return _could_not_look(r, "envelope", "the envelope sidecar", env_path, "missing",
                               f"no {env_path.name} beside the file: nothing says what it is "
                               f"or who sealed it")
    try:
        if env_path.stat().st_size > MAX_ENVELOPE_BYTES:
            return _could_not_look(r, "envelope", "the envelope sidecar", env_path, "unreadable",
                                   f"the sidecar is over {MAX_ENVELOPE_BYTES} bytes; not read")
        text = env_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _could_not_look(r, "envelope", "the envelope sidecar", env_path, "unreadable",
                               f"the sidecar cannot be read as UTF-8 text ({type(e).__name__})")
    try:
        env = loads_strict(text)
    except ValueError as e:
        return _could_not_look(r, "envelope", "the envelope sidecar", env_path, "unreadable",
                               f"the sidecar is not one JSON object ({str(e)[:120]})")
    if not isinstance(env, dict) or env.get("mediaType") != MEDIA_TYPE:
        return _could_not_look(r, "envelope", "an arcaeon envelope", env_path, "unreadable",
                               f"the sidecar is not an envelope this verifier reads "
                               f"(mediaType must be {MEDIA_TYPE})")
    dsse = env.get("dsseEnvelope")
    if not isinstance(dsse, dict) or dsse.get("payloadType") != PAYLOAD_TYPE \
            or not isinstance(dsse.get("signatures"), list):
        return _could_not_look(r, "envelope", "a DSSE envelope with an in-toto payload",
                               env_path, "unreadable",
                               "the sidecar's dsseEnvelope is missing or not an in-toto DSSE envelope")
    try:
        payload = _unb64(dsse.get("payload"))
    except ValueError as e:
        return _could_not_look(r, "envelope", "the DSSE payload", env_path, "unreadable",
                               f"the payload is {e}")
    extra = sorted((set(env) - _TOP_KEYS) | {"dsseEnvelope." + k for k in set(dsse) - _DSSE_KEYS})
    if extra:
        r["findings"].append(f"fields outside the signed payload: {', '.join(extra)}")
        r["steps"]["envelope"] = V.BROKEN
    else:
        r["steps"]["envelope"] = V.VERIFIED
    return dsse, payload


def _check_signatures(r: dict, dsse: dict, payload: bytes, signers: tuple) -> None:
    sigs = dsse["signatures"]
    st = r["steps"]
    if not sigs:
        st["signature"] = V.COULD_NOT_LOOK
        r["_cnl"].append(("signature", "a signature on the envelope", "missing",
                          "the envelope is UNSIGNED: anyone who can write the sidecar could "
                          "have written it, so who sealed the bytes cannot be checked"))
        return
    try:
        from arcaeon.prove.vet import receipts as R
        R._require_backend()
    except Exception:  # noqa: BLE001  no Ed25519 backend in this install
        st["signature"] = V.COULD_NOT_LOOK
        r["_cnl"].append(("signature", "an Ed25519 backend to check the signature", "missing",
                          "this install cannot check Ed25519: pip install 'arcaeon[sign]'"))
        return
    message = pae(PAYLOAD_TYPE, payload)
    valid = []
    for i, s in enumerate(sigs):
        try:
            if not isinstance(s, dict):
                raise ValueError("not an object")
            pub = _pubkey_from_did(s.get("keyid"))
            sig = _unb64(s.get("sig"))
        except ValueError as e:
            r["findings"].append(f"signature {i}: {e}")
            continue
        if R._verify_bytes(pub, message, sig):
            valid.append(s["keyid"])
        else:
            r["findings"].append(f"signature {i} by {s['keyid']} does not verify over the payload "
                                 f"(the payload or the signature was changed)")
    r["signers"] = valid
    if len(valid) != len(sigs):
        st["signature"] = V.BROKEN
        return
    if not signers:
        st["signature"] = V.COULD_NOT_LOOK
        r["_cnl"].append(("signature", "the key you trust (--signer)", "bounded",
                          f"signed by {', '.join(valid)}, a valid signature from a key you did "
                          f"not name: pass --signer with the key you expect"))
        return
    if not set(valid) & set(signers):
        st["signature"] = V.BROKEN
        r["findings"].append(f"signed by {', '.join(valid)}, not by the signer you named")
        return
    st["signature"] = V.VERIFIED


def _statement(r: dict, payload: bytes):
    """The decoded Statement, or None (r's envelope step set)."""
    # Strict: a duplicate key anywhere in the payload is unreadable, the same as
    # in the sidecar. Under JSON's last-key-wins two parsers would read two
    # different labels or bindings from bytes that carry one valid signature.
    try:
        stmt = loads_strict(payload.decode("utf-8"))
    except DuplicateKeyError as e:
        if r["steps"]["envelope"] != V.BROKEN:          # never hide a BROKEN
            r["steps"]["envelope"] = V.COULD_NOT_LOOK
        r["_cnl"].append(("envelope", "an in-toto Statement in the payload", "unreadable",
                          f"the payload repeats a key ({str(e)[:120]}): two readers would see "
                          f"two different statements"))
        return None
    except (UnicodeDecodeError, ValueError) as e:
        r["_cnl"].append(("envelope", "an in-toto Statement in the payload", "unreadable",
                          f"the payload is not JSON ({type(e).__name__})"))
        return None
    if not isinstance(stmt, dict) or stmt.get("_type") != STATEMENT_TYPE \
            or stmt.get("predicateType") != PREDICATE_TYPE:
        r["_cnl"].append(("envelope", "an in-toto Statement of the labeled-exchange type",
                          "unreadable", f"the payload is not a {STATEMENT_TYPE} statement with "
                          f"predicateType {PREDICATE_TYPE}"))
        return None
    return stmt


def _pin_locator(wit) -> tuple[str | None, str | None]:
    """(chain, stamp) named by a witness_ref, or (None, None). The stamp is the
    first <YYYY-MM-DD>T<HHMM>Z segment of the URL or urn; the chain is the
    segment before it (a hint, used only to pick between same-named stamps)."""
    if not isinstance(wit, str):
        return None, None
    parts = re.split(r"[/:]", wit)
    for i, p in enumerate(parts):
        if _STAMP.fullmatch(p):
            return (parts[i - 1] or None) if i else None, p
    return None, None


def _pin_folders(root: Path) -> list[Path]:
    """Every folder at most _PINS_DEPTH below root (root included) that holds a
    statement.json, sorted. OSError when root cannot be listed."""
    out, level = [], [root]
    for depth in range(_PINS_DEPTH + 1):
        nxt = []
        for d in level:
            if (d / PIN_STATEMENT).is_file():
                out.append(d)
            if depth < _PINS_DEPTH:
                try:
                    kids = [k for k in d.iterdir() if k.is_dir() and not k.is_symlink()]
                except OSError:
                    if d == root:
                        raise
                    continue
                nxt.extend(kids)
        level = nxt
    return sorted(out)


def _pin_digest(folder: Path, c14n: bool) -> str | None:
    """sha256 hex of folder/statement.json (its bytes, or for a json-c14n:v1
    pin_ref its parsed value), or None when it cannot be read."""
    p = folder / PIN_STATEMENT
    try:
        if p.stat().st_size > MAX_PIN_STATEMENT_BYTES:
            return None
        raw = p.read_bytes()
    except OSError:
        return None
    if not c14n:
        return hashlib.sha256(raw).hexdigest()
    try:
        return digest_json(loads_strict(raw.decode("utf-8")))[len(JSON_C14N_PREFIX):]
    except (UnicodeDecodeError, ValueError):
        return None


def resolve_pin(pins: str | Path, pin_ref: str, witness_ref: str | None = None) -> dict:
    """Resolve pin_ref against a local pins clone, offline. -> {"word", "reason",
    "reason_word", "pin"}: VERIFIED with the pin folder when its statement digest
    matches; BROKEN when the pin the witness_ref names is there with another
    digest; COULD NOT LOOK when the pin is not there or the clone is unreadable."""
    c14n = pin_ref.startswith(JSON_C14N_PREFIX)
    want = pin_ref.rsplit(":", 1)[1]
    root = Path(pins)

    def cnl(rw, reason):
        return {"word": V.COULD_NOT_LOOK, "reason_word": rw, "reason": reason, "pin": None}

    if not root.exists():
        return cnl("missing", f"--pins {root} does not exist")
    if not root.is_dir():
        return cnl("unreadable", f"--pins {root} is not a folder")
    try:
        folders = _pin_folders(root)
    except OSError as e:
        return cnl("unreadable", f"--pins {root} cannot be listed ({type(e).__name__})")
    if not folders:
        return cnl("empty", f"--pins {root} holds no pin folder with a {PIN_STATEMENT} "
                            f"(expected tips/<chain>/<YYYY-MM-DD>T<HHMM>Z/{PIN_STATEMENT})")
    hint, stamp = _pin_locator(witness_ref)
    if stamp is not None:
        folders = [f for f in folders if f.name == stamp]
        if len(folders) > 1 and hint:
            folders = [f for f in folders if f.parent.name == hint] or folders
        if not folders:
            return cnl("missing", f"the pin {stamp} the witness_ref names is not in --pins "
                                  f"{root} (a clone older than the pin, or no such pin)")
    got = [(f, _pin_digest(f, c14n)) for f in folders]
    for f, d in got:
        if d == want:
            return {"word": V.VERIFIED, "reason_word": None, "reason": None,
                    "pin": {"folder": str(f), "statement_sha256": want, "pin_ref": pin_ref}}
    if any(d is None for _, d in got):
        bad = next(f for f, d in got if d is None)
        return cnl("unreadable", f"{bad / PIN_STATEMENT} cannot be read (or is over "
                                 f"{MAX_PIN_STATEMENT_BYTES} bytes, or not JSON for a "
                                 f"json-c14n:v1 pin_ref)")
    if stamp is None:
        return cnl("missing", f"no pin statement under --pins {root} has digest {want} (a pin "
                              f"not yet in this clone cannot be told from one never made)")
    if len(got) > 1:
        return cnl("bounded", f"{len(got)} pins are named {stamp} under --pins {root} and none "
                              f"has digest {want}: point --pins at the chain folder")
    return {"word": V.BROKEN, "reason_word": None, "pin": None,
            "reason": f"the pin {got[0][0].name} the witness_ref names has statement digest "
                      f"{got[0][1]}, the pin_ref sealed {want}: the pin is not the one sealed"}


def _check_predicate(r: dict, stmt: dict, file: Path, audience, deal, purpose,
                     now: datetime, pins=None) -> None:
    st, find = r["steps"], r["findings"]
    pred = stmt.get("predicate")
    subj = stmt.get("subject")
    # --- the file -----------------------------------------------------------
    want = None
    if isinstance(subj, list) and len(subj) == 1 and isinstance(subj[0], dict) \
            and isinstance(subj[0].get("digest"), dict):
        want = subj[0]["digest"].get("sha256")
    if not (isinstance(want, str) and _HEX64.fullmatch(want)):
        st["file"] = V.BROKEN
        find.append("the statement does not name exactly one subject with a sha256 digest")
    else:
        pin = file_pin(file)
        r["file_sha256"] = pin.get("sha256")             # the bytes this check compared
        if "sha256" not in pin:
            st["file"] = V.COULD_NOT_LOOK
            rw = pin.get("reason_word", "unreadable")
            r["_cnl"].append(("file", "the file the envelope names", rw if rw in V.REASON_WORDS
                              else "unreadable", f"the file cannot be read ({pin.get('error')})"))
        elif pin["sha256"] != want:
            st["file"] = V.BROKEN
            find.append(f"the file's sha256 is {pin['sha256']}, the envelope sealed {want}: "
                        f"the bytes changed after sealing")
        else:
            st["file"] = V.VERIFIED
            if subj[0].get("name") != file.name:
                r["note"] = (f"sealed under the name {subj[0].get('name')!r}; the bytes match, "
                             f"the name is not part of the check")
    # --- the predicate and its binding ---------------------------------------
    if not isinstance(pred, dict):
        st["binding"] = V.BROKEN
        find.append("the statement carries no predicate: an unbound envelope is refused")
        return
    r["sealed"] = {k: pred.get(k) for k in sorted(_PREDICATE_KEYS)}
    if CHECKS_KEY in pred:                       # TE-31: only when the sealer carried rows
        r["sealed"][CHECKS_KEY] = pred[CHECKS_KEY]
        r["not_checked"].append(
            "the carried check rows (checks[]): signed by the sealer, so they are the "
            "sender's report of a checker's word, not re-judged here; `gate decide` reads "
            "them like --checks rows")
    key =(pred.get("sealed_by") or {}).get("key") if isinstance(pred.get("sealed_by"), dict) \
        else None
    if key is not None and r["signers"] and key not in r["signers"]:
        st["signature"] = V.BROKEN
        find.append(f"the label says sealed by {key}, the signature is by "
                    f"{', '.join(r['signers'])}")
    if pred.get("version") != PREDICATE_VERSION or not _text_ok(pred.get("label")):
        st["binding"] = V.BROKEN
        find.append("the predicate has no label or an unknown version")
        return
    b = pred.get("binding")
    absent = [k for k in BINDING_FIELDS if not (isinstance(b, dict) and _text_ok(b.get(k)))]
    if absent:
        st["binding"] = V.BROKEN
        find.append(f"unbound envelope refused: no {', '.join(absent)} (T3: it could be "
                    f"replayed into another exchange)")
        return
    na = _parse_time(b["not_after"])
    if na is None:
        st["binding"] = V.BROKEN
        find.append(f"not_after {b['not_after']!r} is not a time with a zone")
        return
    bad = []
    if now > na:
        bad.append(f"expired: not_after {_utc(na)} is before now ({_utc(now)})")
    # Exact bytes, by design: no Unicode normalization, no case folding, no
    # trimming. A homoglyph, a case change or a stray space is another receiver.
    for name, given in (("audience", audience), ("deal", deal), ("purpose", purpose)):
        if given is not None and given != b[name]:
            bad.append(f"{name}: sealed for {b[name]!r}, you are checking for {given!r}")
    if bad:
        st["binding"] = V.BROKEN
        find.extend(bad)
    elif audience is None:
        st["binding"] = V.COULD_NOT_LOOK
        r["_cnl"].append(("binding", "who you are (--audience)", "bounded",
                          f"sealed for {b['audience']!r}; pass --audience so the envelope is "
                          f"checked against its receiver"))
    else:
        st["binding"] = V.VERIFIED
        for name, given in (("deal", deal), ("purpose", purpose)):
            if given is None:
                r["not_checked"].append(f"{name} (recorded as {b[name]!r}; pass --{name} to hold "
                                        f"the envelope to it)")
    # --- pin and witness refs: shape only ------------------------------------
    pin_ref, wit = pred.get("pin_ref"), pred.get("witness_ref")
    shape = []
    if pin_ref is not None and not (isinstance(pin_ref, str) and _PIN_REF.fullmatch(pin_ref)):
        shape.append("pin_ref is not sha256:<64 hex>")
    if wit is not None and not (isinstance(wit, str) and _WITNESS_REF.fullmatch(wit)):
        shape.append("witness_ref is not an https:// URL or a urn:")
    chain = pred.get("chain")
    if chain is not None and not _text_ok(chain, 256):
        shape.append("chain is not one line of text")
    if shape:
        st["witness"] = V.BROKEN
        find.extend(shape)
    elif pin_ref is None and wit is None:
        st["witness"] = NOT_CLAIMED
    elif pins is not None and pin_ref is not None:
        res = resolve_pin(pins, pin_ref, wit)
        st["witness"] = res["word"]
        r["pin"] = res["pin"]
        if res["word"] == V.BROKEN:
            find.append(res["reason"])
        elif res["word"] == V.COULD_NOT_LOOK:
            r["_pin_cnl"] = ("pins", "the pin the pin_ref names, in --pins",
                             res["reason_word"], res["reason"])
        else:
            r["not_checked"].append(
                "the pin's proofs (.ots, Bitcoin) and that --pins is a faithful clone of the "
                "public pins: run verify_pins for those; the witness_ref is not fetched")
    else:
        st["witness"] = V.COULD_NOT_LOOK
        r["not_checked"].append("pin_ref / witness_ref: recorded and shape-checked, not resolved "
                                "(resolving them needs the network; out of scope here)")


def verify(file: str | Path, envelope: str | Path | None = None, *, audience: str | None = None,
           deal: str | None = None, purpose: str | None = None, signers=(),
           require_witness: bool = False, now: datetime | None = None,
           pins: str | Path | None = None) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK for FILE against its envelope.

    BROKEN if anything checked came out wrong (bytes, signature, a field
    outside the signature, an unbound or expired envelope, another audience,
    deal or purpose than the one given). Else COULD NOT LOOK if a step that
    decides the verdict could not be checked (missing or garbage sidecar,
    unsigned, no --signer, no --audience, no Ed25519 backend; the witness step
    only under require_witness). Else VERIFIED. Never raises.

    `pins`, a local pins clone, resolves the pin_ref offline (resolve_pin);
    without it nothing about the pin or witness refs is resolved."""
    file = Path(file)
    env_path = Path(envelope) if envelope is not None else envelope_path(file)
    r = _report(file, env_path)
    if pins is not None:
        r["pin"] = None
    try:
        out = _verify(r, file, env_path, audience, deal, purpose, tuple(signers or ()),
                      require_witness, (now or datetime.now(timezone.utc)), pins)
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        r.pop("_cnl", None)
        r.pop("_pin_cnl", None)
        out = _could_not_look(r, "envelope", "a finished check", env_path, "unreadable",
                              f"the check could not finish ({type(e).__name__})")
    return _with_file_sha256(out, file)


def _with_file_sha256(r: dict, file: Path) -> dict:
    """The handed file's sha256 on every word, so a report carries it even
    when the check stopped before the file step (no sidecar, unreadable
    payload). The file step's own hash wins when it ran; a file that cannot
    be read stays null. Never raises: the verdict stands either way."""
    if r.get("file_sha256") is None:
        try:
            r["file_sha256"] = file_pin(file).get("sha256")
        except Exception:  # noqa: BLE001
            r["file_sha256"] = None
    return r


def _verify(r, file, env_path, audience, deal, purpose, signers, require_witness, now,
            pins=None) -> dict:
    got = _read_envelope(r, env_path)
    if isinstance(got, dict):
        return got                                   # COULD NOT LOOK already set
    dsse, payload = got
    if not file.exists():
        return _could_not_look(r, "file", "the file the envelope names", file, "missing",
                               "the file is not there; the envelope alone proves nothing")
    r["_cnl"] = []
    _check_signatures(r, dsse, payload, signers)
    stmt = _statement(r, payload)
    if stmt is not None:
        _check_predicate(r, stmt, file, audience, deal, purpose, now.astimezone(timezone.utc),
                         pins)
    cnl = r.pop("_cnl")
    pin_cnl = r.pop("_pin_cnl", None)
    steps = r["steps"]
    if V.BROKEN in steps.values():
        broken = [k for k, v in steps.items() if v == V.BROKEN]
        r["verdict"] = V.BROKEN
        r["reason"] = "; ".join(r["findings"]) or f"step(s) {', '.join(broken)} failed"
        return r
    if require_witness and pin_cnl is not None:
        cnl.append(pin_cnl)
    elif require_witness and steps["witness"] in (V.COULD_NOT_LOOK, NOT_CLAIMED):
        cnl.append(("witness", "a resolved pin / witness ref", "network",
                    "--require-witness: the pin and witness refs are not resolved offline "
                    "(or none was recorded), so the witness step could not look"))
    if cnl:
        step, looked_for, rw, reason = cnl[0]
        where = file if step == "file" else (pins if step == "pins" else env_path)
        r.update(V.could_not_look(looked_for, str(where), rw, reason))
        r["verdict"] = V.COULD_NOT_LOOK
        r["reason"] = "; ".join(c[3] for c in cnl)      # every step that could not look
        return r
    r["verdict"] = V.VERIFIED
    r["reason"] = PROVES
    return r


# --- CLI ------------------------------------------------------------------------

USAGE = """usage: arcaeon envelope seal <file> --label TEXT --audience ID --deal ID
                               --purpose TEXT --not-after WHEN [--key SEEDFILE]
                               [--by NAME] [--chain ID] [--pin-ref REF]
                               [--witness-ref REF] [--flag NAME ...]
                               [--checks FILE ...] [--force]
       arcaeon envelope verify <file> [--audience ID] [--signer DID ...]
                               [--deal ID] [--purpose TEXT] [--envelope PATH]
                               [--require-witness] [--pins DIR]"""

HELP = USAGE + """

seal writes <file>.envelope.json: an in-toto Statement (subject = the file's
sha256) in a DSSE envelope, bound to one exchange. --label, --audience,
--deal, --purpose and --not-after are required (an unbound envelope is refused).
--not-after is a time with a zone (2026-10-11T00:00:00Z) or a span (7d, 12h,
30m). --key signs with Ed25519 (a 32-byte seed, base64, one line; needs
arcaeon[sign]); without it the envelope is UNSIGNED and verify will answer
COULD NOT LOOK on it.

--checks FILE (repeatable) carries check.verdict.relayed rows (a connector
adapter's output: one JSON object, a list, or JSON lines) inside the signed
Statement, as predicate.checks: editing a carried row breaks the signature.
Every row must name this file's sha256 as subject.sha256; any other row, or
a FILE that cannot be read, refuses the seal (exit 2) naming it. At most 64
rows, 16 KiB each, 256 KiB together. A carried row is the sender's report:
`gate decide` reads it like a --checks row (a BROKEN vetoes act, pay and
irreversible), and it never makes anything VERIFIED. Without --checks the
envelope is exactly what it was before checks[] existed.

verify answers VERIFIED (act), BROKEN (refuse, keep the evidence) or COULD NOT
LOOK (do not act on money or an irreversible step), as JSON on stdout and one
line on stderr. VERIFIED needs a signature by a key you name (--signer
did:key:...) and your own id (--audience). Pin and witness refs are recorded
and shape-checked, never fetched (that needs the network). --pins DIR, a local
clone of a pins repo (tips/<chain>/<stamp>/statement.json), resolves the
pin_ref offline: the statement digest matches = VERIFIED, the pin not in the
clone = COULD NOT LOOK, the pin the witness_ref names there with another
digest = BROKEN.

Exit codes: 0 VERIFIED (seal: written), 1 BROKEN, 2 bad usage or a refused
seal, 3 COULD NOT LOOK. Spec and limits: docs/ENVELOPE.md."""


class _Usage(Exception):
    pass


def _parse(argv: list[str], spec: dict[str, str]) -> tuple[list[str], dict]:
    """A tiny flag parser: spec maps --flag to 'value', 'list' or 'bool'."""
    pos, opts, i = [], {}, 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and "=" in a:
            a, val = a.split("=", 1)
            argv = argv[:i] + [a, val] + argv[i + 1:]
        if a.startswith("-") and len(a) > 1:
            kind = spec.get(a)
            if kind is None:
                raise _Usage(f"unknown option {a}")
            if kind == "bool":
                opts[a] = True
                i += 1
                continue
            if i + 1 >= len(argv):
                raise _Usage(f"{a} needs a value")
            if kind == "list":
                opts.setdefault(a, []).append(argv[i + 1])
            else:
                opts[a] = argv[i + 1]
            i += 2
            continue
        pos.append(a)
        i += 1
    return pos, opts


_SEAL_SPEC = {"--label": "value", "--audience": "value", "--deal": "value",
              "--purpose": "value", "--not-after": "value", "--key": "value", "--by": "value",
              "--chain": "value", "--pin-ref": "value", "--witness-ref": "value",
              "--flag": "list", "--checks": "list", "--force": "bool"}
_VERIFY_SPEC = {"--audience": "value", "--signer": "list", "--deal": "value",
                "--purpose": "value", "--envelope": "value", "--require-witness": "bool",
                "--pins": "value"}


def _seal_cli(argv: list[str]) -> int:
    pos, o = _parse(argv, _SEAL_SPEC)
    if len(pos) != 1:
        raise _Usage("seal takes one file")
    target = Path(pos[0])
    if not target.is_file():
        why = "it does not exist" if not target.exists() else "it is not a regular file"
        cnl = V.could_not_look("the file to seal", pos[0], "missing" if not target.exists()
                               else "unreadable", f"cannot seal {pos[0]}: {why}")
        print(json.dumps({"ok": False, "verdict": V.COULD_NOT_LOOK, **cnl}, indent=1))
        print(f"{V.COULD_NOT_LOOK}: cannot seal {pos[0]}: {why}; nothing was written",
              file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    try:
        env = seal(target, key_file=o.get("--key"), force=bool(o.get("--force")),
                   label=o.get("--label"), audience=o.get("--audience"), deal=o.get("--deal"),
                   purpose=o.get("--purpose"), not_after=o.get("--not-after"),
                   sealed_by=o.get("--by"), chain=o.get("--chain"), pin_ref=o.get("--pin-ref"),
                   witness_ref=o.get("--witness-ref"), flags=o.get("--flag", []),
                   checks=o.get("--checks"))
    except SealError as e:
        print(f"arcaeon envelope seal: {e}; nothing was written", file=sys.stderr)
        return V.EXIT_USAGE
    stmt = json.loads(base64.b64decode(env["dsseEnvelope"]["payload"]))
    signed = bool(env["dsseEnvelope"]["signatures"])
    out = {"ok": True, "envelope": str(envelope_path(target)), "signed": signed,
           "signer": stmt["predicate"]["sealed_by"]["key"]}
    if CHECKS_KEY in stmt["predicate"]:
        out["carried_checks"] = len(stmt["predicate"][CHECKS_KEY])
    out["statement"] = stmt
    print(json.dumps(out, indent=1, ensure_ascii=False))
    if not signed:
        print("UNSIGNED: no --key, so `envelope verify` will answer COULD NOT LOOK on who "
              "sealed it", file=sys.stderr)
    return V.EXIT_GOOD


def _verify_cli(argv: list[str]) -> int:
    pos, o = _parse(argv, _VERIFY_SPEC)
    if len(pos) != 1:
        raise _Usage("verify takes one file")
    r = verify(pos[0], o.get("--envelope"), audience=o.get("--audience"), deal=o.get("--deal"),
               purpose=o.get("--purpose"), signers=o.get("--signer", []),
               require_witness=bool(o.get("--require-witness")), pins=o.get("--pins"))
    print(json.dumps(r, indent=1, ensure_ascii=False))
    print(f"{r['verdict']}: {r['reason']}", file=sys.stderr)
    return V.exit_for(r["verdict"])


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") or any(a in ("-h", "--help") for a in argv):
        print(HELP)
        return V.EXIT_GOOD if argv else V.EXIT_USAGE
    sub, rest = argv[0], argv[1:]
    try:
        if sub == "seal":
            return _seal_cli(rest)
        if sub == "verify":
            return _verify_cli(rest)
        raise _Usage(f"unknown subcommand {sub!r} (seal or verify)")
    except _Usage as e:
        print(f"arcaeon envelope: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
