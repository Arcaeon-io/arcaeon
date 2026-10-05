# SPDX-License-Identifier: MIT
"""Write the signed latest.json that `arcaeon`'s version check-in reads.

    py tools/make_latest_json.py --latest 0.11.0 --minimum-supported 0.9.0 \\
        [--block-after-version 0.12.0 --block-after-date YYYY-MM-DD] \\
        [--notice TEXT] [--issued-at 2026-10-05T00:00:00Z] \\
        (--key-file PATH | --key-env NAME) [--out latest.json]

The payload (kind arcaeon.latest, schema 1) is signed with Ed25519 over its
JCS canonical bytes, the exact bytes arcaeon.checkin verifies, and the file is
verified once more before it is written. The signer's did:key (public) is
printed on stderr so the release owner can compare it with
arcaeon.checkin.CHECKIN_KEYS; a signer not in that list is warned about,
because clients of this checkout would ignore the file.

THE KEY. A 32-byte Ed25519 seed, base64 on one line, read from the file named
by --key-file, or from the file whose path is in the environment variable
NAMED by --key-env (the variable holds a path, never the key). The seed is
never printed, and this tool never makes a key. --test-key is the door for
tests: it only accepts a file whose name contains TEST_ONLY, and --key-file
refuses such a file, so a test key cannot sign a real release by accident.

Needs the `cryptography` package (pip install 'arcaeon[sign]'). Exit 0
written, 2 refused (usage, a bad field, no key, no backend); nothing is
written on a refusal.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from arcaeon import checkin  # noqa: E402
from arcaeon.prove import jcs  # noqa: E402

TEST_MARK = "TEST_ONLY"
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class Refused(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="make_latest_json",
                                description="write the signed latest.json")
    p.add_argument("--latest", required=True)
    p.add_argument("--minimum-supported", required=True)
    p.add_argument("--block-after-version")
    p.add_argument("--block-after-date", help="YYYY-MM-DD, set by the release owner")
    p.add_argument("--notice")
    p.add_argument("--issued-at", help="UTC, 2026-10-05T00:00:00Z (default: now)")
    p.add_argument("--key-file", help="path to the seed file")
    p.add_argument("--key-env", help="NAME of an environment variable holding the seed file's path")
    p.add_argument("--test-key", help="tests only: a seed file whose name contains TEST_ONLY")
    p.add_argument("--out", help="where to write (default: stdout)")
    return p


def _key_path(a) -> tuple[Path, bool]:
    doors = [d for d in (a.key_file, a.key_env, a.test_key) if d]
    if len(doors) != 1:
        raise Refused("give exactly one of --key-file, --key-env, --test-key")
    if a.test_key:
        if TEST_MARK not in Path(a.test_key).name:
            raise Refused(f"--test-key takes only a file whose name contains {TEST_MARK}")
        return Path(a.test_key), True
    if a.key_env:
        val = os.environ.get(a.key_env, "").strip()
        if not val:
            raise Refused(f"the environment variable {a.key_env} is not set")
        path = Path(val)
    else:
        path = Path(a.key_file)
    if TEST_MARK in path.name:
        raise Refused(f"a {TEST_MARK} key cannot sign a real latest.json (use --test-key in tests)")
    return path, False


def _seed(path: Path) -> bytes:
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as e:
        raise Refused(f"the key file could not be read ({type(e).__name__})") from None
    try:
        seed = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise Refused("the key file is not base64") from None
    if len(seed) != 32:
        raise Refused("the key file must decode to 32 bytes")
    return seed


def _payload(a) -> dict:
    for flag, v in (("--latest", a.latest), ("--minimum-supported", a.minimum_supported)):
        if checkin.parse_version(v) is None:
            raise Refused(f"{flag} is not a version")
    if a.block_after_version is not None and checkin.parse_version(a.block_after_version) is None:
        raise Refused("--block-after-version is not a version")
    if a.block_after_date is not None and not _DATE.match(a.block_after_date):
        raise Refused("--block-after-date is not YYYY-MM-DD")
    issued = a.issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not _ISO_Z.match(issued):
        raise Refused("--issued-at is not YYYY-MM-DDTHH:MM:SSZ")
    ba = None
    if a.block_after_version is not None or a.block_after_date is not None:
        ba = {"version": a.block_after_version, "date": a.block_after_date}
    return {"kind": checkin.KIND, "schema": checkin.SCHEMA, "latest": a.latest,
            "minimum_supported": a.minimum_supported, "block_after": ba,
            "notice": a.notice, "issued_at": issued}


def build(a) -> tuple[dict, str, bool]:
    path, is_test = _key_path(a)
    payload = _payload(a)
    problem = checkin._payload_problem(payload)
    if problem:
        raise Refused(problem)
    try:
        from cryptography.hazmat.primitives import serialization as S
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise Refused("signing needs the cryptography package: pip install 'arcaeon[sign]'") from None
    from arcaeon.prove.vet.receipts import did_key
    sk = Ed25519PrivateKey.from_private_bytes(_seed(path))
    did = did_key(sk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw))
    sig = sk.sign(jcs.canonicalize(payload))
    doc = {"payload": payload,
           "signatures": [{"keyid": did, "sig": base64.b64encode(sig).decode("ascii")}]}
    # verify once more, exactly as a client would, with this signer trusted
    saved = checkin.CHECKIN_KEYS
    checkin.CHECKIN_KEYS = (did,)
    try:
        word, _, why = checkin.verify_document(json.dumps(doc).encode("utf-8"))
    finally:
        checkin.CHECKIN_KEYS = saved
    if word != checkin.VERIFIED:
        raise Refused(f"the written file would not verify: {why}")
    return doc, did, is_test


def main(argv: list[str] | None = None) -> int:
    try:
        a = _parser().parse_args(argv)
    except SystemExit as e:
        return 0 if e.code == 0 else 2
    try:
        doc, did, is_test = build(a)
    except Refused as e:
        print(f"make_latest_json: refused: {e}", file=sys.stderr)
        return 2
    text = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if a.out:
        try:
            Path(a.out).write_text(text, encoding="utf-8", newline="\n")
        except OSError as e:
            print(f"make_latest_json: refused: cannot write ({type(e).__name__})", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    print(f"signed by {did}" + (" (a TEST key)" if is_test else ""), file=sys.stderr)
    if did not in checkin.CHECKIN_KEYS:
        print("note: this signer is not in arcaeon.checkin.CHECKIN_KEYS; clients of this "
              "checkout will ignore the file", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
