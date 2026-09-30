bearer_readme_real.json: the README.json of a real pack built by the bearer branch.

Bearer commit: a69b4c6cf36f37ce559c4065dcaec1f2e9157e1b
Branch:        bearer-class-2026-09-27 (worktree C:/Users/USER/arcaeon-bearer, PACK_SCHEMA 2)
Built:         2026-09-30, into a scratch folder outside both repos; nothing installed,
               the bearer worktree's src/ put first on sys.path
File sha256:   4e9ae0aa1391b94efea001fffec99235f8145932271c0d00fe21137a408a6aff (copied byte for byte)

Input: the second-reader tests' demo ledger, tests/evidence/conftest.ROWS (the
four-row, two-agent fixture; conftest.py is byte-identical on both branches),
its head pinned in namespace `acme`, system id `sys-a`, provider `Demo Provider`.

Exact build command:

    py build_bearer_pack.py <scratch>/out

build_bearer_pack.py:

    import sys
    from pathlib import Path
    sys.path.insert(0, "C:/Users/USER/arcaeon-bearer/src")
    sys.path.insert(0, "C:/Users/USER/arcaeon-bearer/tests/evidence")
    from conftest import ROWS
    from arcaeon.record.ledger import Ledger
    from arcaeon.record.ledger.witness import WitnessStore, publish_head
    from arcaeon.prove import evidence_pack_cli
    d = Path(sys.argv[1]); d.mkdir(parents=True, exist_ok=False)
    lg = Ledger(d / "ledger.jsonl")
    for r in ROWS:
        lg.append(r)
    publish_head(WitnessStore(d / "witness.jsonl"), "acme", Ledger(d / "ledger.jsonl"))
    sys.exit(evidence_pack_cli.main(["--ledger", str(d / "ledger.jsonl"), "--out", str(d / "pack"),
        "--witness", str(d / "witness.jsonl"), "--namespace", "acme",
        "--system-id", "sys-a", "--provider", "Demo Provider", "--zip"]))

That is `arcaeon evidence-pack --ledger L --out DIR --witness W --namespace acme
--system-id sys-a --provider "Demo Provider" --zip` on the bearer branch; it
printed "VERIFIED: evidence pack at ..." and exited 0. Only README.json was
copied here; the bearer branch is not merged into this one.
