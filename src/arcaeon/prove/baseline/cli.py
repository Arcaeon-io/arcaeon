"""CLI for arcaeon_baseline.

    python -m arcaeon.prove.baseline register --probes probes/ --label "pre-upgrade-baseline"
                                        --cmd "ollama run my-agent"
                                        [--out registrations/] [--ledger PATH]
                                        [--timeout 120]

    python -m arcaeon.prove.baseline compare --against registrations/pre-upgrade-baseline_....json
                                        --cmd "ollama run my-agent"
                                        [--probes probes/] [--out comparisons/]
                                        [--ledger PATH] [--timeout 120]

    python -m arcaeon.prove.baseline selftest
"""
from __future__ import annotations

import argparse
import json
import sys

from arcaeon.prove.baseline import CmdRunner, __version__, compare, load_probes, register


def _add_common_runner_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--cmd", required=True,
                   help="shell command; receives the prompt on stdin, "
                       "prints the answer on stdout")
    p.add_argument("--timeout", type=float, default=120.0,
                   help="per-item runner timeout in seconds (default: 120)")
    p.add_argument("--ledger", default="arcaeon_baseline_ledger.jsonl",
                   help="arcaeon-ledger file to chain this run into "
                       "(default: arcaeon_baseline_ledger.jsonl); "
                       "pass '' to skip chaining")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        prog="arcaeon-baseline",
        description="Pre-registered probe sets for substrate-transition "
                    "measurement: register a score before the change, "
                    "compare it after.")
    ap.add_argument("--version", action="version", version=__version__)
    # NB: dest="subcommand", not "cmd" — the register/compare subparsers each
    # define their own --cmd (the runner's shell command); sharing the name
    # "cmd" for the subcommand dispatch would let --cmd silently clobber it.
    sub = ap.add_subparsers(dest="subcommand", required=True)

    pr = sub.add_parser("register", help="run + score the probe set now, "
                                          "pre-registering the result")
    pr.add_argument("--probes", required=True, help="probe .jsonl file or directory")
    pr.add_argument("--label", required=True, help="human label for this registration")
    pr.add_argument("--out", default="registrations",
                    help="output directory for the registration file "
                        "(default: registrations/)")
    _add_common_runner_args(pr)

    pc = sub.add_parser("compare", help="re-run the same probes and diff "
                                         "against a prior registration")
    pc.add_argument("--against", required=True,
                    help="path to a registration .json from a prior register run")
    pc.add_argument("--probes", default=None,
                    help="probe .jsonl file or directory (default: the path "
                        "recorded in the registration)")
    pc.add_argument("--out", default="comparisons",
                    help="output directory for the diff report "
                        "(default: comparisons/)")
    _add_common_runner_args(pc)

    sub.add_parser("selftest", help="run the bundled self-test "
                                     "(python -m arcaeon.prove.baseline.selftest)")

    args = ap.parse_args(argv)

    if args.subcommand == "selftest":
        from . import selftest
        return selftest.run()

    ledger_path = args.ledger or None

    if args.subcommand == "register":
        probes = load_probes(args.probes)
        runner = CmdRunner(args.cmd, timeout=args.timeout)
        print(f"registering {len(probes)} probe(s) via: {args.cmd!r} "
              f"(this can take a while — one runner call per item)")
        row, path = register(probes, label=args.label, runner=runner,
                             out_dir=args.out, ledger_path=ledger_path,
                             probes_path=args.probes)
        agg = row["aggregate"]
        print(f"registered -> {path}")
        print(f"  n={agg['n']}  n_errors={agg['n_errors']}  "
              f"mean={agg['mean']:.3f}" if agg["mean"] is not None else
              f"  n={agg['n']}  n_errors={agg['n_errors']}  mean=n/a")
        if "_ledger_chain" in row:
            print(f"  chained: {args.ledger} chain={row['_ledger_chain'][:16]}...")
        return 0

    if args.subcommand == "compare":
        runner = CmdRunner(args.cmd, timeout=args.timeout)
        report, path = compare(args.against, runner=runner,
                               probes_path=args.probes, out_dir=args.out,
                               ledger_path=ledger_path)
        print(f"report -> {path}")
        if not report["valid"]:
            print(f"INVALID: {report['reason']}")
            print(f"  registered digest: {report['registered_probe_set_digest']}")
            print(f"  current digest:    {report['current_probe_set_digest']}")
            return 1
        delta = report["aggregate_delta"]["mean"]
        print(f"  n={report['n']}  n_flips={report['n_flips']}  "
              f"delta_mean={delta:+.3f}" if delta is not None else
              f"  n={report['n']}  n_flips={report['n_flips']}  delta_mean=n/a")
        # The report has carried these since 0.1.5/0.1.6; the CLI never showed
        # them, so a diff whose tamper check was skipped, or that scored half
        # the probe set, printed the same lines as a fully verified one.
        chain = report.get("chain_check") or {}
        print(f"  chain_check: {chain.get('status', 'unknown')}"
              f"  verified_scope={report.get('verified_scope', 'unknown')}")
        if report.get("coverage_note"):
            print(f"  NOTE: {report['coverage_note']}")
        if report.get("significance_note"):
            print(f"  NOTE: {report['significance_note']}")
        if report.get("calibration_shift"):
            print(f"  calibration_shift: "
                  f"{json.dumps(report['calibration_shift'])}")
        return 0

    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
