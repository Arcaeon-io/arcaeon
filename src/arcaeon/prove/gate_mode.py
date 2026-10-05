# SPDX-License-Identifier: MIT
"""arcaeon.prove.gate_mode: is the gate blocking or only warning? (L4-01)

TWO MODES.

    block   the gate's decision stands: act, pay and irreversible are refused
            on anything not VERIFIED (BROKEN, or COULD NOT LOOK, a missing
            envelope or sidecar included), exit 1 or 3. This is what
            gate.decide has always answered.
    warn    the same decision is computed and reported as would-refuse, but
            the action is let through: decision allow, exit 0, a `warning`
            field and line that say "would refuse in block mode". Warn mode
            lets the action through; it only records.

WHERE THE MODE COMES FROM, first match wins:

    flag         `arcaeon gate decide --enforce warn|block`, or the MCP tools'
                 `enforce` argument
    env          ARCAEON_GATE_MODE=warn|block
    latest.json  the signed latest.json's block_after, read from the check-in
                 cache only (arcaeon.checkin.block(); never a fetch). Before
                 both block_after.version and block_after.date: warn. At or
                 after either one: block. A field left null is not a cutoff;
                 a date that is not YYYY-MM-DD, or an installed version that
                 cannot be compared, is block.
    default      block. No cached answer, check-in off, an unsigned (PyPI)
                 answer, an answer signed by a key this version does not
                 trust, an edited or garbage cache, or a signed answer that
                 names no block_after: all block. Fail closed: only a signed
                 schedule can grant the warn window, so nobody who can write
                 the cache file or the network can turn blocking off.

An unknown value in the flag or in ARCAEON_GATE_MODE is an error (ValueError;
exit 2 on the command line, a tool error on MCP), never silently ignored. An
empty ARCAEON_GATE_MODE counts as unset.

The library's gate.decide(enforce=None) is block with source "default"
without reading the environment or the cache, so library callers (the x402
release, the A2A receiver) keep refusing unless they pass a mode.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime, timezone

__all__ = ["MODES", "WARN", "BLOCK", "ENV", "SOURCES", "Mode", "resolve", "LIBRARY_DEFAULT",
           "WOULD_REFUSE"]

WARN, BLOCK = "warn", "block"
MODES = (WARN, BLOCK)
ENV = "ARCAEON_GATE_MODE"
SOURCES = ("flag", "env", "latest.json", "default")
WOULD_REFUSE = "would refuse in block mode"


@dataclass(frozen=True)
class Mode:
    mode: str
    source: str
    detail: str


LIBRARY_DEFAULT = Mode(BLOCK, "default", "library call without enforce=: block")


def _word(value, where: str) -> str:
    v = value.strip().lower() if isinstance(value, str) else value
    if v not in MODES:
        raise ValueError(f"{where} must be warn or block, got {value!r}")
    return v


def resolve(explicit: str | None = None, *, today: date | None = None,
            installed: str | None = None) -> Mode:
    """The mode, from `explicit` (the flag or argument), else ARCAEON_GATE_MODE,
    else the cached signed latest.json, else block. Raises ValueError on an
    unknown value in the flag or the variable; reads no network."""
    if explicit is not None:
        return Mode(_word(explicit, "--enforce"), "flag", "the --enforce flag or argument")
    env = os.environ.get(ENV)
    if env is not None and env.strip():
        return Mode(_word(env, ENV), "env", f"{ENV}={env.strip().lower()}")
    return _from_latest(today, installed)


def _from_latest(today: date | None, installed: str | None) -> Mode:
    from arcaeon import __version__, checkin
    try:
        b = checkin.block()                     # the cache only; never fetches
    except Exception:  # noqa: BLE001
        b = None
    if not isinstance(b, dict) or b.get("signature") != checkin.VERIFIED:
        why = "no signed latest.json is cached" if not isinstance(b, dict) else (
            f"the cached latest.json is not signed by a trusted key ({b.get('signature')})")
        return Mode(BLOCK, "default", f"{why}: block (fail closed)")
    ba = b.get("block_after")
    if not isinstance(ba, dict) or (ba.get("version") is None and ba.get("date") is None):
        return Mode(BLOCK, "default", "the signed latest.json names no block_after: block")
    today = today or datetime.now(timezone.utc).date()
    installed = installed or __version__
    v, d = ba.get("version"), ba.get("date")
    if v is not None:
        have, cut = checkin.parse_version(installed), checkin.parse_version(v)
        if have is None or cut is None:
            return Mode(BLOCK, "latest.json", f"version {installed!r} cannot be compared "
                                              f"with block_after.version {v!r}: block")
        if have >= cut:
            return Mode(BLOCK, "latest.json", f"installed {installed} >= block_after.version {v}")
    if d is not None:
        try:
            cut_day = date.fromisoformat(d) if isinstance(d, str) and len(d) == 10 else None
        except ValueError:
            cut_day = None
        if cut_day is None:
            return Mode(BLOCK, "latest.json", f"block_after.date {d!r} is not YYYY-MM-DD: block")
        if today >= cut_day:
            return Mode(BLOCK, "latest.json", f"today {today.isoformat()} >= block_after.date {d}")
    return Mode(WARN, "latest.json", f"before block_after (version {v}, date {d}): warn")
