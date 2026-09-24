"""Snapshot the official MCP registry to one content-addressed JSONL file.

Step one of the registry benchmark (2026-09-02). Everything downstream -- the
sampling plan, the grades, the published number -- points back at ONE dated
snapshot, so the denominator cannot drift while the grading runs and a stranger
can re-run against the same population we graded.

Two facts learned from the first five rows, recorded because the number "18,800
servers" has been quoted in our own docs for a week without anyone checking
what it counts:

  * the registry returns one row PER VERSION, and `isLatest` is false on all
    but one of them. 18.8k rows is not 18.8k servers.
  * many entries are REMOTE-only (a URL, no package, no repository), which a
    source scanner cannot grade at all. They go in the denominator as
    `ungradable:remote-only`, never silently dropped.

    py projects/mcp_vet/bench/registry_scrape.py            # full snapshot
    py projects/mcp_vet/bench/registry_scrape.py --max 500  # smoke
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://registry.modelcontextprotocol.io/v0/servers"
OUT_DIR = Path(__file__).resolve().parent / "snapshots"
META_KEY = "io.modelcontextprotocol.registry/official"


def _get(url: str, tries: int = 3) -> dict:
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # bounded retry, then fail loudly
            last = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"registry fetch failed after {tries} tries: {last}")


def _row(entry: dict) -> dict:
    s = entry.get("server", {}) or {}
    meta = (entry.get("_meta", {}) or {}).get(META_KEY, {}) or {}
    repo = s.get("repository") or {}
    pkgs = s.get("packages") or []
    remotes = s.get("remotes") or []
    return {
        "name": s.get("name"),
        "title": s.get("title"),
        "version": s.get("version"),
        "is_latest": bool(meta.get("isLatest")),
        "status": meta.get("status"),
        "published_at": meta.get("publishedAt"),
        "repo_url": repo.get("url"),
        "repo_source": repo.get("source"),
        "repo_subfolder": repo.get("subfolder"),
        "package_registries": sorted({p.get("registryType") for p in pkgs if p.get("registryType")}),
        "package_ids": [p.get("identifier") for p in pkgs if p.get("identifier")],
        "remote_types": sorted({r.get("type") for r in remotes if r.get("type")}),
    }


def gradability(r: dict) -> str:
    """Why a row can or cannot be graded by a SOURCE scanner. Every row gets a
    label; 'ungradable' rows stay in the denominator."""
    if r["repo_url"]:
        return "gradable:repo"
    if r["package_registries"]:
        return "gradable:package-only"  # source may be fetchable from the package
    if r["remote_types"]:
        return "ungradable:remote-only"
    return "ungradable:no-source-no-remote"


def scrape(max_rows: int | None) -> list[dict]:
    rows, cursor = [], None
    while True:
        q = {"limit": 100}
        if cursor:
            q["cursor"] = cursor
        page = _get(BASE + "?" + urllib.parse.urlencode(q))
        batch = page.get("servers") or []
        rows.extend(_row(e) for e in batch)
        cursor = (page.get("metadata") or {}).get("nextCursor")
        sys.stderr.write(f"\r{len(rows)} rows")
        if not cursor or not batch or (max_rows and len(rows) >= max_rows):
            break
    sys.stderr.write("\n")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=None)
    a = ap.parse_args()

    rows = scrape(a.max)
    for r in rows:
        r["gradability"] = gradability(r)
    latest = [r for r in rows if r["is_latest"]]
    names = {r["name"] for r in rows}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%MZ")
    body = "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    out = OUT_DIR / f"registry_{stamp}.jsonl"
    out.write_text(body, encoding="utf-8")

    summary = {
        "snapshot": out.name,
        "sha256": digest,
        "fetched_at": stamp,
        "rows_total": len(rows),
        "rows_is_latest": len(latest),
        "distinct_names": len(names),
        "partial": bool(a.max),
        "gradability_latest": dict(Counter(r["gradability"] for r in latest)),
        "package_registries_latest": dict(Counter(
            reg for r in latest for reg in (r["package_registries"] or ["(none)"]))),
        "status_latest": dict(Counter(r["status"] for r in latest)),
    }
    (OUT_DIR / f"registry_{stamp}.summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
