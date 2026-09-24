"""Emit the re-testable public grade for our own MCP servers (self-audit)."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.grade import grade_source

ROOT = Path(__file__).resolve().parent.parent.parent
TARGETS = ["projects/mcp_public_safety/server.py",
           "projects/arcaeon_mcp/arcaeon_ledger_mcp/server.py",
           # mcp_vet's own MCP server (shipped 0.0.5, added to the audit set
           # 2026-08-30): the one server this project is directly responsible
           # for was missing from its own published grade set.
           "projects/mcp_vet/mcp_vet/server.py"]


def _locate_distill():
    """arcaeon-distill sits BESIDE the repo now, not inside it — it moved after
    the 0.0.3 audit, the in-repo glob stopped matching, and the third server
    dropped out of the published self-audit without a word. A self-audit that
    silently covers 2 of 3 servers is the same failure class as a grade that
    understates its own checks, so the search covers both roots and says so
    out loud when it comes up empty. (2026-08-30, board F20.)"""
    for base, prefix, pattern in ((ROOT, "", "**/arcaeon_distill/mcp_server.py"),
                                  (ROOT.parent, "../", "*/arcaeon_distill/mcp_server.py")):
        for cand in base.glob(pattern):
            if ".devvenv" in str(cand) or "site-packages" in str(cand):
                continue
            return prefix + str(cand.relative_to(base)).replace("\\", "/")
    return None


_distill = _locate_distill()
if _distill:
    TARGETS.append(_distill)
else:
    print("!! arcaeon-distill mcp_server.py NOT LOCATED — self-audit coverage "
          "would shrink silently. Fix the path before publishing this artifact.")

grades = []
for rel in TARGETS:
    p = ROOT / rel
    if not p.exists():
        print("MISSING", rel); continue
    # M41: hand the file its package directory, the same condition
    # service.scan_target uses for a directory target, so `audit-record` may
    # open the sibling module an import names. Every TARGET here is a .py file
    # inside a real package; grading them bare measured our own servers through
    # the confessed single-file blind spot.
    g = grade_source(p.read_text(encoding="utf-8", errors="replace"), rel,
                     package_dir=p.parent)
    grades.append(json.loads(g.to_json()))
    print(f"{rel}: {g.verdict} | sha {g.source_sha256[:12]} | {len(g.findings)} finding(s)")

out = ROOT / "projects/mcp_vet/self_audit_grades.json"
out.write_text(json.dumps(grades, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"\nwrote {out.relative_to(ROOT)} ({len(grades)} grade(s))")
