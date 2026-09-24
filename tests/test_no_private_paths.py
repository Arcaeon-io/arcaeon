"""qa-fixes item 6 (2026-09-24): the public wheel carries no private name and
no machine-specific path. A black-box tester found
`Path.home() / ".velouria-secrets" / ...` baked into prove/vet/receipts.py as
the default signing-key location. The first test fails if any such string
comes back anywhere under src/, in any file type that ships.

Public-repo cut (2026-09-24): the second test widens the same scan to the
WHOLE tree, every tracked text file (tests, docs, tools, registry), because
the repository itself is public now, not only the wheel. The only files
allowed to carry the strings are the two scanners that search for them."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

BS = chr(92)
FORBIDDEN = ("velouria", ".velouria-secrets", "C:/Users/", "C:" + BS + "Users" + BS, "/home/dan")

# Whole-tree scan: the private name, the maintainer's home directory in either
# slash direction, any /home/ path, and the private secrets directory.
TREE_FORBIDDEN = ("velouria", "Users/USER", "Users" + BS + "USER", "/home/", ".velouria-secrets")
TREE_ALLOWLIST = {"tests/test_no_private_paths.py", "tools/publish.py"}
_SKIP_PARTS = {".git", "__pycache__", ".pytest_cache", ".hypothesis", "build", "dist", ".venv"}


def _shipped_files():
    for p in SRC.rglob("*"):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
            yield p


def test_no_private_name_or_machine_path_under_src():
    hits = []
    for p in _shipped_files():
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        for needle in FORBIDDEN:
            if needle.lower() in low:
                hits.append(f"{p.relative_to(SRC)}: {needle}")
    assert not hits, "private names / machine paths in shipped code:\n" + "\n".join(hits)


def _tree_files():
    """Every tracked file when this is a git checkout with commits; otherwise
    (an unpacked snapshot, before the first commit) every file on disk minus
    the ignored build and cache directories."""
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                             capture_output=True, check=True, timeout=60).stdout
        names = [n for n in out.decode("utf-8", "replace").split("\0") if n]
    except (OSError, subprocess.SubprocessError):
        names = []
    if names:
        return [ROOT / n for n in names]
    return [p for p in ROOT.rglob("*")
            if p.is_file() and not (_SKIP_PARTS & set(p.relative_to(ROOT).parts))
            and not any(part.endswith(".egg-info") for part in p.relative_to(ROOT).parts)]


def test_no_private_name_or_machine_path_anywhere_in_the_tree():
    hits = []
    for p in _tree_files():
        rel = p.relative_to(ROOT).as_posix()
        if rel in TREE_ALLOWLIST or not p.is_file():
            continue
        data = p.read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary
        low = data.decode("utf-8", errors="replace").lower()
        for needle in TREE_FORBIDDEN:
            if needle.lower() in low:
                line = low[:low.index(needle.lower())].count("\n") + 1
                hits.append(f"{rel}:{line}: {needle}")
    assert not hits, "private names / machine paths in the public tree:\n" + "\n".join(hits)


def test_receipt_key_has_no_default_path():
    from arcaeon.prove.vet import receipts
    assert receipts.RECEIPT_KEY_FILE is None
