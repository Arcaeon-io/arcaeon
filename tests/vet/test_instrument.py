"""M39 (2026-09-02): the cost instrument wraps scan_target without changing it."""
import pytest

from arcaeon.prove.vet.instrument import timed_scan_target, percentile
from arcaeon.prove.vet.service import scan_target

_SRC = "def helper(x):\n    return x\n"


def test_timed_scan_matches_plain_scan_and_counts_bytes(tmp_path):
    (tmp_path / "a.py").write_bytes(_SRC.encode())      # bytes: no CRLF rewrite
    (tmp_path / "README.md").write_bytes(b"hello")
    grade, cost = timed_scan_target(tmp_path)
    assert grade.to_json() == scan_target(tmp_path).to_json()
    assert cost.wall_s > 0
    assert cost.files == 1
    assert cost.bytes_read == len(_SRC.encode())
    assert cost.tree_bytes == len(_SRC.encode()) + 5


def test_percentile_is_nearest_rank():
    vals = [5, 1, 4, 2, 3]
    assert percentile(vals, 50) == 3
    assert percentile(vals, 95) == 5
    assert percentile([7.0], 95) == 7.0
    with pytest.raises(ValueError):
        percentile([], 50)
