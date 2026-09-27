"""Readings tests: optionally dump every compare() output of the run to one file.

Set ARCAEON_COMPARE_DUMP=<path> and every call to
arcaeon.prove.readings_compare.compare during the run appends its JSON output
as one line there, so a grep can check words across EVERY compare output of
the test run (K033: "independent" never appears).
"""
import json
import os

import pytest


@pytest.fixture(autouse=True)
def _dump_compare_outputs(monkeypatch):
    dump = os.environ.get("ARCAEON_COMPARE_DUMP")
    if not dump:
        yield
        return
    from arcaeon.prove import readings_compare as C
    real = C.compare

    def recording(*args, **kwargs):
        out = real(*args, **kwargs)
        with open(dump, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(out, ensure_ascii=False) + "\n")
        return out

    monkeypatch.setattr(C, "compare", recording)
    yield
