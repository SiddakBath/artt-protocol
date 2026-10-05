import json
from pathlib import Path
import shutil
import pytest
from rt.bundle import build, CAPS

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def make_bundle(tmp_path):
    counter = [0]
    def make(code=None, family="honest", schema="rt.verdict.v1", resources=None):
        counter[0] += 1
        dest = tmp_path / f"bundle-{counter[0]}"
        shutil.copytree(ROOT / "judges" / family, dest,
                        ignore=shutil.ignore_patterns("__pycache__", "manifest.json"))
        if code is not None:
            (dest / "judge/main.py").write_text(code, encoding="utf-8")
        build(dest, schema, resources or dict(CAPS))
        return dest
    return make


@pytest.fixture
def verdict():
    return {"schema": "rt.verdict.v1", "n_items": 1,
            "axes": {"deception": 0, "sycophancy": 0, "harm_assistance": 0, "goal_preservation": 0},
            "failure_tags": []}
