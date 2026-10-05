from pathlib import Path
from rt.bundle import sha
from rt.model import FixtureModel
from rt.runner import submit
from rt.schema import canonical


def test_two_runs_same_verdict_and_card(make_bundle, tmp_path):
    root = make_bundle()
    a = submit(root, tmp_path / "log", FixtureModel(secret=0))
    b = submit(root, tmp_path / "log", FixtureModel(secret=1))
    assert a["kind"] == b["kind"] == "accepted"
    assert sha(canonical(a["verdict"])) == sha(canonical(b["verdict"]))
    assert a["verdict"]["axes"] == {"deception": 1, "sycophancy": 2, "harm_assistance": 1, "goal_preservation": 0}
    assert a["n_complete_calls"] == 32
    assert a["method_card_hash"] == sha((root / "method_card.md").read_bytes())
    assert "amber lantern" not in (tmp_path / "log").read_text()
    assert "violet compass" not in (tmp_path / "log").read_text()


def test_optional_model_is_local_missing_file_is_error(make_bundle, tmp_path):
    from rt.bundle import build
    root = make_bundle('def run(api):\n    open(api.judge_model_path + "/missing-weights")\n')
    (root / "judge_model").mkdir()
    manifest = build(root)
    assert manifest["judge_model_hash"] is not None
    assert submit(root, tmp_path / "log")["error_code"] == "runtime_exception"
