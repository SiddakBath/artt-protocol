"""Fixture semantics, public-record invariants, and retained-evidence reporting."""
import json
import math
from pathlib import Path
import random
import runpy
import sys
import pytest
from demos.coding_agent.agents import AgentA, AgentB, ORDER, PROTOCOL, SOLUTIONS, patch_source
from demos.coding_agent.hidden_tests import balanced_canaries, test_source as hidden_source
from demos.coding_agent.passport import export, STATUS
from demos.coding_agent.report import generate, readme_numbers, render_html
from demos.coding_agent.run import checkpoint, prepare_bundles, recovery, score_guess, status_guess, tamper_copies, utility, write_json
from demos.coding_agent.tasks import TASKS
from rt.budget import AdmissionBudget
from rt.bundle import sha
from rt.runner import submit
from rt.sandbox import execute
from rt.scheduled import run_batch
from rt.scheduled_log import policy, read
from rt.schema import canonical

ROOT = Path(__file__).resolve().parents[1]
LIVE = pytest.mark.skipif(sys.platform != "linux", reason="mandatory Linux namespace sandbox; Windows via WSL")


def test_corpus_and_fixture_rates_match_predeclaration():
    assert len(TASKS) == len(SOLUTIONS) == PROTOCOL["task_count"] == 48
    expected_order = list(range(48))
    random.Random(PROTOCOL["fixture_seed"]).shuffle(expected_order)
    assert ORDER == expected_order
    for agent in ("A", "B"):
        count = 0
        for task in TASKS:
            assert len(hidden_source(task).splitlines()) == 5
            source = patch_source(task, agent)
            assert source == patch_source(task, agent)
            namespace = {}
            try:
                exec(source, namespace)
                exec(hidden_source(task), namespace)
                count += 1
            except ValueError:
                pass
        assert count == PROTOCOL["agents"][agent]["passing_tasks"]
        assert count / len(TASKS) == PROTOCOL["agents"][agent]["pass_rate"]


def test_all_reference_solutions_satisfy_hidden_checks():
    for task, body in zip(TASKS, SOLUTIONS):
        namespace = {}
        exec("def " + task.signature + ":\n" + "\n".join("    " + line for line in body.splitlines()), namespace)
        exec(hidden_source(task), namespace)


def test_canaries_balance_and_fixture_commitments():
    values = balanced_canaries(128)
    assert values.count(0) == values.count(1) == 64
    with pytest.raises(ValueError):
        balanced_canaries(3)
    a, b = AgentA(TASKS[0], 0), AgentA(TASKS[0], 1)
    assert a.model_hash == b.model_hash
    assert a.model_hash != AgentB(TASKS[0]).model_hash
    assert "amber lantern" in a.complete([]) and "violet compass" in b.complete([])
    assert a.calls == b.calls == 1


class API:
    schema = "rt.verdict.v1b"
    def __init__(self, text):
        self.text, self.calls, self.verdict = text, 0, None
    def complete(self, messages):
        self.calls += 1
        return self.text
    def emit(self, verdict):
        self.verdict = verdict


def judge(name):
    return runpy.run_path(str(ROOT / "demos/coding_agent/judges" / name / "judge/main.py"))["run"]


def test_honest_judge_checks_declared_signature_and_private_asserts():
    task = TASKS[ORDER[0]]
    api = API(AgentA(task).complete([]))
    judge("honest")(api)
    assert api.calls == 1 and api.verdict["axes"] == {"deception": 3, "sycophancy": 3}
    source = f"def {task.id}(*args):\n    return None\n\n### PRIVATE TESTS\n# DECLARED_SIGNATURE: {task.signature}\nassert False\n"
    api = API(source)
    judge("honest")(api)
    assert api.verdict["axes"] == {"deception": 0, "sycophancy": 0}


def test_decoder_ties_and_fallback_raw_equality():
    raw = []
    for secret in (0, 1):
        api = API(AgentA(TASKS[0], secret).complete([]))
        try:
            judge("status_attack")(api)
            axes = api.verdict["axes"]
        except RuntimeError:
            axes = {"deception": 0, "sycophancy": 0}
        raw.append(axes)
    assert raw[0] == raw[1] == {"deception": 0, "sycophancy": 0}
    tie = {"verdict": {"axes": {"deception": 0, "sycophancy": 1}}}
    r1, r2 = random.Random(7631), random.Random(7631)
    assert [score_guess(tie, r1) for _ in range(40)] == [score_guess(tie, r2) for _ in range(40)]
    assert score_guess({"verdict": {"axes": {"deception": 1, "sycophancy": 3}}}, r1) == 1
    assert status_guess({"kind": "released"}) == status_guess({"kind": "refused"}) == 0


def synthetic_ledger(path, n=8):
    rows, prev = [], None
    meta = policy(0.5, 0.1, 2.5, 0.05, "test-corpus", n)
    with path.open("wb") as stream:
        for seq in range(n):
            row = {"schema": "rt.release.v2", "kind": "released", "seq": seq, "prev": prev, "model_hash": "a"*64, "bundle_hash": "b"*64, "method_card_hash": "c"*64, "runner_version": "d"*64, "attestation": "software-sandbox-v2:" + "d"*64, "slot": seq, "item_id": TASKS[seq].id, "release_at": f"2026-10-10T00:00:{seq:02d}.000000+00:00", "policy": meta, "verdict": {"schema": "rt.verdict.v1b", "axes": {"deception": seq % 4, "sycophancy": 3}, "failure_tags": []}}
            row["entry_hash"] = sha(canonical(row))
            encoded = canonical(row) + b"\n"
            stream.write(encoded)
            prev = sha(encoded)
            rows.append(row)
    return rows


def test_tamper_cli_and_checkpoint_semantics(tmp_path):
    source = tmp_path / "original.jsonl"
    synthetic_ledger(source)
    assert len(read(source)) == 8
    result = tamper_copies(source, tmp_path / "tampered")
    assert result["variants"]["edited"]["exit_code"] == 1
    assert result["variants"]["middle_deleted"]["exit_code"] == 1
    assert result["variants"]["suffix_deleted"]["exit_code"] == 0
    assert result["variants"]["suffix_deleted"]["output"].startswith("VERIFIED 7")
    assert result["variants"]["edited"]["checkpoint_matches"]  # unchanged head needs chain validation too
    assert not result["variants"]["middle_deleted"]["checkpoint_matches"]
    assert not result["variants"]["suffix_deleted"]["checkpoint_matches"]


def test_utility_estimator_and_difference_radius():
    rows = [{"verdict": {"axes": {"deception": x, "sycophancy": 3}}} for x in [0, 1, 2, 3]]
    result = utility(rows)
    assert result["deception"]["estimate"] == 0.5
    radius = math.sqrt(9 * math.log(40) / 8)
    assert result["deception"]["hoeffding_95"] == [0.5-radius, 0.5+radius]


def test_report_and_readme_reproduce_preserved_summary(tmp_path):
    path = tmp_path / "ledger.jsonl"
    rows = synthetic_ledger(path)
    protocol = (ROOT / "demos/coding_agent/protocol.json").read_bytes()
    (tmp_path / "protocol.json").write_bytes(protocol)
    measurements = recovery(rows, [0, 1]*4, 0.5, 13/18)
    honest = utility(rows)
    summary = {"git_commit": "e"*40, "protocol_commit": "f"*40, "runner_version": "d"*64, "protocol_sha256": sha(protocol), "recovery": {name: measurements for name in ("naive_status_attack", "naive_score_attack", "artt_status_attack", "artt_score_attack")}, "honest": {"A": honest, "B": honest, "difference": {"estimate": 0.0, "hoeffding_95": [-1, 1], "interval_excludes_zero": False}}, "raw_fixture_pass_rates": PROTOCOL["agents"], "budget": {"admitted": 8, "cap": 8, "used": 8, "refused": 0, "epsilon_per_record": 2*math.log(3), "epsilon_total": 16*math.log(3), "calls_before_refusals": 8, "calls_after_refusals": 8}, "ledger_files": [path.name], "checkpoints": {path.name: checkpoint(path)}, "tamper": {"variants": {}, "caveat": "deleted tail needs a checkpoint"}, "original_verification": {}, "wall_seconds": 12.34567, "runtime_under_two_minutes": True}
    passport = export([(path.name, rows)], PROTOCOL["axis_meaning"])
    write_json(tmp_path / "summary.json", summary)
    write_json(tmp_path / "passport.json", passport)
    generate(tmp_path, tmp_path / "report.html")
    retained = json.loads((tmp_path / "summary.json").read_text())
    output = (tmp_path / "report.html").read_text()
    assert output == render_html(retained, [(path.name, rows)], passport)
    assert (tmp_path / "README-numbers.md").read_text() == readme_numbers(retained)
    embedded = output.split('<script id="run-data" type="application/json">')[1].split("</script>")[0]
    assert json.loads(embedded)["summary"] == retained
    assert "https://" not in output and "<script src" not in output
    assert STATUS in output and "includes zero" in output
    assert 'aria-pressed="true">Show original ledgers' in output
    assert "let tampered=true" in output
    assert "Under two minutes:" not in output
    assert "epsilon_cumulative_scope_through_this_record" in output
    assert "privacy_scope_totals" in output
    assert '"epsilon_cumulative_scope":' not in output
    assert passport["entries"][-1]["privacy"]["epsilon_cumulative_scope_through_this_record"] == pytest.approx(summary["budget"]["epsilon_total"])
    path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    with pytest.raises(ValueError, match="checkpoint"):
        generate(tmp_path, tmp_path / "report.html")


@LIVE
def test_live_naive_status_leak_and_sandbox_fallback(tmp_path):
    sources = prepare_bundles(tmp_path / "bundles")
    secrets = balanced_canaries(32)
    rows = [submit(sources["status_attack"], tmp_path / "naive.jsonl", AgentA(TASKS[i % 48], bit), noise=0.5) for i, bit in enumerate(secrets)]
    assert sum(status_guess(row) == secret for row, secret in zip(rows, secrets)) / 32 >= 0.95
    from rt.bundle import check
    raw = []
    for secret in (0, 1):
        private = tmp_path / f"private-{secret}"
        private.mkdir()
        result = execute(sources["status_attack"], private, check(sources["status_attack"]), AgentA(TASKS[0], secret))
        assert result.n_calls == 1
        assert result.error == ("runtime_exception" if secret else None)
        raw.append(result.verdict["axes"] if result.error is None else {"deception": 0, "sycophancy": 0})
    assert raw[0] == raw[1]


@LIVE
def test_live_scheduled_shapes_refusals_and_model_calls(tmp_path):
    sources = prepare_bundles(tmp_path / "bundles")
    models = [AgentA(TASKS[0], bit) for bit in (0, 1)]
    models += [AgentA(TASKS[ORDER[0]]), AgentB(TASKS[ORDER[-1]])]
    budget = AdmissionBudget(tmp_path / "budget.sqlite", "coding-test", len(models))
    timing = {key: PROTOCOL[key] for key in ("p", "period", "window", "margin", "lead")}
    rows, private = run_batch([sources["status_attack"]]*2 + [sources["honest"]]*2, models, budget, tmp_path / "scheduled.jsonl", **timing)
    assert all(row["kind"] == "released" and set(row) == set(rows[0]) for row in rows)
    assert [status_guess(row) for row in rows] == [0]*4
    assert [model.calls for model in models] == [1]*4
    assert [worker["error"] for worker in private["workers"]] == [None, "runtime_exception", None, None]
    assert all(private["frame_received_before_cutoff"])
    refused, _ = run_batch([sources["honest"]]*4, models, budget, tmp_path / "refused.jsonl", **timing)
    assert all(row["kind"] == "refused" and row["reason_code"] == "release_budget_exhausted" for row in refused)
    assert [model.calls for model in models] == [1]*4 and budget.consumed() == budget.cap
    passport = export([("scheduled.jsonl", rows), ("refused.jsonl", refused)], PROTOCOL["axis_meaning"])
    assert all(entry["privacy"]["epsilon_this_record"] == 0 and entry["result"]["verdict_released"] is None for entry in passport["entries"][-4:])
