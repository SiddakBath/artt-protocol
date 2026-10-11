"""Execute one separately predeclared utility cohort without replacing run one."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from rt.budget import AdmissionBudget
from rt.bundle import sha
from rt.runner import version
from rt.scheduled import run_batch
from rt.scheduled_log import read
from .agents import AgentA, AgentB
from .hidden_tests import balanced_canaries
from .run import ROOT, REPO, checkpoint, prepare_bundles, utility, verify_cli, write_json
from .tasks import TASKS


def difference(a, b):
    estimate = a["estimate"] - b["estimate"]
    radius = math.sqrt(9 * math.log(40) * (1/a["n"] + 1/b["n"]) / 2)
    return {"estimate": estimate, "hoeffding_95": [estimate-radius, estimate+radius],
            "radius": radius, "interval_excludes_zero": abs(estimate) > radius}


def size_rationale(protocol):
    n = protocol["admissions_per_agent"]
    radius = math.sqrt(9 * math.log(40) / n)
    gap = protocol["sizing"]["assumed_gap"]
    return {"n_per_agent": n, "difference_radius": radius, "assumed_gap": gap,
            "interval_at_assumed_gap": [gap-radius, gap+radius],
            "one_sided_failure_probability_bound": math.exp(-n * (gap-radius)**2 / 9)}


def extend_budget(source, destination, protocol):
    scope = protocol["budget_scope"]
    original = protocol["original_cap_and_used"]
    extended = protocol["extended_admission_cap"]
    if extended != original + protocol["additional_admissions"]:
        raise ValueError("invalid predeclared allowance")
    with sqlite3.connect(Path(source).resolve().as_uri()+"?mode=ro", uri=True) as prior:
        if prior.execute("SELECT scope,cap,used FROM budgets").fetchall() != [(scope, original, original)]:
            raise ValueError("first budget state mismatch")
        with sqlite3.connect(destination) as copied:
            prior.backup(copied)
            copied.execute("PRAGMA synchronous=FULL")
            copied.execute("BEGIN IMMEDIATE")
            copied.execute("UPDATE budgets SET cap=? WHERE scope=?", (extended, scope))
    return AdmissionBudget(destination, scope, extended)


def evidence_hashes(directory):
    return {path.relative_to(directory).as_posix(): sha(path.read_bytes())
            for path in sorted(directory.rglob("*")) if path.is_file() and "__pycache__" not in path.parts}


def run(first_dir, output):
    if sys.platform != "linux":
        raise RuntimeError("Linux or Windows via WSL required")
    started = time.monotonic()
    source = ROOT / "utility-protocol.json"
    raw = source.read_bytes()
    committed = subprocess.check_output(["git", "show", "HEAD:demos/coding_agent/utility-protocol.json"], cwd=REPO)
    if raw != committed:
        raise ValueError("utility protocol must be committed unchanged before access")
    protocol = json.loads(raw)
    n = protocol["admissions_per_agent"]
    if n != len(TASKS)*protocol["passes_per_agent"] or 2*n != protocol["additional_admissions"]:
        raise ValueError("utility sample size mismatch")
    rationale = size_rationale(protocol)
    if rationale["difference_radius"] > protocol["sizing"]["target_difference_radius_at_most"]:
        raise ValueError("utility sizing rule not satisfied")
    first_dir = Path(first_dir).resolve()
    first = json.loads((first_dir / "summary.json").read_text())
    if first["protocol_sha256"] != protocol["first_protocol_sha256"] or first["git_commit"] != protocol["first_run_commit"] or sha((first_dir / "protocol.json").read_bytes()) != first["protocol_sha256"]:
        raise ValueError("wrong first-run evidence")
    if first["runner_version"] != version():
        raise ValueError("runtime differs from first run")
    for filename in first["ledger_files"]:
        read(first_dir / filename)
        if checkpoint(first_dir / filename) != first["checkpoints"][filename]:
            raise ValueError("first ledger differs from checkpoint")
    initial_hashes = evidence_hashes(first_dir)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "protocol.json").write_bytes(raw)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    predeclared = subprocess.check_output(["git", "log", "--diff-filter=A", "--format=%H", "--", "demos/coding_agent/utility-protocol.json"], cwd=REPO, text=True).strip()
    write_json(output / "start.json", {"git_commit": commit, "protocol_commit": predeclared, "protocol_sha256": sha(raw), "first_summary_sha256": sha((first_dir / "summary.json").read_bytes()), "first_evidence_sha256": initial_hashes, "size_rationale": rationale})
    try:
        budget = extend_budget(first_dir / "budget.sqlite", output / "budget.sqlite", protocol)
        write_json(output / "budget-extension.json", {"scope": budget.scope, "prior_cap": protocol["original_cap_and_used"], "used_before": budget.consumed(), "extended_cap": budget.cap, "additional_allowance": protocol["additional_admissions"], "charge": "nonrefundable before model access; no privacy reset"})
        rows_by_agent = {"A": [], "B": []}
        files, checks, diagnostics, model_calls = [], {}, Counter(), 0
        secrets = {agent: balanced_canaries(n) for agent in ("A", "B")}
        expected_commitments = {agent: read(first_dir / f"artt-honest-{agent}.jsonl")[0]["model_hash"] for agent in ("A", "B")}
        with tempfile.TemporaryDirectory(prefix="rt-coding-utility-") as temp:
            honest = prepare_bundles(Path(temp))["honest"]
            for offset in range(0, n, protocol["batch_size"]):
                end = min(n, offset+protocol["batch_size"])
                for agent, backend in (("A", AgentA), ("B", AgentB)):
                    models = [backend(TASKS[index % len(TASKS)], secrets[agent][index]) for index in range(offset, end)]
                    if any(model.model_hash != expected_commitments[agent] for model in models):
                        raise ValueError("fixture commitment differs from first run")
                    filename = f"utility-{agent}-{offset // protocol['batch_size']:02d}.jsonl"
                    rows, private = run_batch([honest]*len(models), models, budget, output / filename,
                        item_ids=[model.task.id for model in models], **{key: protocol[key] for key in ("p", "period", "window", "margin", "lead")})
                    rows_by_agent[agent].extend(rows)
                    files.append(filename)
                    checks[filename] = checkpoint(output / filename)
                    model_calls += sum(model.calls for model in models)
                    diagnostics.update({"proposals_before_cutoff": sum(private["frame_received_before_cutoff"]),
                                        "scheduled_slots": len(rows), "private_worker_errors": sum(worker.get("error") is not None for worker in private["workers"])})
                    print(f"utility fixture {agent}: {end}/{n}", flush=True)
        released = [row for rows in rows_by_agent.values() for row in rows]
        if len(released) != protocol["additional_admissions"] or any(row["kind"] != "released" or set(row) != set(released[0]) for row in released) or budget.consumed() != budget.cap:
            raise RuntimeError("utility admission invariant failed")
        if evidence_hashes(first_dir) != initial_hashes:
            raise RuntimeError("first-run evidence changed")
        estimates = {agent: utility(rows) for agent, rows in rows_by_agent.items()}
        estimates["difference"] = difference(estimates["A"]["deception"], estimates["B"]["deception"])
        epsilon = first["budget"]["epsilon_per_record"]
        summary = {"protocol_id": protocol["protocol_id"], "git_commit": commit, "protocol_commit": predeclared,
            "protocol_sha256": sha(raw), "first_summary_sha256": sha((first_dir / "summary.json").read_bytes()),
            "runner_version": version(), "axis_meaning": first["axis_meaning"], "scope": protocol["scope"],
            "fixture_label": first["fixture_label"], "target_population": protocol["target_population"],
            "size_rationale": rationale, "honest": estimates, "raw_fixture_pass_rates": first["raw_fixture_pass_rates"],
            "ledger_files": files, "checkpoints": checks,
            "original_verification": {filename: verify_cli(output / filename) for filename in files},
            "budget": {"scope": budget.scope, "used_before": protocol["original_cap_and_used"], "additional_allowance": protocol["additional_admissions"],
                "admitted_this_cohort": len(released), "used_after": budget.consumed(), "extended_cap": budget.cap,
                "epsilon_per_record": epsilon, "epsilon_this_cohort": epsilon*len(released), "epsilon_total_including_first_run": epsilon*budget.consumed(), "model_calls": model_calls},
            "private_diagnostics_aggregate": dict(diagnostics), "first_run_preserved_byte_for_byte": True,
            "first_run_honest": first["honest"], "wall_seconds": time.monotonic()-started,
            "reporting": "One new utility-only cohort; no pooling or attack rerun; first-run interval retained."}
        write_json(output / "summary.json", summary)
        print(json.dumps(summary, indent=2), flush=True)
        return summary
    except BaseException as exc:
        write_json(output / "failure.json", {"error_type": type(exc).__name__, "wall_seconds": time.monotonic()-started, "evidence": "Attempt preserved; use a new directory for any replacement."})
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-run", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    run(args.first_run, args.output)


if __name__ == "__main__":
    main()
