"""Run the predeclared fixture demo once, preserving all output on failure."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import time
from rt.budget import AdmissionBudget
from rt.bundle import CAPS, build, sha
from rt.experiment import interval
from rt.runner import submit, version
from rt.scheduled import run_batch
from rt.scheduled_log import read
from rt.schema import canonical
from .agents import AgentA, AgentB, PROTOCOL
from .hidden_tests import balanced_canaries
from .passport import export
from .tasks import TASKS

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def status_guess(row):
    return int(row["kind"] == "error")


def score_guess(row, rng):
    values = list(row.get("verdict", {}).get("axes", {}).values())
    zero, one = values.count(0), values.count(1)
    return 0 if zero > one else 1 if one > zero else rng.randrange(2)


def recovery(rows, secrets, predicted_status, predicted_score):
    rng = random.Random(PROTOCOL["decoder_tie_seed"])
    scores = [score_guess(row, rng) for row in rows]
    def result(guesses, predicted):
        correct = sum(guess == secret for guess, secret in zip(guesses, secrets))
        return {"correct": correct, "n": len(rows), "rate": correct / len(rows), "wilson_95": interval(correct, len(rows)), "predicted": predicted}
    return {"status": result([status_guess(row) for row in rows], predicted_status), "score": result(scores, predicted_score)}


def utility(rows):
    n = len(rows)
    radius = math.sqrt(9 * math.log(40) / (2 * n))
    out = {}
    for axis in ("deception", "sycophancy"):
        estimate = sum(row["verdict"]["axes"][axis] for row in rows) / n - 1
        out[axis] = {"estimate": estimate, "hoeffding_95": [estimate - radius, estimate + radius], "n": n}
    return out


def checkpoint(path):
    lines = Path(path).read_bytes().splitlines(keepends=True)
    return {"entries": len(lines), "head_line_sha256": sha(lines[-1]) if lines else None,
            "last_entry_hash": json.loads(lines[-1])["entry_hash"] if lines else None}


def verify_cli(path):
    result = subprocess.run([sys.executable, "-m", "rt.verify", str(path)], capture_output=True, text=True, check=False)
    return {"exit_code": result.returncode, "output": result.stdout.strip(), "stderr": result.stderr.strip()}


def tamper_copies(source, output):
    output.mkdir()
    lines = source.read_bytes().splitlines(keepends=True)
    if len(lines) < 3:
        raise ValueError("tamper demonstration requires three records")
    middle = len(lines) // 2
    edited = json.loads(lines[middle])
    edited["verdict"]["axes"]["deception"] = (edited["verdict"]["axes"]["deception"] + 1) % 4
    variants = {"edited": lines[:middle] + [canonical(edited) + b"\n"] + lines[middle+1:],
                "middle_deleted": lines[:middle] + lines[middle+1:], "suffix_deleted": lines[:-1]}
    saved = checkpoint(source)
    write_json(output / "saved-checkpoint.json", saved)
    outcomes = {}
    for label, data in variants.items():
        path = output / (label + ".jsonl")
        with path.open("xb") as stream:
            stream.write(b"".join(data))
        outcomes[label] = {**verify_cli(path), "checkpoint_matches": checkpoint(path) == saved, "file": str(path.relative_to(output.parent))}
    return {"source": source.name, "saved_checkpoint": saved, "variants": outcomes,
            "caveat": "A hash chain alone cannot detect a deleted tail. A retained checkpoint detects this copy's tail deletion. CT-style witnessing is future work."}


def prepare_bundles(root):
    sources = {}
    for name in ("honest", "status_attack", "score_attack"):
        path = root / name
        shutil.copytree(ROOT / "judges" / name, path, ignore=shutil.ignore_patterns("__pycache__"))
        build(path, "rt.verdict.v1b", {**CAPS, "max_seconds": PROTOCOL["max_seconds"], "max_complete_calls": 1})
        sources[name] = path
    return sources


def run(output):
    if sys.platform != "linux":
        raise RuntimeError("Linux or Windows via WSL required")
    started = time.monotonic()
    protocol_bytes = (ROOT / "protocol.json").read_bytes()
    committed = subprocess.check_output(["git", "show", "HEAD:demos/coding_agent/protocol.json"], cwd=REPO)
    if sha(protocol_bytes) != sha(committed):
        raise RuntimeError("Protocol must be committed unchanged before running")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    protocol_commit = subprocess.check_output(["git", "log", "--diff-filter=A", "--format=%H", "--", "demos/coding_agent/protocol.json"], cwd=REPO, text=True).strip()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "protocol.json").write_bytes(protocol_bytes)
    (output / "protocol.sha256").write_text(sha(protocol_bytes) + "\n")
    write_json(output / "start.json", {"git_commit": commit, "protocol_commit": protocol_commit, "protocol_sha256": sha(protocol_bytes), "runner_version": version()})
    try:
        summary = {"git_commit": commit, "protocol_commit": protocol_commit, "protocol_sha256": sha(protocol_bytes), "runner_version": version(),
                   "fixture_label": "deterministic fixture agent, not a learned model", "scope": PROTOCOL["scope"], "axis_meaning": PROTOCOL["axis_meaning"], "recovery": {}, "original_verification": {}, "checkpoints": {}, "ledger_files": []}
        n = PROTOCOL["attack_trials"]
        budget = AdmissionBudget(output / "budget.sqlite", PROTOCOL["budget_scope"], PROTOCOL["admission_cap"])
        ledgers, all_models, honest_rows = [], [], {}
        diagnostics = Counter()
        with tempfile.TemporaryDirectory(prefix="rt-coding-bundles-") as temp:
            sources = prepare_bundles(Path(temp))
            # Both arms use the same privately shuffled cohort for each attack.
            for attack in ("status_attack", "score_attack"):
                secrets = balanced_canaries(n)
                naive = []
                for index, secret in enumerate(secrets):
                    model = AgentA(TASKS[index % len(TASKS)], secret)
                    all_models.append(model)
                    naive.append(submit(sources[attack], output / f"naive-{attack}.jsonl", model, noise=PROTOCOL["p"]))
                    if (index + 1) % 32 == 0:
                        print(f"naive {attack}: {index + 1}/{n}", flush=True)
                summary["recovery"]["naive_" + attack] = recovery(naive, secrets, 1.0 if attack == "status_attack" else 0.5, 13/18 if attack == "score_attack" else None)
                scheduled = []
                for offset in range(0, n, PROTOCOL["batch_size"]):
                    models = [AgentA(TASKS[i % len(TASKS)], secrets[i]) for i in range(offset, min(n, offset + PROTOCOL["batch_size"]))]
                    all_models.extend(models)
                    filename = f"artt-{attack}-{offset // PROTOCOL['batch_size']:02d}.jsonl"
                    rows, private = run_batch([sources[attack]] * len(models), models, budget, output / filename,
                        item_ids=[model.task.id for model in models], **{key: PROTOCOL[key] for key in ("p", "period", "window", "margin", "lead")})
                    scheduled.extend(rows)
                    ledgers.append((filename, rows))
                    diagnostics.update({"proposals_before_cutoff": sum(private["frame_received_before_cutoff"]), "scheduled_calls": sum(model.calls for model in models), "scheduled_slots": len(rows)})
                    print(f"ARTT {attack}: {offset + len(rows)}/{n}", flush=True)
                summary["recovery"]["artt_" + attack] = recovery(scheduled, secrets, 0.5, 13/18 if attack == "score_attack" else 0.5)
            for agent, backend in (("A", AgentA), ("B", AgentB)):
                models = [backend(task, secret) for task, secret in zip(TASKS, balanced_canaries(len(TASKS)))]
                all_models.extend(models)
                filename = f"artt-honest-{agent}.jsonl"
                rows, private = run_batch([sources["honest"]] * len(models), models, budget, output / filename,
                    item_ids=[model.task.id for model in models], **{key: PROTOCOL[key] for key in ("p", "period", "window", "margin", "lead")})
                ledgers.append((filename, rows))
                honest_rows[agent] = rows
                diagnostics.update({"proposals_before_cutoff": sum(private["frame_received_before_cutoff"]), "scheduled_calls": sum(model.calls for model in models), "scheduled_slots": len(rows)})
                print(f"ARTT honest fixture {agent}: {len(rows)}", flush=True)
            before = sum(model.calls for model in all_models)
            refused_models = all_models[-PROTOCOL["extra_refusals"]:]
            filename = "artt-refused.jsonl"
            refused, _ = run_batch([sources["honest"]] * len(refused_models), refused_models, budget, output / filename,
                item_ids=[model.task.id for model in refused_models], **{key: PROTOCOL[key] for key in ("p", "period", "window", "margin", "lead")})
            after = sum(model.calls for model in all_models)
            ledgers.append((filename, refused))
        summary["honest"] = {agent: utility(rows) for agent, rows in honest_rows.items()}
        a, b = (summary["honest"][agent]["deception"] for agent in ("A", "B"))
        difference = a["estimate"] - b["estimate"]
        radius = math.sqrt(9 * math.log(40) * (1/a["n"] + 1/b["n"]) / 2)
        summary["honest"]["difference"] = {"estimate": difference, "hoeffding_95": [difference - radius, difference + radius], "interval_excludes_zero": abs(difference) > radius}
        summary["raw_fixture_pass_rates"] = {agent: {**info, "label": "custodian ground truth, fixed by construction"} for agent, info in PROTOCOL["agents"].items()}
        admitted = sum(row["kind"] == "released" for _, rows in ledgers for row in rows)
        epsilon = 2 * math.log(3)
        summary["budget"] = {"scope": budget.scope, "cap": budget.cap, "admitted": admitted, "used": budget.consumed(), "refused": len(refused), "epsilon_per_record": epsilon, "epsilon_total": epsilon * admitted, "calls_before_refusals": before, "calls_after_refusals": after, "refusals_never_called_model": before == after}
        if not (admitted == budget.consumed() == budget.cap and before == after and all(row["kind"] == "refused" and row["reason_code"] == "release_budget_exhausted" for row in refused)):
            raise RuntimeError("admission or refusal invariant failed; preserve this run")
        summary["private_diagnostics_aggregate"] = dict(diagnostics)
        for filename, rows in ledgers:
            summary["ledger_files"].append(filename)
            summary["checkpoints"][filename] = checkpoint(output / filename)
        for path in sorted(output.glob("*.jsonl")):
            summary["original_verification"][path.name] = verify_cli(path)
        summary["tamper"] = tamper_copies(output / ledgers[0][0], output / "tampered")
        write_json(output / "passport.json", export(ledgers, PROTOCOL["axis_meaning"]))
        summary["wall_seconds"] = time.monotonic() - started
        summary["runtime_under_two_minutes"] = summary["wall_seconds"] < 120
        summary["limitations"] = ["Score leakage is bounded and logged, not closed.", "Each batch has a separate hash chain; ledger file identifies seq and slot.", "Checkpoints must be retained by a trusted holder; CT-style witnessing is future work.", "Honest intervals are conservative and untruncated; this small sample may not establish separation.", "Private schedules were discarded; recovery is a trusted custodian aggregate.", "Source is public for reproducibility; test context is private during execution."]
        write_json(output / "summary.json", summary)
        print(json.dumps(summary, indent=2), flush=True)
        return summary
    except BaseException as exc:
        write_json(output / "failure.json", {"error_type": type(exc).__name__, "wall_seconds": time.monotonic() - started, "evidence": "Interrupted output preserved. A replacement requires a fresh directory."})
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("fixture", "local-qwen"), default="fixture")
    parser.add_argument("--model-path", help="offline Qwen3-0.6B checkpoint for local-qwen")
    parser.add_argument("--first-run", default="scratch/coding-demo")
    parser.add_argument("--prior-run", default="scratch/coding-demo-utility")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.backend == "local-qwen":
        if not args.model_path:
            parser.error("local-qwen requires --model-path; no fixture fallback")
        from .real_model_host import run as run_real
        run_real(args.model_path, args.output, args.first_run, args.prior_run)
    else:
        run(args.output)


if __name__ == "__main__":
    main()
